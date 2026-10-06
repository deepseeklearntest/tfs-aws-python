"""
Britive-backed multi-account session management with parallel execution helpers.

Usage:
    with session.AccountIterator(args.accounts, regions, max_accounts=3) as it:
        session.run_parallel(
            it.iter_regions(),
            lambda sess, account_id, region: scan(sess, account_id, region, writer),
            max_workers=args.workers,
        )
"""
from __future__ import annotations

# Must run before boto3/botocore are imported so the patched ssl.SSLContext
# is in place when botocore builds its urllib3 SSL context.
import truststore
truststore.inject_into_ssl()

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Generator, Iterable

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from britive import BritiveKeychain

log = logging.getLogger(__name__)

SKIP_CODES = frozenset([
    'AuthFailure',
    'UnauthorizedOperation',
    'AccessDenied',
    'AccessDeniedException',
    'OptInRequired',
    'InvalidClientTokenId',
])


def is_skippable(exc: ClientError) -> bool:
    return exc.response['Error']['Code'] in SKIP_CODES


def chunked(seq: list, size: int) -> Generator[list, None, None]:
    """Yield successive `size`-length chunks of `seq`. Used for CloudWatch batching."""
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _make_session(creds: dict) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=creds['access_key'],
        aws_secret_access_key=creds['secret_key'],
        aws_session_token=creds['security_token'],
    )


def _get_account_id(sess: boto3.Session) -> str:
    try:
        return sess.client('sts', region_name='us-east-1').get_caller_identity()['Account']
    except Exception as exc:
        log.warning("STS get_caller_identity failed: %s", exc)
        return 'unknown'


def _get_enabled_regions(sess: boto3.Session) -> list[str]:
    try:
        ec2 = sess.client('ec2', region_name='us-east-1')
        return [
            r['RegionName']
            for r in ec2.describe_regions(
                Filters=[
                    {'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}
                ]
            )['Regions']
        ]
    except Exception as exc:
        log.warning("Could not enumerate regions (%s). Defaulting to us-east-1.", exc)
        return ['us-east-1']


class AccountIterator:
    """
    Context manager: collects Britive credentials interactively once, then
    iterates the specified accounts/regions for parallel scanning.

    Args:
        accounts:      List of AWS account IDs to scan
        regions:       Optional explicit region list (overrides auto-discovery)
        max_accounts:  If set, only iterate the first N accounts (sample mode)
        max_regions:   If set, only iterate the first N regions per account
    """

    def __init__(
        self,
        accounts: list[str],
        regions: list[str] | None = None,
        max_accounts: int | None = None,
        max_regions: int | None = None,
        creds_file: str | None = None,
    ) -> None:
        self._accounts = accounts
        self._regions = regions
        self._max_accounts = max_accounts
        self._max_regions = max_regions
        self._creds_file = creds_file
        self._kc: BritiveKeychain | None = None

    def __enter__(self) -> AccountIterator:
        targets = self._accounts
        if self._max_accounts and len(targets) > self._max_accounts:
            log.warning(
                "Sample mode: limiting to first %d of %d account(s)",
                self._max_accounts, len(targets),
            )
            targets = targets[:self._max_accounts]
        self._kc = BritiveKeychain()
        self._kc.collect_creds(targets, creds_file=self._creds_file)
        if not self._kc.account_keys:
            log.error("No credentials collected — nothing to scan.")
        return self

    def __exit__(self, *_) -> None:
        if self._kc:
            self._kc.revoke_all_leases()

    def iter_accounts(self) -> Generator[tuple[boto3.Session, str], None, None]:
        """Yield (session, account_id) once per account."""
        assert self._kc is not None, "Must be used as a context manager"
        for account_id, creds in list(self._kc.account_keys.items()):
            sess = _make_session(creds)
            log.info("Account %s", account_id)
            yield sess, account_id

    def iter_regions(self) -> Generator[tuple[boto3.Session, str, str], None, None]:
        """Yield (session, account_id, region) for every account/region combination."""
        for sess, account_id in self.iter_accounts():
            regions = self._regions or _get_enabled_regions(sess)
            if self._max_regions and len(regions) > self._max_regions:
                log.warning(
                    "Sample mode: limiting account %s to first %d of %d region(s)",
                    account_id, self._max_regions, len(regions),
                )
                regions = regions[:self._max_regions]
            log.info("Account %s â€” %d region(s)", account_id, len(regions))
            for region in regions:
                yield sess, account_id, region


def run_parallel(
    items: Iterable[tuple],
    fn: Callable,
    max_workers: int = 10,
) -> None:
    """
    Run fn(*args) for each tuple yielded by `items` in parallel.
    Failures are logged with full traceback; the sweep continues.

    Set max_workers <= 1 for sequential mode (useful for debugging).
    """
    materialised = list(items)
    if not materialised:
        log.warning("No tasks to run.")
        return

    if max_workers <= 1:
        log.info("Running %d task(s) sequentially", len(materialised))
        for args in materialised:
            try:
                fn(*args)
            except Exception:
                log.exception("Task failed: %s", _summarise(args))
        return

    log.info("Running %d task(s) in parallel (workers=%d)", len(materialised), max_workers)
    failures = 0
    exe = ThreadPoolExecutor(max_workers=max_workers)
    futures = {exe.submit(fn, *args): args for args in materialised}
    try:
        for f in as_completed(futures):
            try:
                f.result()
            except Exception:
                failures += 1
                log.exception("Task failed: %s", _summarise(futures[f]))
    except KeyboardInterrupt:
        # Cancel futures that haven't started yet; running threads finish their
        # current boto3 call then exit naturally (they are daemon threads).
        for f in futures:
            f.cancel()
        exe.shutdown(wait=False, cancel_futures=True)
        log.warning("Scan interrupted.")
        raise
    else:
        exe.shutdown(wait=True)
    if failures:
        log.warning("Completed with %d failure(s)", failures)


def _summarise(args: tuple) -> str:
    """Render a task argument tuple for log messages without dumping the boto3 Session."""
    return '/'.join(str(a) for a in args[1:]) if len(args) > 1 else str(args)
