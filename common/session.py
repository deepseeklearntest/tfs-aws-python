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
from contextvars import ContextVar
from dataclasses import dataclass, field
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Generator, Iterable

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from britive import BritiveKeychain

log = logging.getLogger(__name__)


class IncompleteScanError(RuntimeError):
    """A sweep did not cover every requested task; do not publish it as current."""


@dataclass
class TaskOutcome:
    target: str
    issues: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.issues


_active_task: ContextVar[TaskOutcome | None] = ContextVar('scan_task', default=None)


def mark_incomplete(reason: str) -> None:
    outcome = _active_task.get()
    if outcome is not None and reason not in outcome.issues:
        outcome.issues.append(reason)


class _ScanWarnings(logging.Handler):
    """Warnings/errors emitted inside a scan are conservative coverage failures.

    This also captures existing detector branches that log and return rather
    than raising. ContextVar keeps each worker's outcome separate.
    """
    def emit(self, record) -> None:
        if record.levelno >= logging.WARNING:
            mark_incomplete(record.getMessage())


def _run_task(fn: Callable, args: tuple) -> TaskOutcome:
    outcome = TaskOutcome(_summarise(args))
    token = _active_task.set(outcome)
    try:
        fn(*args)
    except Exception as exc:
        mark_incomplete(f'{type(exc).__name__}: {exc}')
        log.exception('Task failed: %s', outcome.target)
    finally:
        _active_task.reset(token)
    return outcome

SKIP_CODES = frozenset([
    'AuthFailure',
    'UnauthorizedOperation',
    'AccessDenied',
    'AccessDeniedException',
    'OptInRequired',
    'InvalidClientTokenId',
])


def is_skippable(exc: ClientError) -> bool:
    code = exc.response['Error']['Code']
    skipped = code in SKIP_CODES
    if skipped:
        mark_incomplete(f'AWS access skipped: {code}')
    return skipped


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
        raise IncompleteScanError("Could not enumerate enabled regions") from exc


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
        missing = sorted(set(targets) - set(self._kc.account_keys))
        if missing:
            self._kc.revoke_all_leases()
            raise IncompleteScanError(f"Credentials missing for account(s): {', '.join(missing)}")
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
) -> list[TaskOutcome]:
    """Complete the sweep, returning outcomes or raising on incomplete coverage.

    Every task runs even if another fails. The caller retains partial results
    separately; exceptions, skipped permissions, and scan warnings never become
    a successful empty scan. Running workers are joined before the writer closes.
    """
    materialised = list(items)
    if not materialised:
        raise IncompleteScanError('No tasks to run')
    handler = _ScanWarnings(level=logging.WARNING)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    outcomes = []
    try:
        if max_workers <= 1:
            outcomes = [_run_task(fn, args) for args in materialised]
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as exe:
                futures = [exe.submit(_run_task, fn, args) for args in materialised]
                try:
                    for future in as_completed(futures):
                        outcomes.append(future.result())
                except BaseException:
                    for future in futures:
                        future.cancel()
                    raise
    finally:
        root_logger.removeHandler(handler)
    failed = [o for o in outcomes if not o.complete]
    if failed:
        error = IncompleteScanError(f'{len(failed)} of {len(outcomes)} scan task(s) incomplete')
        error.outcomes = outcomes
        raise error
    return outcomes


def _summarise(args: tuple) -> str:
    """Render a task argument tuple for log messages without dumping the boto3 Session."""
    return '/'.join(str(a) for a in args[1:] if not hasattr(a, 'write')) if len(args) > 1 else 'task'
