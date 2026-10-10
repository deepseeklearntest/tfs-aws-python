from __future__ import annotations

import csv
import logging
import json
import tempfile
import re
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path

from common.findings_io import wave_of
from common import tags as tagutil

log = logging.getLogger(__name__)

# Every script's CSV shares these columns so outputs can be concatenated and
# loaded into Excel / Power BI without schema wrangling.
COMMON_FIELDS = [
    'scan_time',
    'account_id',
    'region',
    'resource_id',
    'resource_type',
    'finding',
    'detail',
    'estimated_monthly_savings_usd',
    'tags',
    'owner',
]

# Number of most-recent timestamped CSVs to keep per script; older ones are
# pruned automatically when a run finishes (see FindingsWriter._prune_old_runs).
# generate_report.py, build_dataset.py, and continuous/54_inventory_refresh.py
# all only ever read the single newest CSV per script, so this loses nothing
# they use — the actual historical trend store is dataset/findings_dataset.csv
# (a separate, append-only, per-day file untouched by this pruning).
DEFAULT_KEEP_RUNS = 10


class FindingsWriter:
    """
    Thread-safe context manager that writes findings to a timestamped CSV file.

    A single threading.Lock serialises writes so concurrent worker threads
    can call write() without corrupting CSV rows.
    """

    def __init__(
        self,
        output_dir: str,
        script_name: str,
        extra_fields: list[str] | None = None,
        keep_runs: int | None = DEFAULT_KEEP_RUNS,
        sample: bool = False,
        scope: dict | None = None,
    ) -> None:
        if keep_runs is not None and keep_runs < 1:
            raise ValueError('keep_runs must be positive or None')
        subfolder = wave_of(script_name)
        base = Path(output_dir) / subfolder if subfolder else Path(output_dir)
        base.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc)
        while True:
            path = base / f"{script_name}_{stamp.strftime('%Y%m%d_%H%M%S')}.csv"
            reservation = path.with_suffix('.run')
            try:
                with reservation.open('x'):
                    pass
            except FileExistsError:
                stamp += timedelta(seconds=1)
                continue
            if path.exists() or path.with_suffix('.json').exists() or list(base.glob(path.stem + '.*.csv')):
                reservation.unlink()
                stamp += timedelta(seconds=1)
                continue
            break
        self._reservation = reservation

        self._path = path
        self._sample = sample
        self._scope = scope or {}
        self._outcomes = []
        self._closed = False
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._script_name = script_name
        self._keep_runs = keep_runs
        self._fields = COMMON_FIELDS + (extra_fields or [])
        self._fh = tempfile.NamedTemporaryFile(
            mode='w', newline='', encoding='utf-8', dir=base,
            prefix=f'.{script_name}_', suffix='.partial.csv', delete=False,
        )
        self._staged_path = Path(self._fh.name)
        self._writer = csv.DictWriter(
            self._fh, fieldnames=self._fields, extrasaction='ignore'
        )
        self._writer.writeheader()
        self._count = 0
        self._lock = threading.Lock()
        log.info("Output → %s", path)

    def write(
        self,
        account_id: str,
        region: str,
        resource_id: str,
        resource_type: str,
        finding: str,
        detail: str = '',
        estimated_monthly_savings_usd: float | None = None,
        tags: dict | list | None = None,
        **extra,
    ) -> None:
        # 'owner' is a COMMON_FIELDS column derived once here so every script
        # gets consistent owner attribution without hand-wiring it. A script
        # that knows a better owner than the resource's own tags (e.g. the
        # attached EC2 instance's owner tag) can pass owner=... explicitly to
        # override the tag-derived default.
        owner = extra.pop('owner', None)
        if owner is None:
            owner = tagutil.owner_from_tags(tags)
        row = {
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'account_id': account_id,
            'region': region,
            'resource_id': resource_id,
            'resource_type': resource_type,
            'finding': finding,
            'detail': detail,
            'estimated_monthly_savings_usd': (
                f"{estimated_monthly_savings_usd:.2f}"
                if estimated_monthly_savings_usd is not None
                else ''
            ),
            'tags': _flatten_tags(tags),
            'owner': owner,
            **extra,
        }
        with self._lock:
            self._writer.writerow(row)
            self._fh.flush()
            self._count += 1

    def record_outcomes(self, outcomes) -> None:
        self._outcomes = [
            {'target': o.target, 'complete': o.complete, 'issues': o.issues}
            for o in outcomes
        ]

    def close(self, error: BaseException | None = None) -> None:
        if self._closed:
            return
        self._closed = True
        self._fh.close()
        status = 'incomplete' if error else ('sample' if self._sample or self._narrows_previous_scope() else 'complete')
        destination = self._path if status == 'complete' else self._path.with_suffix(f'.{status}.csv')
        manifest = {
            'status': status, 'scope': self._scope,
            'started_at': self._started_at,
            'finished_at': datetime.now(timezone.utc).isoformat(),
            'finding_count': self._count, 'tasks': self._outcomes,
            'error': str(error) if error else None,
        }
        # Publish metadata before the CSV, so a new run is never visible to
        # readers without its status. Legacy CSVs remain readable.
        manifest_path = destination.with_suffix('.json')
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        self._staged_path.replace(destination)
        self._reservation.unlink(missing_ok=True)
        log.info('Wrote %d finding(s), status=%s → %s', self._count, status, destination)
        if status == 'complete':
            self._prune_old_runs()

    def _narrows_previous_scope(self) -> bool:
        """A smaller account set must not retire findings from unscanned accounts."""
        current = set(self._scope.get('accounts', []))
        if not current:
            return False
        candidates = sorted(
            p for p in self._path.parent.glob(f'{self._script_name}_*.csv')
            if re.match(rf'^{re.escape(self._script_name)}_\d{{8}}_\d{{6}}\.csv$', p.name)
        )
        if not candidates:
            return False
        previous = candidates[-1]
        manifest_path = previous.with_suffix('.json')
        if manifest_path.exists():
            previous_accounts = set(json.loads(manifest_path.read_text(encoding='utf-8')).get('scope', {}).get('accounts', []))
        else:
            with previous.open(newline='', encoding='utf-8-sig') as fh:
                previous_accounts = {row.get('account_id', '') for row in csv.DictReader(fh)} - {''}
        if not previous_accounts <= current:
            log.warning('Narrower account scope retained as sample; use a separate output directory for a new scope')
            return True
        return False

    def _prune_old_runs(self) -> None:
        """Delete this script's older timestamped CSVs beyond `keep_runs`.

        Only ever touches files matching this exact script_name's
        <script_name>_YYYYMMDD_HHMMSS.csv pattern in this run's output folder
        (regex-anchored so e.g. '33_...' can't match a differently-numbered
        script). keep_runs=None disables pruning entirely.
        """
        if self._keep_runs is None:
            return
        pattern = re.compile(
            rf"^{re.escape(self._script_name)}_\d{{8}}_\d{{6}}\.csv$"
        )
        candidates = sorted(
            p for p in self._path.parent.glob(f"{self._script_name}_*.csv")
            if pattern.match(p.name)
        )
        stale = candidates[:-self._keep_runs] if len(candidates) > self._keep_runs else []
        for f in stale:
            try:
                f.unlink()
                f.with_suffix('.json').unlink(missing_ok=True)
                log.info("Pruned old findings CSV: %s", f)
            except OSError as exc:
                log.warning("Could not prune %s: %s", f, exc)

    def __enter__(self) -> FindingsWriter:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if exc is not None:
            self.record_outcomes(getattr(exc, 'outcomes', []))
        self.close(error=exc)


def _flatten_tags(tags: dict | list | None) -> str:
    if not tags:
        return ''
    if isinstance(tags, list):
        tags = {t.get('Key', ''): t.get('Value', '') for t in tags}
    return ';'.join(f"{k}={v}" for k, v in tags.items())
