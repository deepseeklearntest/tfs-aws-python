"""
Shared CLI helpers — every wave1 script reuses the same argparse boilerplate
and main() runner pattern via this module.
"""
from __future__ import annotations

import argparse
import logging
import os
from typing import Callable

from common import logging_config, output, session


def make_parser(description: str, account_level: bool = False) -> argparse.ArgumentParser:
    """
    Build an argparse parser with the standard wave1 flags.
    Scripts can call parser.add_argument(...) afterwards to add their own.

    Standard flags:
        --accounts      comma-separated AWS account IDs (required)
        --output-dir
        --max-accounts  (sample mode: first N of the specified accounts)
        --workers       (parallel worker pool size)
        --regions       (regional scripts only)
        --max-regions   (regional scripts only)
        --keep-runs     (number of most-recent CSVs to retain per script)
        --no-prune      (disable automatic CSV retention for this run)
    """
    p = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        '--accounts',
        required=True,
        help='Comma-separated AWS account IDs to scan (e.g. 123456789012,234567890123)',
    )
    p.add_argument(
        '--output-dir', default='findings',
        help='Directory for CSV output (default: findings)',
    )
    p.add_argument(
        '--max-accounts', type=int, default=None,
        help='Sample mode: only scan the first N accounts',
    )
    p.add_argument(
        '--workers', type=int, default=10,
        help='Parallel worker count (default: 10, use 1 for sequential debug)',
    )
    p.add_argument(
        '--creds-file', default='britive_creds.json',
        help='JSON file with saved Britive credentials (default: britive_creds.json). '
             'Missing accounts fall back to interactive prompt.',
    )
    p.add_argument(
        '--keep-runs', type=int, default=output.DEFAULT_KEEP_RUNS,
        help=(
            'Number of most-recent CSV runs to keep per script; older ones '
            f'are pruned automatically after each run (default: {output.DEFAULT_KEEP_RUNS})'
        ),
    )
    p.add_argument(
        '--no-prune', action='store_true',
        help='Disable automatic CSV retention for this run (keep every run\'s CSV forever)',
    )
    if not account_level:
        p.add_argument(
            '--regions',
            help='Comma-separated regions to scan (default: all enabled)',
        )
        p.add_argument(
            '--max-regions', type=int, default=None,
            help='Sample mode: only scan the first N regions per account',
        )
    return p


def run(
    args: argparse.Namespace,
    script_name: str,
    scan_fn: Callable,
    extra_fields: list[str] | None = None,
    account_level: bool = False,
    task_expander: Callable | None = None,
) -> None:
    """
    Standard scan-and-write pipeline.

    For regional scans (account_level=False): scan_fn(session, account_id, region, writer)
    For account-level scans (account_level=True): scan_fn(session, account_id, writer)

    Optional task_expander: callable(base_task_tuple) -> iterable of expanded tuples.
    When provided, each base task (sess, account_id[, region]) is expanded into one
    or more tuples before the writer is appended and the list is sent to run_parallel.
    This allows a script to shard work within a region (e.g. per resource type)
    without needing a nested thread pool — all shards are flat work units in the
    same pool, so total concurrency remains bounded by --workers.
    Default None preserves existing behaviour for all other scripts.
    """
    logging_config.setup(args.output_dir, script_name)
    log = logging.getLogger(script_name)
    log.info("Starting %s", script_name)

    regions = None
    if not account_level and getattr(args, 'regions', None):
        regions = [r.strip() for r in args.regions.split(',') if r.strip()]

    accounts = [a.strip() for a in args.accounts.split(',') if a.strip()]

    iterator_kwargs = {
        'max_accounts': args.max_accounts,
        'creds_file': getattr(args, 'creds_file', None),
    }
    if not account_level:
        iterator_kwargs['regions'] = regions
        iterator_kwargs['max_regions'] = args.max_regions

    if not accounts or any(len(a) != 12 or not a.isdigit() for a in accounts):
        raise ValueError('--accounts must contain 12-digit AWS account IDs')
    for name in ('workers', 'max_accounts', 'max_regions', 'keep_runs'):
        value = getattr(args, name, None)
        if value is not None and value < 1:
            raise ValueError(f'--{name.replace("_", "-")} must be positive')
    sample = bool(args.max_accounts or getattr(args, 'max_regions', None) or regions)
    keep_runs = None if getattr(args, 'no_prune', False) else args.keep_runs
    with output.FindingsWriter(
        args.output_dir, script_name, extra_fields, keep_runs=keep_runs,
        sample=sample, scope={'accounts': sorted(set(accounts)), 'regions': regions or 'enabled'},
    ) as writer:
        with session.AccountIterator(accounts, **iterator_kwargs) as it:
            tasks = it.iter_accounts() if account_level else it.iter_regions()
            # Materialise the iterator under the Vault context so all STS / region
            # discovery happens before threads start hitting the per-account API.
            task_list = list(tasks)
            if task_expander is not None:
                task_list = [exp for t in task_list for exp in task_expander(t)]
            outcomes = session.run_parallel(
                ((*task, writer) for task in task_list),
                scan_fn,
                max_workers=args.workers,
            )
            writer.record_outcomes(outcomes)

    log.info("Done.")
