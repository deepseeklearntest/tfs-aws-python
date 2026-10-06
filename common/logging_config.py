from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


def setup(output_dir: str, script_name: str, level: int = logging.INFO) -> None:
    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    log_dir = Path(output_dir) / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(name)s: %(message)s')

    fh = logging.FileHandler(log_dir / f"{script_name}_{ts}.log", encoding='utf-8')
    fh.setFormatter(fmt)

    # Windows consoles often default to a legacy codepage (e.g. cp1252) that
    # can't encode characters like the "->" arrow used in log messages,
    # which raises UnicodeEncodeError and prints a logging traceback.
    # Falling back to character replacement keeps console logging non-fatal.
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(errors='replace')
        except (ValueError, OSError):
            pass

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(fh)
    root.addHandler(sh)

    # Silence noisy SDK loggers unless debug is explicitly requested
    for noisy in ('boto3', 'botocore', 'urllib3'):
        logging.getLogger(noisy).setLevel(logging.WARNING)
