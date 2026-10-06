---
name: wave-status
description: Show which of the 54 proactive.md detection tasks are implemented vs pending. Use when asked about project progress, what tasks remain, or what to build next.
allowed-tools: Glob Read
---

Show the implementation status of all 54 detection tasks from `proactive.md`.

1. Use Glob with patterns `wave1_cost/*.py`, `wave2_*/*.py`, `wave3_*/*.py`, `wave4_*/*.py` to list all implemented detection scripts. Extract the numeric task prefix from each filename (e.g. `01` from `01_detect_gp2_volumes.py`).

2. Read `proactive.md` to get the full task list: task number, title, wave assignment.

3. Cross-reference and output a status table sorted by task number:

| # | Title | Wave | Status |
|---|-------|------|--------|

   Mark ✅ Implemented (a script file exists for that task number) or ⬜ Pending.

4. End with a summary line and the next 3 unimplemented tasks per wave:

   > X / 54 implemented. Recommended next tasks: ...
