# ReproTrace

Turn a mysterious CI failure into evidence.

ReproTrace is a command-line tool (in early development) that will explain why a command
behaves differently on two machines by comparing `strace` recordings. See `PRD.md` for scope
and `Phases.md` for progress. Capture and a per-run summary are implemented so far:

```text
reprotrace capture --label local --runs 3 -- pytest tests/test_api.py
reprotrace show <run_id>     # failed file opens, programs run, connections
```

This saves `.reprotrace/runs/<run_id>/raw.strace` and `meta.json`. The raw trace contains the
traced command's full environment, so do not share it without reviewing it first.

## Development setup (Linux, Python 3.11+)

```text
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
reprotrace --help
pytest && ruff check .
```
