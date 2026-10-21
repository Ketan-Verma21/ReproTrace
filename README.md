# ReproTrace

Turn a mysterious CI failure into evidence.

ReproTrace is a command-line tool (in early development) that will explain why a command
behaves differently on two machines by comparing `strace` recordings. See `PRD.md` for scope
and `Phases.md` for progress. Capture, a per-run summary, a ranked comparison of two environments, and Markdown reports are
implemented so far:

```text
reprotrace capture --label local --runs 3 -- pytest tests/test_api.py
reprotrace show RUN_ID       # failed file opens, programs run, connections
reprotrace runs                 # saved runs, grouped by capture group
reprotrace diff local ci        # ranked differences between the newest 'local' and 'ci' groups
reprotrace report               # Markdown report of the latest comparison
```

Add `--no-color` (or set `NO_COLOR`) for plain output.

To compare a GitHub Actions run with your machine, see `docs/CI.md`. The workflow in
`.github/workflows/ci.yml` runs the tests and uploads an example CI-side capture.

`diff` ranks divergences by likely cause and shows the reasons for each rank. The ranking is a
heuristic, not proof of cause.

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
