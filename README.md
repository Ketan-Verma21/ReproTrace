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

## Evaluation

`eval/scenarios/` holds eight failures planted in pairs of Docker images (missing CA bundle,
timezone, locale, missing environment variable, dependency version, file permission, missing
program on `PATH`, missing config file). One command builds the images, captures both sides,
compares them and scores where the planted cause ranks (needs Docker; about 5-10 minutes):

```text
python eval/run_eval.py --update-readme
```

<!-- eval:start -->
Measured 2026-10-21 with `python eval/run_eval.py` (3 runs per side).

| Scenario | Cause rank | Top 3 | Divergences | Ranked above cause | Warnings | Runs needed | Rank with 1 run | Tracing overhead |
|---|---|---|---|---|---|---|---|---|
| dependency_version | 1 | yes | 9 | 0 | 4 | 1 | 1 | 3.1x |
| locale | 1 | yes | 52 | 0 | 3 | 1 | 1 | 4.0x |
| missing_ca_bundle | 1 | yes | 5 | 0 | 1 | 1 | 1 | 2.8x |
| missing_config_file | 1 | yes | 9 | 0 | 1 | 1 | 1 | 3.6x |
| missing_env_var | 1 | yes | 7 | 0 | 1 | 1 | 1 | 3.5x |
| path_binary | 1 | yes | 21 | 0 | 2 | 1 | 1 | 3.3x |
| permission | 1 | yes | 9 | 0 | 1 | 1 | 1 | 3.3x |
| timezone | 1 | yes | 7 | 0 | 3 | 1 | 1 | 3.3x |

**Totals:** top-1 8/8, top-3 8/8.

Scenarios are written by the author of ReproTrace, so these numbers describe these scenarios only; they are not general proof of accuracy. Tracing overhead compares the mean traced run (including strace start-up) with the mean untraced run of the same command; the commands are short, so start-up dominates.
<!-- eval:end -->
