# Changelog

## v0.1.0 (first release)

ReproTrace compares `strace` recordings of the same command in two environments and ranks
the differences by how likely they are to explain a failure.

- `capture`: trace a command one or more times (`strace -f -ttt -y -s 200 -v`), with a
  timeout that stops the whole process group; runs are saved under a label.
- `show`: one run at a glance: failed file opens (search-path probes folded), programs run,
  network connections.
- `runs`: saved runs grouped by capture; broken run folders are listed, not fatal.
- `diff`: normalizes machine-specific details, filters run-to-run noise, aligns the two
  recordings process by process, and ranks the divergences with a reason for every score.
  Comparisons are saved in SQLite.
- `report`: Markdown report with the evidence (sanitized trace excerpts), environment
  differences with secrets redacted, reproduction steps and limitations.
- CI: a GitHub Actions example that captures the CI side and uploads it as an artifact, and
  a guide for comparing it with a local capture (`docs/CI.md`).
- Evaluation: eight Docker scenarios with planted causes and one command to measure where the
  cause ranks (`eval/run_eval.py`). The results are in the README.
- Experimental: `explain` sends a bounded, redacted summary of the top divergences to Google
  Gemini and keeps only answers whose citations all exist. Tested against a simulated provider
  only.

Linux only. Python 3.11 or newer.
