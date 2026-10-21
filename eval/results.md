# Evaluation results

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
