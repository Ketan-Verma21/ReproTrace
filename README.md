# ReproTrace

[![ci](https://github.com/Ketan-Verma21/ReproTrace/actions/workflows/ci.yml/badge.svg)](https://github.com/Ketan-Verma21/ReproTrace/actions/workflows/ci.yml)

Turn a mysterious CI failure into evidence.

A test passes on your machine and fails in CI. The logs say `FileNotFoundError` or
`certificate verify failed`, and the real question is: *what is different between the two
machines?* ReproTrace answers that with evidence instead of guesswork. It records what the
command does at the operating-system level on each machine (files opened, programs run,
environment, network calls) using `strace`, compares the two recordings, and ranks the
differences by how likely they are to explain the failure. Every finding points to the exact
system calls behind it.

## How it works

1. **Capture** the same command in each environment, ideally two or more times, with
   `strace -f`.
2. **Normalize** what always differs between machines (home folder, working directory, PIDs,
   timestamps, temp paths) and drop calls that vary from run to run on the same machine.
3. **Align** the two recordings process by process and list where they diverge: a file
   found on one side only, a call that fails on one side, a different program or library, a
   different environment variable.
4. **Rank** the divergences with explained signals: did it fail on the failing side only?
   Is it the first difference in its process? Is it stable across runs? Is it just a
   consequence of an earlier difference?
5. **Report** in the terminal or as a Markdown report you can attach to an issue.

The ranking is a heuristic. A top-ranked divergence is consistent with the failure; it is not
proof of the cause.

## Install

Linux only (strace is Linux-specific). Needs Python 3.11 or newer and `strace`.

```text
sudo apt install strace                 # Debian/Ubuntu; Fedora: sudo dnf install strace
python3 -m pip install "git+https://github.com/Ketan-Verma21/ReproTrace@v0.1.0"
reprotrace --help
```

`pipx install "git+https://github.com/Ketan-Verma21/ReproTrace@v0.1.0"` works too and keeps
the tool in its own environment.

## 60-second demo

A command that reads `settings.toml` works where the file exists and fails where it does not.
Capture both situations and compare them:

```text
mkdir reprotrace-demo && cd reprotrace-demo
printf 'debug = false\n' > settings.toml
reprotrace capture --label good --runs 2 -- python3 -c "open('settings.toml').read()"
rm settings.toml
reprotrace capture --label bad --runs 2 -- python3 -c "open('settings.toml').read()"
reprotrace diff good bad
reprotrace report
```

The `bad` captures print Python's `FileNotFoundError`; that is the failure being
investigated. `diff` then prints something like this (shortened; the counts depend on the
machine):

```text
Comparison  |  good (2 run(s)) vs bad (2 run(s))
Command: python3 -c open('settings.toml').read()
Exit codes: good exit 0, bad exit 1

Top divergences (ranked, heuristic)  |  105 total: 1 critical, 0 warning, 104 info

  1  [CRITICAL]  score 0.97  (d1, result_mismatch)
     openat <cwd>/settings.toml: OK on good, ENOENT on bad
     Evidence: good run_2817a3af02be:566   bad run_9ad0fd8d347e:566
     Why ranked here: failed on bad (ENOENT) but succeeded on good; result_mismatch (category
     weight 1.0); 1st of 105 divergences in process p0; stable across repeated runs (2 on
     good, 2 on bad); 328 events before the failing exit on bad
```

`report` writes the full Markdown report to `.reprotrace/reports/`. See
[`docs/example-report.md`](docs/example-report.md) for one made from real captures, where a
missing file and a different time zone both differ.

## Commands

| Command | What it does |
|---|---|
| `reprotrace capture --label NAME [--runs N] -- CMD ...` | Trace a command (N times) and save the runs under a label |
| `reprotrace show RUN_ID` | One run: failed file opens, programs run, network connections |
| `reprotrace runs` | Saved runs, grouped by capture |
| `reprotrace diff A B` | Compare two labels (newest capture of each), group ids or run ids; ranked |
| `reprotrace report [CMP_ID]` | Markdown report of the latest (or a given) comparison |

Global options go before the command: `reprotrace --no-color diff ...` for plain output (or
set `NO_COLOR`), `reprotrace --debug ...` for stack traces. Data is stored in `.reprotrace/`
in the current folder.

## Comparing CI with your machine

[`docs/CI.md`](docs/CI.md) shows how to capture the command in GitHub Actions, download the
run folders as an artifact, and compare them with a capture from your machine. The workflow
in `.github/workflows/ci.yml` includes a working example.

## Privacy

strace records the full environment of the traced command, so `raw.strace` files can
contain secrets (tokens, keys) from your shell. They stay in `.reprotrace/runs/` and are never
uploaded by ReproTrace. Terminal output, `meta.json` and reports redact secret-looking values,
but review raw traces before sharing them, and keep `.reprotrace/` out of version control.

## Evaluation

`eval/scenarios/` holds eight failures planted in pairs of Docker images (missing CA bundle,
time zone, locale, missing environment variable, dependency version, file permission,
missing program on `PATH`, missing config file). One command builds the images, captures both
sides, compares them and scores where the planted cause ranks (needs Docker; about 5-10
minutes):

```text
python eval/run_eval.py --update-readme
```

<!-- eval:start -->
Measured 2026-10-21 with `python eval/run_eval.py` (3 runs per side).

| Scenario | Cause rank | Top 3 | Divergences | Ranked above cause | Warnings | Runs needed | Rank with 1 run | Tracing overhead |
|---|---|---|---|---|---|---|---|---|
| dependency_version | 1 | yes | 9 | 0 | 4 | 1 | 1 | 3.1x |
| locale | 1 | yes | 52 | 0 | 3 | 1 | 1 | 2.2x |
| missing_ca_bundle | 1 | yes | 5 | 0 | 1 | 1 | 1 | 2.5x |
| missing_config_file | 1 | yes | 9 | 0 | 1 | 1 | 1 | 3.0x |
| missing_env_var | 1 | yes | 7 | 0 | 1 | 1 | 1 | 3.8x |
| path_binary | 1 | yes | 21 | 0 | 2 | 1 | 1 | 3.6x |
| permission | 1 | yes | 9 | 0 | 1 | 1 | 1 | 3.2x |
| timezone | 1 | yes | 7 | 0 | 3 | 1 | 1 | 3.8x |

**Totals:** top-1 8/8, top-3 8/8.

Scenarios are written by the author of ReproTrace, so these numbers describe these scenarios only; they are not general proof of accuracy. Tracing overhead compares the mean traced run (including strace start-up) with the mean untraced run of the same command; the commands are short, so start-up dominates.
<!-- eval:end -->

## Limitations

- Linux only, and the command must be traceable: inside containers strace may need
  `--cap-add=SYS_PTRACE` (see `docs/CI.md`).
- Tracing slows commands down (about 3-4x on the short evaluation commands, mostly strace
  start-up), so timing-dependent failures may not reproduce under tracing.
- strace cannot see which environment variables a program actually reads (`getenv()`); the
  environment comparison covers everything passed to the command.
- The same command line must be captured on both sides; processes are matched by the
  programs they run.
- The ranking is a heuristic tuned on a small set of author-written scenarios. Read the
  evidence, not just the score.
- Run-to-run noise is filtered only for sides captured with two or more runs.

## Experimental: AI explanation

`reprotrace explain` can send the top-ranked divergences (summaries, reasons, event ids, short
redacted excerpts; never raw traces or the environment) to Google Gemini and add the
returned hypotheses to the report, labeled as AI-generated. Answers that cite evidence not in
the comparison are rejected. It needs `GEMINI_API_KEY`, is tested only against a simulated
provider so far, and is not needed for anything else. Google's free tier may use prompts to
improve its products.

## Development

```text
git clone https://github.com/Ketan-Verma21/ReproTrace && cd ReproTrace
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check .
```

The tests use real strace recordings in `testdata/traces/` (regenerate them with
`testdata/capture_fixtures.sh`); several tests also trace small commands live, so install
strace first.

## License

MIT. See [LICENSE](LICENSE).
