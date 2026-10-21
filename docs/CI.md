# Comparing a CI run with a local run

ReproTrace needs a capture from each environment. This guide shows how to capture the CI side
in GitHub Actions, download it, and compare it with a capture from your machine.

## 1. The workflow

`.github/workflows/ci.yml` has two jobs:

- `test` runs Ruff and the test suite on Python 3.11 and 3.12.
- `capture` installs strace and ReproTrace, captures a command twice with the label `ci`, and
  uploads the run folders as an artifact named `reprotrace-ci-runs` (kept for 7 days).

The example command in the `capture` job is:

```text
reprotrace capture --label ci --runs 2 -- \
  python3 -c "import time; time.localtime(); open('settings.toml').read()"
```

Replace it with the command you want to investigate, for example
`pytest tests/test_api.py::test_fetch`. Use the exact same command on both sides: processes are
matched by what they run, so a different command line produces many unrelated differences.

The job runs on every push and pull request, and can be started by hand from the Actions tab
(`workflow_dispatch`).

## 2. Download the CI runs

With the GitHub CLI (`gh`), from your project folder:

```text
gh run list --workflow ci.yml --limit 5
gh run download RUN_ID --name reprotrace-ci-runs --dir ci-runs
```

`RUN_ID` is the number in the first column of `gh run list`. Without the CLI, open the workflow run
on github.com, scroll to **Artifacts**, download `reprotrace-ci-runs`, and unzip it into `ci-runs`.

Then copy the run folders into your project's ReproTrace data folder:

```text
mkdir -p .reprotrace/runs
cp -r ci-runs/run_* .reprotrace/runs/
reprotrace runs
```

`reprotrace runs` indexes the copied folders automatically and lists the `ci` group. A folder that
was only partly copied is listed as skipped, with the reason, instead of breaking the listing.

## 3. Capture locally and compare

Run the same command on your machine, ideally twice so run-to-run noise can be filtered. For the
example command, create the file it reads first, so the local side passes while CI fails:

```text
printf 'debug = false\n' > settings.toml
reprotrace capture --label local --runs 2 -- python3 -c "import time; time.localtime(); open('settings.toml').read()"
reprotrace diff local ci
reprotrace report
```

`diff` accepts labels: `local` and `ci` mean the most recent capture group with that label. You can
also pass a group id (`grp_...`) or a run id (`run_...`) from `reprotrace runs`. `report` without an
argument writes the report of the latest comparison to `.reprotrace/reports/`.

Paths that only differ by machine are normalized before comparing: the home folder
(`/home/runner` versus `/home/you`) becomes `~`, and the working directory becomes `<cwd>`.
Differences that remain, such as a different Python installation path, are real differences
between the environments and are listed and ranked.

A GitHub runner sets more than 100 environment variables your machine does not have
(`GITHUB_*`, `RUNNER_*`, `JAVA_HOME`, ...). They are listed, but ranked low: a variable that exists
only on the failing side rarely causes a failure, and CI platform variables almost never do. The
same goes for your terminal and desktop session (`DISPLAY`, `XDG_*`, `LS_COLORS`, ...), which CI
never has. A variable that is missing on the failing side, or has a different value, ranks
high when only a few variables differ that way; when your shell has many that CI lacks
(`AWS_*`, `EDITOR`, ...), each of them counts less, because any single one is then weak
evidence. Locale variables (`LANG`, `LC_*`) and `VIRTUAL_ENV` are always treated as
meaningful.

## 4. Secrets: what the artifact contains

strace is run with `-v`, which records the **full environment** of the traced command in
`raw.strace`. That is what lets ReproTrace find a missing or different environment variable, and it
also means the uploaded artifact contains every variable of the capture step. Anyone who can read
the repository's Actions can download the artifact.

To keep secrets out of it:

1. **Do not pass secrets to the capture step.** GitHub only puts a secret into a step's
   environment when the workflow maps it explicitly (`env: API_KEY: ${{ secrets.API_KEY }}`). Keep
   such mappings out of the capture step.
2. The capture step unsets every variable whose name contains `TOKEN`, `SECRET`, `KEY`,
   `PASSWORD`, `PASSWD`, `CREDENTIAL` or `AUTH` before capturing. This is a safety net, not a
   guarantee: a secret stored under an unremarkable name, such as `DATABASE_URL` holding a password,
   is not caught.
3. If the command needs a secret to run, capture a variant that does not, or capture on a
   self-hosted runner and do not upload the artifact.

ReproTrace never uploads anything itself. Locally, `meta.json`, terminal output and reports show
secret-looking values as `<redacted>`, but `raw.strace` and `events.jsonl` are kept verbatim
because they are the evidence. Review them before sharing them.

## 5. When strace is not allowed to trace

strace uses the kernel's `ptrace` interface. If it is blocked, `reprotrace capture` stops with:

```text
Error: strace produced no trace. It is probably not allowed to use ptrace here.
```

and exits with code 2.

- **GitHub-hosted Ubuntu runners** allow a process to trace its own children, which is all
  ReproTrace needs. No extra setup is required.
- **Container jobs** (`container:` in the workflow) and `docker run` may block ptrace, depending on
  the Docker version and security profile. Add the capability to the job:

  ```yaml
  container:
    image: python:3.11-slim
    options: --cap-add=SYS_PTRACE
  ```

- **Self-hosted runners or hardened hosts** may set `kernel.yama.ptrace_scope` to 2 or 3, which
  blocks tracing. Check it with `cat /proc/sys/kernel/yama/ptrace_scope`: 0 and 1 work.

**Container fallback.** If the runner itself cannot trace, run the capture inside a container that
is allowed to:

```text
docker run --rm --cap-add=SYS_PTRACE -v "$PWD":/work -w /work python:3.11-slim sh -c '
  apt-get update -qq && apt-get install -y -qq strace >/dev/null &&
  pip install -q . &&
  reprotrace capture --label ci --runs 2 -- python3 -c "import time; time.localtime(); open(\"settings.toml\").read()"'
```

The run folders appear in `.reprotrace/runs/` of the mounted project and can be uploaded the same
way. The files are owned by root; run `sudo chown -R "$(id -u):$(id -g)" .reprotrace` afterwards if
you need to modify them.

## 6. Limitations

- Tracing slows the command down, so timing-dependent failures may not reproduce under strace.
- strace cannot see which environment variables a program actually reads (`getenv()`); the
  environment comparison covers everything passed to the command.
- The ranking is a heuristic. A top-ranked divergence is consistent with the failure; it is not
  proof of the cause.
