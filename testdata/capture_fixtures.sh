#!/usr/bin/env bash
# Regenerates the real strace fixtures in testdata/traces/ (Rules.md 7: fixtures are real
# captures and are never hand-edited). Run from anywhere with the project venv installed.
#
#   bash testdata/capture_fixtures.sh              # capture every fixture
#   bash testdata/capture_fixtures.sh repeat_      # only fixtures whose name starts with repeat_
#
# Each command runs with a minimal environment (env -i) because strace -v writes the full
# environment into the raw trace, and these files are committed.
# Note: tests assert some values (PIDs) from the current captures; regenerating an existing
# fixture means updating those assertions.
#
# Not made by this script: ci_github_* (artifact of .github/workflows/ci.yml) and eval_*
# (the first two runs per side of `python eval/run_eval.py --scenario timezone --scenario
# path_binary --keep`, copied with their meta.json; captured inside the scenario containers).
#
# Not produced by this script: ci_github_1/2 (.strace + .meta.json) are the two runs of the
# `capture` job in .github/workflows/ci.yml (GitHub Actions, commit 0722f1f, 2026-10-21),
# copied unchanged from the `reprotrace-ci-runs` artifact, ordered by started_at.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/testdata/traces"
CLEAN_ENV=(env -i "PATH=$ROOT/.venv/bin:/usr/bin:/bin" "HOME=$HOME" "LANG=C.UTF-8")
ONLY="${1:-}"
mkdir -p "$OUT"

wanted() { [[ -z "$ONLY" || "$1" == "$ONLY"* ]]; }

# Print run folders under $1, oldest first by started_at in meta.json.
runs_by_start() {
  python3 - "$1" <<'PY'
import json
import pathlib
import sys

metas = pathlib.Path(sys.argv[1]).glob("*/meta.json")
for meta in sorted(metas, key=lambda p: json.loads(p.read_text())["started_at"]):
    print(meta.parent)
PY
}

# capture NAME RUNS TIMEOUT COMMAND...
#   RUNS=1 -> OUT/NAME.strace and OUT/NAME.meta.json
#   RUNS>1 -> OUT/NAME_1.strace ... (one group, same environment)
# Optional variables set on the call: LABEL (default fixture), TZ_VALUE (adds TZ to the
# environment), EXTRA_ENV (one NAME=value added to the environment), SETTINGS_FILE=1
# (creates settings.toml in the working directory first).
capture() {
  local name=$1 runs=$2 timeout=$3
  shift 3
  wanted "$name" || return 0
  local base
  base="$(mktemp -d)"
  local env_cmd=("${CLEAN_ENV[@]}")
  [[ -n "${TZ_VALUE:-}" ]] && env_cmd+=("TZ=$TZ_VALUE")
  [[ -n "${EXTRA_ENV:-}" ]] && env_cmd+=("$EXTRA_ENV")
  [[ -n "${SETTINGS_FILE:-}" ]] && printf 'debug = false\n' >"$base/settings.toml"
  (cd "$base" && "${env_cmd[@]}" reprotrace capture --label "${LABEL:-fixture}" --runs "$runs" \
    --timeout "$timeout" -- "$@")
  local index=0 run suffix
  # Runs are ordered by the start time recorded in their meta.json.
  while read -r run; do
    index=$((index + 1))
    suffix=""
    [[ "$runs" -gt 1 ]] && suffix="_$index"
    cp "$run/raw.strace" "$OUT/$name$suffix.strace"
    cp "$run/meta.json" "$OUT/$name$suffix.meta.json"
  done < <(runs_by_start "$base/.reprotrace/runs")
  rm -rf "$base"
  echo "saved $name ($runs run(s))"
}

capture local_python_missing_file 1 60 python3 -c "open('/nonexistent/config.toml')"
capture local_multiprocess 1 60 sh -c 'ls /etc/hostname /nonexistent; cat /etc/hostname & wait'
capture local_connect_refused 1 60 python3 -c \
  "import socket; s = socket.socket(); s.settimeout(1); print(s.connect_ex(('127.0.0.1', 9)))"
capture local_long_path 1 60 python3 -c "open('/nonexistent/' + 'x' * 300)"
capture local_killed_by_signal 1 60 sh -c 'kill -TERM $$'
capture local_timeout 1 1 sleep 5

# Repeated runs of one command in one environment, for the Phase 3 noise filter.
capture repeat_python_tempfile 3 60 python3 -c \
  "import os, tempfile; open(f'/proc/{os.getpid()}/status').read(); d = tempfile.mkdtemp(); open(os.path.join(d, 'f.txt'), 'w').close(); open('/nonexistent/config.toml')"
capture repeat_multiprocess 3 60 sh -c 'ls /etc/hostname /nonexistent; cat /etc/hostname & wait'

# Known-difference pair for Phase 4 (diff): same command, two environments.
#   good: settings.toml present, TZ=UTC            -> exit 0
#   bad:  settings.toml missing, TZ=Asia/Kolkata   -> exit 1 (FileNotFoundError)
PAIR_CMD=(python3 -c "import time; time.localtime(); open('settings.toml').read()")
LABEL=good TZ_VALUE=UTC SETTINGS_FILE=1 capture pair_good 2 60 "${PAIR_CMD[@]}"
LABEL=bad TZ_VALUE=Asia/Kolkata capture pair_bad 2 60 "${PAIR_CMD[@]}"

# Second pair for Phase 5 (ranking): the cause is a missing environment variable.
#   good: APP_MODE=prod   -> exit 0
#   bad:  APP_MODE unset  -> exit 1 (KeyError)
ENV_CMD=(python3 -c "import os; print(os.environ['APP_MODE'])")
LABEL=good EXTRA_ENV=APP_MODE=prod capture pair_env_good 2 60 "${ENV_CMD[@]}"
LABEL=bad capture pair_env_bad 2 60 "${ENV_CMD[@]}"

# Minimal Docker image: same strace flags as reprotrace.config.STRACE_FLAGS, run directly
# because the image has no reprotrace install. Produces a .strace file only.
if wanted docker_python_missing_file && [[ "${SKIP_DOCKER:-0}" != "1" ]]; then
  docker run --rm --cap-add=SYS_PTRACE -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$OUT:/out" python:3.11-slim sh -c '
      apt-get update -qq >/dev/null && apt-get install -y -qq strace >/dev/null
      strace -f -ttt -y -s 200 -v -o /out/docker_python_missing_file.strace \
        -- python3 -c "open(\"/nonexistent/config.toml\")" || true
      chown "$HOST_UID:$HOST_GID" /out/docker_python_missing_file.strace'
  echo "saved docker_python_missing_file"
fi
