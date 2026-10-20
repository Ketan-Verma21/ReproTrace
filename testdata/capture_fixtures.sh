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
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/testdata/traces"
CLEAN_ENV=(env -i "PATH=$ROOT/.venv/bin:/usr/bin:/bin" "HOME=$HOME" "LANG=C.UTF-8")
ONLY="${1:-}"
mkdir -p "$OUT"

wanted() { [[ -z "$ONLY" || "$1" == "$ONLY"* ]]; }

# capture NAME RUNS TIMEOUT COMMAND...
#   RUNS=1 -> OUT/NAME.strace and OUT/NAME.meta.json
#   RUNS>1 -> OUT/NAME_1.strace ... (one group, same environment)
capture() {
  local name=$1 runs=$2 timeout=$3
  shift 3
  wanted "$name" || return 0
  local base
  base="$(mktemp -d)"
  (cd "$base" && "${CLEAN_ENV[@]}" reprotrace capture --label fixture --runs "$runs" \
    --timeout "$timeout" -- "$@")
  local index=0 meta run suffix
  # Runs are ordered by their start time recorded in meta.json.
  while read -r meta; do
    index=$((index + 1))
    run="$(dirname "$meta")"
    suffix=""
    [[ "$runs" -gt 1 ]] && suffix="_$index"
    cp "$run/raw.strace" "$OUT/$name$suffix.strace"
    cp "$run/meta.json" "$OUT/$name$suffix.meta.json"
  done < <(grep -l '"started_at"' "$base"/.reprotrace/runs/*/meta.json |
    xargs -I{} sh -c 'printf "%s %s\n" "$(grep -o "\"started_at\": \"[^\"]*\"" {})" {}' |
    sort | awk '{print $NF}')
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
