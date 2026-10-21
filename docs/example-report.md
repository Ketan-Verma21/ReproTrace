# ReproTrace Report: cmp_f1e3cf3234f8

> **Before sharing:** this report contains paths and command lines from the traced runs. Raw traces in `.reprotrace/runs/` contain the full, unredacted environment of the traced command; review them before attaching them anywhere.

## Summary

- **Command:** `python3 -c 'import time; time.localtime(); open('"'"'settings.toml'"'"').read()'`
- **Environments compared:** `good` (2 run(s), `good`) vs `bad` (2 run(s), `bad`)
- **Exit codes:** good exit 0, bad exit 1
- **Divergences:** 9 (2 critical, 2 warning, 5 info)
- **Likely cause:** openat &lt;cwd&gt;/settings.toml: OK on good, ENOENT on bad (score 0.92). This is the highest-ranked divergence; the ranking is a heuristic, not proof.

## Top divergences

### 1. openat &lt;cwd&gt;/settings.toml: OK on good, ENOENT on bad

**CRITICAL**, score 0.92, `result_mismatch`, id `d6`

- **What differed:** The same call had a different result on the two sides.
- **Evidence:** `good` run_252f921d3c4c:367; `bad` run_ee09d7152d3c:367

```text
good  run_252f921d3c4c:367
  17622 1792573992.155200 openat(AT_FDCWD</tmp/tmp.l1Dq7j4akO>, "settings.toml", O_RDONLY|O_CLOEXEC) = 3</tmp/tmp.l1Dq7j4akO/settings.toml>
bad  run_ee09d7152d3c:367
  17651 1792573992.479749 openat(AT_FDCWD</tmp/tmp.Muindl9TcH>, "settings.toml", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
```

- **Why it ranked here:**
  - failed on bad (ENOENT) but succeeded on good
  - result_mismatch (category weight 1.0)
  - 5th of 8 divergences in process p0
  - stable across repeated runs (2 on good, 2 on bad)
  - 8 events before the failing exit on bad

### 2. Environment variable TZ: UTC on good, Asia/Kolkata on bad

**CRITICAL**, score 0.73, `env_diff`, id `d1`

- **What differed:** The environment passed to the command differs.
- **Evidence:** `good` run_252f921d3c4c:0; `bad` run_ee09d7152d3c:0

```text
good  run_252f921d3c4c:0
  17622 1792573992.115424 execve("/home/ketan/Code/Python/Reprotrace/.venv/bin/python3", ["python3", "-c", "import time; time.localtime(); open('settings.toml').read()"], [/* 4 variables, see Environment differences */]) = 0
bad  run_ee09d7152d3c:0
  17651 1792573992.463126 execve("/home/ketan/Code/Python/Reprotrace/.venv/bin/python3", ["python3", "-c", "import time; time.localtime(); open('settings.toml').read()"], [/* 4 variables, see Environment differences */]) = 0
```

- **Why it ranked here:**
  - TZ has a different value where the command failed
  - env_diff (category weight 0.8)
  - set before the program started
  - stable across repeated runs (2 on good, 2 on bad)

### 3. openat /usr/share/zoneinfo/UTC (OK) only on good

**WARNING**, score 0.58, `file_only_in_a`, id `d2`

- **What differed:** A file call happened only on good.
- **Evidence:** `good` run_252f921d3c4c:115; `bad` -

```text
good  run_252f921d3c4c:115
  17622 1792573992.143100 openat(AT_FDCWD</tmp/tmp.l1Dq7j4akO>, "/usr/share/zoneinfo/UTC", O_RDONLY|O_CLOEXEC) = 3</usr/share/zoneinfo/Etc/UTC>
```

- **Why it ranked here:**
  - file_only_in_a (category weight 0.5)
  - 1st of 8 divergences in process p0
  - stable across repeated runs (2 on good, 2 on bad)

### 4. newfstatat /usr/share/zoneinfo/Etc/UTC (OK) only on good (x2)

**WARNING**, score 0.54, `file_only_in_a`, id `d4`

- **What differed:** A file call happened only on good.
- **Evidence:** `good` run_252f921d3c4c:116, run_252f921d3c4c:117; `bad` -

```text
good  run_252f921d3c4c:116
  17622 1792573992.143184 newfstatat(3</usr/share/zoneinfo/Etc/UTC>, "", {st_dev=makedev(0x8, 0x3), st_ino=4197660, st_mode=S_IFREG|0644, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=8, st_size=114, st_atime=1792489658 /* 20 ...
good  run_252f921d3c4c:117
  17622 1792573992.143249 newfstatat(3</usr/share/zoneinfo/Etc/UTC>, "", {st_dev=makedev(0x8, 0x3), st_ino=4197660, st_mode=S_IFREG|0644, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=8, st_size=114, st_atime=1792489658 /* 20 ...
```

- **Why it ranked here:**
  - file_only_in_a (category weight 0.5)
  - 3rd of 8 divergences in process p0
  - stable across repeated runs (2 on good, 2 on bad)

### 5. openat /usr/share/zoneinfo/Asia/Kolkata (OK) only on bad

**INFO**, score 0.34, `file_only_in_b`, id `d3`

- **What differed:** A file call happened only on bad.
- **Evidence:** `good` -; `bad` run_ee09d7152d3c:115

```text
bad  run_ee09d7152d3c:115
  17651 1792573992.469587 openat(AT_FDCWD</tmp/tmp.Muindl9TcH>, "/usr/share/zoneinfo/Asia/Kolkata", O_RDONLY|O_CLOEXEC) = 3</usr/share/zoneinfo/Asia/Kolkata>
```

- **Why it ranked here:**
  - file_only_in_b (category weight 0.5)
  - 2nd of 8 divergences in process p0
  - stable across repeated runs (2 on good, 2 on bad)
  - 260 events before the failing exit on bad
  - the path contains Asia/Kolkata, the value of TZ: follows from that difference

### 6. newfstatat /usr/share/zoneinfo/Asia/Kolkata (OK) only on bad (x2)

**INFO**, score 0.30, `file_only_in_b`, id `d5`

- **What differed:** A file call happened only on bad.
- **Evidence:** `good` -; `bad` run_ee09d7152d3c:116, run_ee09d7152d3c:117

```text
bad  run_ee09d7152d3c:116
  17651 1792573992.469619 newfstatat(3</usr/share/zoneinfo/Asia/Kolkata>, "", {st_dev=makedev(0x8, 0x3), st_ino=4194786, st_mode=S_IFREG|0644, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=8, st_size=285, st_atime=1792592469  ...
bad  run_ee09d7152d3c:117
  17651 1792573992.469645 newfstatat(3</usr/share/zoneinfo/Asia/Kolkata>, "", {st_dev=makedev(0x8, 0x3), st_ino=4194786, st_mode=S_IFREG|0644, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=8, st_size=285, st_atime=1792592469  ...
```

- **Why it ranked here:**
  - file_only_in_b (category weight 0.5)
  - 4th of 8 divergences in process p0
  - stable across repeated runs (2 on good, 2 on bad)
  - 258 events before the failing exit on bad
  - the path contains Asia/Kolkata, the value of TZ: follows from that difference

### 7. newfstatat &lt;cwd&gt;/settings.toml (OK) only on good (x2)

**INFO**, score 0.23, `file_only_in_a`, id `d7`

- **What differed:** A file call happened only on good.
- **Evidence:** `good` run_252f921d3c4c:368, run_252f921d3c4c:372; `bad` -

```text
good  run_252f921d3c4c:368
  17622 1792573992.155224 newfstatat(3</tmp/tmp.l1Dq7j4akO/settings.toml>, "", {st_dev=makedev(0x8, 0x3), st_ino=6291574, st_mode=S_IFREG|0664, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=14, st_atime=17925 ...
good  run_252f921d3c4c:372
  17622 1792573992.155307 newfstatat(3</tmp/tmp.l1Dq7j4akO/settings.toml>, "", {st_dev=makedev(0x8, 0x3), st_ino=6291574, st_mode=S_IFREG|0664, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=14, st_atime=17925 ...
```

- **Why it ranked here:**
  - file_only_in_a (category weight 0.5)
  - 6th of 8 divergences in process p0
  - stable across repeated runs (2 on good, 2 on bad)
  - only on good after the two runs stopped matching: likely a consequence of an earlier difference

### 8. Process p0 ended differently: exit 0 on good, exit 1 on bad

**INFO**, score 0.22, `exit_status_mismatch`, id `d9`

- **What differed:** The process ended differently.
- **Evidence:** `good` run_252f921d3c4c:379, run_252f921d3c4c:380; `bad` run_ee09d7152d3c:374, run_ee09d7152d3c:375

```text
good  run_252f921d3c4c:379
  17622 1792573992.157177 exit_group(0)   = ?
good  run_252f921d3c4c:380
  17622 1792573992.157414 +++ exited with 0 +++
bad  run_ee09d7152d3c:374
  17651 1792573992.481774 exit_group(1)   = ?
bad  run_ee09d7152d3c:375
  17651 1792573992.482032 +++ exited with 1 +++
```

- **Why it ranked here:**
  - exit_status_mismatch (category weight 0.2)
  - 8th of 8 divergences in process p0
  - stable across repeated runs (2 on good, 2 on bad)
  - 0 events before the failing exit on bad
  - the exit status is the symptom being explained, not a cause

### 9. ioctl &lt;cwd&gt;/settings.toml (ENOTTY) only on good

**INFO**, score 0.16, `other_only_in_a`, id `d8`

- **What differed:** A other call happened only on good.
- **Evidence:** `good` run_252f921d3c4c:369; `bad` -

```text
good  run_252f921d3c4c:369
  17622 1792573992.155249 ioctl(3</tmp/tmp.l1Dq7j4akO/settings.toml>, TCGETS, 0x7ffef2fccca0) = -1 ENOTTY (Inappropriate ioctl for device)
```

- **Why it ranked here:**
  - other_only_in_a (category weight 0.2)
  - 7th of 8 divergences in process p0
  - stable across repeated runs (2 on good, 2 on bad)
  - only on good after the two runs stopped matching: likely a consequence of an earlier difference

## How to reproduce

Capture each environment again, then compare:

```text
# in the good environment
reprotrace capture --label good --runs 2 -- python3 -c 'import time; time.localtime(); open('"'"'settings.toml'"'"').read()'
# in the bad environment
reprotrace capture --label bad --runs 2 -- python3 -c 'import time; time.localtime(); open('"'"'settings.toml'"'"').read()'
# then, with both run folders in one project
reprotrace diff GRP_A GRP_B
```

Original groups: `good` and `bad`.

## Environment differences

| Variable | good | bad |
|---|---|---|
| `TZ` | UTC | Asia/Kolkata |

Values are normalized (home folder as `~`, working directory as `<cwd>`) and secrets are redacted.

## Limitations

- Ranking is a heuristic. A high score means the divergence is consistent with the failure, not that it is proven to cause it.
- Tracing with strace slows the command down and can hide timing-dependent bugs.
- strace cannot see which environment variables a program reads (`getenv()`); environment differences compare everything passed to the command.
- Run-to-run noise is filtered only for sides captured with two or more runs.
- Evidence ids refer to the first run of each side; excerpts are shortened and sanitized. Full lines are in `events.jsonl` and `raw.strace` of those runs.

---

Generated 2026-10-21 18:41 UTC by reprotrace 0.1.0. Comparison created 2026-10-21 18:41 UTC.
