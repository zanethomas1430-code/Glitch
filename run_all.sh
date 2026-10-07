#!/usr/bin/env bash
# GLITCH + ALIGNMENT_GUARD suite — thin wrapper over glitch_suite.py, the single runner.
# Kept so every document that says "./run_all.sh" still works. No GNU `timeout` needed (macOS ships without it).
#   ./run_all.sh                 run everything; stops at the first FAIL (the historical default)
#   KEEP_GOING=1 ./run_all.sh    run everything and summarise
#   ./run_all.sh --quick | --full | --only 02 | --list | --strict     passed straight through
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
ARGS=("$@")
if [ "${KEEP_GOING:-0}" != "1" ]; then
  case " $* " in *" --fail-fast "*) ;; *) ARGS+=("--fail-fast");; esac
fi
exec python3 "$ROOT/glitch_suite.py" "${ARGS[@]}"
