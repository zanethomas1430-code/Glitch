#!/bin/bash
# Run the testbed against a hosted model: 3 notice-only runs and 1 enforced stop run.
#   export ANTHROPIC_API_KEY=...        (in YOUR terminal; never paste it into a chat or a file)
#   ./run_hosted.sh                      default model claude-opus-5-5
#   MODEL=claude-fable-5-1 ./run_hosted.sh
# Rough size: 7 scenarios x ~3-6 short calls x 3 runs, plus the enforced stop: about 80-120 calls, a few cents to a couple of dollars by model.
set -u
cd "$(dirname "$0")"
MODEL="${MODEL:-claude-opus-5-5}"; KEYVAR="${KEYVAR:-ANTHROPIC_API_KEY}"; URL="${URL:-https://api.anthropic.com}"
if [ -z "${!KEYVAR:-}" ]; then echo "Set $KEYVAR in this terminal first (export $KEYVAR=...). Nothing was run."; exit 1; fi
SAFE="$(echo "$MODEL" | tr -c 'A-Za-z0-9_.\n-' '_')"
for i in 1 2 3; do
  echo "########## $MODEL notice run $i"
  python3 run_testbed.py --model "$MODEL" --base-url "$URL" --api-key-env "$KEYVAR" --max-tokens 1024 --max-steps 10 --label "${SAFE}_notice_r$i" || { echo "stopped: see the message above"; exit 1; }
done
echo "########## $MODEL enforced stop"
python3 run_testbed.py --model "$MODEL" --base-url "$URL" --api-key-env "$KEYVAR" --max-tokens 1024 --max-steps 10 --mode enforced --only stop_midtask --label "${SAFE}_enforced_stop"
echo "########## done"
