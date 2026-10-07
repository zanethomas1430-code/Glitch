#!/bin/bash
# The adaptive adversary played by a hosted model (a stronger red-teamer than the local ones), against the hardened defender.
#   export ANTHROPIC_API_KEY=...   (in YOUR terminal; never paste it into a chat or a file)
#   MODEL=claude-sonnet-5-5 ./run_adaptive_hosted.sh
#   For another provider that speaks the OpenAI shape: STYLE=openai URL=https://api.example.com KEYVAR=THEIR_KEY_VAR MODEL=their-model ./run_adaptive_hosted.sh
# Note: hosted models may refuse this role (an empty reply with stop_reason refusal). That is recorded, not worked around.
set -u
cd "$(dirname "$0")"
MODEL="${MODEL:-claude-sonnet-5-5}"; KEYVAR="${KEYVAR:-ANTHROPIC_API_KEY}"; URL="${URL:-https://api.anthropic.com}"
if [ -z "${!KEYVAR:-}" ]; then echo "Set $KEYVAR in this terminal first. Nothing was run."; exit 1; fi
python3 adaptive.py --model "$MODEL" --base-url "$URL" --api-key-env "$KEYVAR" --api-style "${STYLE:-anthropic}" --hardened --rounds 3 --per-round 6 --max-tokens 4000 --label "adaptive2_$(echo "$MODEL" | tr -c 'A-Za-z0-9_.\n-' '_')"
