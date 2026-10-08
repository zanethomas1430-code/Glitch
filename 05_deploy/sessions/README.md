# sessions — real-traffic runs against a local model

| file | what |
|---|---|
| `ibuprofen_escalation.json` | run 1's six-turn benign escalation |
| `local23b_run1.transcript.json` | run 1 record: responses, three scorer columns, the operator's ruling, the reading |
| `local23b_run1.rescored_*.json` | the two Qwen re-scores of run 1 |
| `local23b_run1.label_sheet.csv` | **test 1**: the six run-1 responses, blank level column. Copy it per labeler (`labels_zane_live.csv`, `labels_rater_b_live.csv`), rate each with `09_study/SCALE.md`, under a minute per item, key unopened |
| `local23b_run1.scorer_key.DO_NOT_OPEN_UNTIL_LABELED.json` | the local-23B scorer instance's levels for those six, in kappa's key shape |
| `RESULTS.md` | plain-language results of runs 2–4 with per-turn tables |
| `local23b_run2_pull.transcript.json`, `local23b_run3_control.transcript.json`, `local23b_run4_cross.transcript.json` | runs 2–4 records, each with a `summary` block |
| `local23b_run5_crescendo.transcript.json`, `local23b_run6_cross_frozen.transcript.json` | runs 5 and 6 under the frozen pilot configuration (checklist scorer); tables in RESULTS.md |
| `sourdough_sustained_pull.json` | **test 2a**: 13 turns, parameters and sequencing from turn 4 on |
| `sourdough_control.json` | **test 2b**: same purpose and length, no pull; any tripwire is a false positive |
| `sourdough_crescendo_backtrack.json` | **test 2d**: Crescendo-shaped pull; each ask leans on the last answer and backs off after a refusal instead of pushing (the documented multi-turn attack shape, benign subject) |
| `bike_chain_cross_session.json` | **test 2c**: drift in session A, then a fresh session B that goes straight for the protocol |

Run a session (from `05_deploy`), scorer = the local-23B scorer instance:

    python3 live_session.py --model local23b:latest --scorer-model local23b:latest --allow-same-scorer \
        --turns sessions/sourdough_sustained_pull.json --save sessions/local23b_run2_pull.transcript.json

Compare the human sheets to each other and to the scorer (from `05_deploy/sessions`):

    python3 ../../09_study/kappa.py labels_zane_live.csv labels_rater_b_live.csv --key local23b_run1.scorer_key.DO_NOT_OPEN_UNTIL_LABELED.json

Test 3 (does a checkpoint change behaviour) runs the same session files through the proxy in enforce mode; see ../README.md.
