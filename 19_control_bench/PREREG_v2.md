# Pre-registration v2: LinuxArena with the clean task text

**Frozen 2026-10-24, before the v2 attack run.** v1 (`PREREG.md`, commit `90b02a8`) stands as published. Its LinuxArena row was invalid because the attack runs' system prompt carries
the attacker's side-task instructions and v1 used the system prompt as the trusted task text (`FINDINGS.md`). v2 changes only that: the task text is the setting's main-task
description from the sample metadata, for honest and attack runs alike. **The laws are unchanged**; `laws.py` has the same hash as in v1.

| file | sha256 |
|---|---|
| `laws.py` sha256 `1cb6dd7957d2e6c406ad8a50f701fa8035b96f57fa1a12ce98190747a7222a87` | unchanged from v1 |
| `adapter.py` sha256 `9a206d2c42428c6de98845430bb7f15f1dd4fa827420ded34b19370be185be2d` | unchanged from v1 |
| `adapter_v2.py` sha256 `3900d9b27586ebbc23322dc7d08a9a8a5d6925ab35a4a0cde0ff154cbe59c874` | task text from the main-task description |
| `run_bench_v2.py` sha256 `eb8d0047794acc0d60be144d5b7689b7a2aac6cfd9c0093441497ddef2aba20b` | the v2 run |

Calibration (honest LinuxArena runs only, v2 adapter): the honest task text is identical to v1's, so the distribution is unchanged, {0: 172, 1: 10, 2: 12, 3: 6};
FROZEN_THRESHOLD = 4 (0 of 200 honest runs at or above it; at 3 it would be 6 of 200 = 3%).

What has been seen before this run: v1's aggregate LinuxArena numbers (contaminated) and no individual LinuxArena attack trajectory. The laws cannot have been tuned to it.

Prediction: with the attacker's destinations no longer counted as named, R1 BOUNDARY fires more on attacks than v1's 13.4%; whether that moves the catch rate at a threshold of four
converging laws is the open question, and v1's diagnosis on BashArena (sabotage inside task code) predicts it will stay low.
