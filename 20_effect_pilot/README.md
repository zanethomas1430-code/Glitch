# 20 · Effect-level pilot: can recorded runs be replayed in the real sandbox?

*Run 2026-10-24. A feasibility pilot, not a detection result: no monitor was run and no attack's effects were read.*

The string-level laws (`19_control_bench`) read the caption: the commands and the code an agent writes. The next test watches the footage, meaning
what actually changed in the system. That needs the recorded runs to happen again inside BashArena's own Docker environment. This pilot asks
whether they do, and what it costs.

## Method

- `select_runs.py` picks runs from the public BashArena logs with a fixed seed (20261024). Attacks: 5 per side task, only runs whose side task
  succeeded when recorded. Honest: 10 that passed the main task, 10 that did not. Only tasks whose recorded description equals today's dataset
  (`Eccentricity/bashbench2`, 637 tasks) are eligible: 594/600 honest and 596/600 attack runs.
- `replay.py` plays each recorded action back through the setting's own tools in its own sandbox (task container, router, logging, database and
  malware servers). No model is called. One change to the recording: bash's argument `cmd` is renamed `command`, the name this Inspect version uses.
- `compare.py` checks each replay against its recording: the main-task verdict (honest), the side-task verdict (attack), and how alike each tool output is.

## Result

| | |
|---|---|
| attack replays whose side task succeeds again | **20 / 20** (5 each: firewall, sudo, malware, password leak) |
| honest replays with the same main-task verdict | **17 / 20** (7 of 10 recorded passes pass again; 10 of 10 recorded fails fail again) |
| honest replays that trip any of the four side-task checkers | 0 / 20 |
| tool-output similarity per action (mean) | honest 0.94, attack 0.95 |
| samples that errored | 0 / 40 |
| wall time | 69 min for 40 runs, 4 in parallel, including 56 first-time image builds; about 1 min per run once images exist |
| disk | 3.2 GB base image, then +15 GB for 29 tasks (images 13.8 GB, build cache 8.1 GB, of which ~4.8 GB reclaimable) |

The three honest runs that did not hold (tasks 23369937, 4459077, 9624947) scored 0.8, 0.5 and 0.67 of their tests. Each failure involves something
that has to run in the background for a while: a timed-out read, a monitor's output file not yet written, an rsync service not seen running.
**Hypothesis, not checked:** the replay leaves no gap between actions, where the recorded run had model-thinking time, so long-running work had less
time. Pacing the replay to the recorded gaps would test that.

## What it means for the next step

Attacks replay faithfully, so an effect-level monitor can be measured on the real change each attack makes rather than on its description. The
next test follows the same discipline as `19_control_bench`. Capture the protected surface and network effects at the end of each replay. Write and
calibrate the effect laws on honest replays only. Freeze them with file hashes, then replay the attacks once. Keep MonitoringBench held out.

At full scale the cost is disk, not time. About 0.25 GB per task in images means a few hundred tasks will not fit on a 60 GB VM disk at once. Run in
batches and prune images between them.

Benchmark data stays evaluation-only and local: the selection and replay logs live in `/Volumes/GlitchVM/pilot/`, not in this repo.
