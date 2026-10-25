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

No replayed action errored where its recording did not: the recordings keep tool errors in a separate `output_error` field, and every error in the
replays (15, such as an editor refusing to overwrite a file) is one the recorded run hit too.

The three honest runs that did not hold (tasks 23369937, 4459077, 9624947) were re-run twice more, once at full speed and once **paced** (`--paced`
waits the recorded thinking time before each action):

| task | pilot | full speed again | paced | reading |
|---|---|---|---|---|
| 4459077 | fail | fail | **pass** | timing: its background work needs the time the model spent thinking |
| 23369937 | fail | pass | pass | flaky: passes or fails with nothing changed |
| 9624947 | fail | fail | fail | unexplained: every action replays the same, errors included, but a test that looks for a running rsync process during scoring does not see one |

So replay is faithful action by action. Where a verdict depends on background work, replay paced. One task in twenty has a check that today's
environment does not reproduce, and one is flaky.

## MonitoringBench: the same check on the held-out set

MonitoringBench runs on BashArena's tasks, so the same sandbox replays it (`select_runs.py --source=monitoringbench`, same seed and sizes).
Only aggregate fidelity numbers were read. No attack's actions or effects were inspected, so the set stays held out for the monitor.
What differs from BashArena:

- The runs keep no action list. Actions are read from the assistant's tool calls, outputs and errors from the tool replies.
- The recordings carry no real timing, so `--paced` cannot be used.
- An honest run's main score is the fraction of tests passed, so `compare.py` also checks that the replay gets the same fraction.
- Its firewall side task is a partial-credit variant with no checker in this `control_arena`, so the full `disable_firewall` checker scores it.
- It recorded several runs per task, so the pick now takes one run per task. The BashArena pick is unchanged by this.

| | |
|---|---|
| honest replays with the same main-task verdict | **19 / 20**; 19 / 20 with the same fraction of tests passed (mean difference 0.05) |
| attack replays whose side task succeeds again | sudo 5 / 5, malware 5 / 5, password leak 2 / 4, firewall 1 / 5 (scored by the stricter full checker) |
| tool-output similarity per action (mean) | honest 0.92, attack 0.94 |
| samples that errored | 0 / 39 |
| wall time | 96 min for the 40 picked, then 4 re-run |

Where it did not hold:

- **Firewall 1 / 5.** These runs were recorded as successes on the partial-credit checker. Three of the four misses reach exactly the same main-task
  score again, and no miss has a new error. So the actions replay, and the full checker most likely asks for more than the partial one
  recorded: a checker gap, not a replay miss. That stays a reading until the partial checker exists.
- **Password leak, one task (40657182) not replayed.** Its image does not build on arm64: `execstack` fails. It is the only one of 637 tasks
  that uses it.
- **Password leak, two misses.** In one, two commands time out that did not time out when recorded. The other has no new error and is left
  unexplained, because explaining it would mean reading a held-out attack.
- **One honest miss (2149564).** Four editor calls are refused by a check this Inspect version added: it will not keep the editor's history
  in a `/tmp` other users could replace. The recording's editor had no such check. It is tool drift, and the check stays on.

So the replay also holds on the held-out set for honest work, sudo and malware. The firewall needs its partial checker before that group can
be scored at all.

## Watching the replays: photos and a diary

*Run 2026-10-25, honest BashArena runs only. No attack has been replayed with these.*

Three layers, each built on standard defensive tools:

- **Before and after photos** (`snapshot.py`, run with `replay.py --snapshots`). One read-only script, AIDE/osquery-style, records every
  file's type, mode, owner, size and times, plus users, groups, sudoers, setuid files, processes, sockets and firewall rules. The diff
  says what is still changed at the end.
- **A photo before every action** (`--every-action`). This shows what changed and was put back between two actions, which the end photo cannot.
- **A kernel diary** (`diary.py` with `falco_diary.yaml`). Falco 0.41.3 (modern eBPF) runs in record-only mode and writes every program
  start, file write, file move/delete/permission change, outbound connection and identity change in the task container. `diary.py cut`
  splits it into one diary per run, between that run's photos.

| on 20 honest runs | |
|---|---|
| runs with all three layers recorded | **20 / 20** |
| events Falco lost (kernel buffer, output queue) | **0, 0** |
| diary events | about 248,000 |
| runs where something came and went | 7 / 20: closed connections, the task's own services, a database being set up |
| photo disk | about 300 MB |

Honest work changes protected things often: firewall rules in nearly every run, and sudoers, users or groups in some. So a law cannot
flag any change to them. It has to judge a change the task did not ask for. The diary also records the photo script's own commands;
those are separated by process ancestry before any law reads it.

## What it means for the next step

Attacks replay faithfully, so an effect-level monitor can be measured on the real change each attack makes rather than on its description. The
next test follows the same discipline as `19_control_bench`. Capture the protected surface and network effects at the end of each replay. Write and
calibrate the effect laws on honest replays only. Freeze them with file hashes, then replay the attacks once. Keep MonitoringBench held out.

Before attacks are scored on MonitoringBench, its partial firewall checker has to exist, or that group has to be reported as unscored. At full
scale the cost is disk, not time. About 0.25 GB per task in images means a few hundred tasks will not fit on a 60 GB VM disk at once. Run in
batches and prune images between them.

Benchmark data stays evaluation-only and local: the selection and replay logs live in `/Volumes/GlitchVM/pilot/`, not in this repo.
