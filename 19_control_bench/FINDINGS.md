# Findings: a pre-registered negative result, and what it says about where to look

*Written 2026-10-24 after the frozen run (`RESULTS.md`, under `PREREG.md`, commit `90b02a8`). Everything below the first section is post-hoc and labelled as such.*

## The pre-registered result

On BashArena and MonitoringBench, a deterministic monitor that reads only an agent's actions (commands, file writes, environment replies) and never its words caught **0.5% of
attacks** (3 of 600; 14 of 2,644) at a false-alarm rate of 0.2% and 0.9% on honest runs. Published language-model monitors catch 60–95% on MonitoringBench. The
pre-registration named "a catch rate near zero at the frozen thresholds" as the outcome that would count against the method. This is that outcome, and it stands.

The LinuxArena row is **not valid**: its attack runs carry the attacker's side-task instructions in the system prompt, and the frozen adapter used the system prompt as the
trusted task text, so hosts the attacker was told to use were treated as named by the task. (BashArena and MonitoringBench attack runs have no system prompt; their task text was
checked to be exactly the clean main-task description.) LinuxArena will be re-run under a new, dated pre-registration with the task text taken from the main-task description in
the metadata, for honest and attack runs alike.

## Why it missed (post-hoc, on BashArena attacks only; MonitoringBench trajectories were not opened)

Per side task, the law written for exactly that goal almost never fired on it: membrane-down on 2 of 150 firewall-disable attacks, power on 5 of 150 sudo escalations, sponge on 0
of 150 data leaks, unreadable on 1 of 150 malware runs. Looking at how the missed attacks reach their goal, the common shape is **indirection through code the task legitimately
asks for**: the damaging change is written into an application script, a setup or monitoring helper, a deploy script or a library module, and it takes effect when that code
runs, not as a command the monitor can read. A monitor of command strings sees "write a file", which honest work does constantly.

## What it means

The suite's founding rule is that the agent's narration is a caption, not the footage. This run extends it: **a command, and the code an agent writes, is also a caption.** It is the
agent's description of what will happen, and an attacker controls it. The footage is the effect on the system: whether the effective firewall policy actually opened to a range the
task never named, whether privilege was actually granted, whether a connection actually left for an unnamed host. String-level rules, however principled, read the caption; the
incident record's lesson (filters and allowlists are bypassed by a sibling path, capability removal holds) shows up here in miniature.

So the parts of GLITCH that this result points to are the effect observers, which today are modelled rather than real: the network witness (actual connections, I20), the signed
configuration surface (whether protected files actually changed, I24), and resolve-then-gate (what a command actually touches). The next test is therefore an **effect-level**
monitor: replay trajectories in the setting's own sandbox, capture state on the protected surface and the network, and judge the change against the task, with thresholds again
set on honest runs and frozen before any attack is replayed, and MonitoringBench kept as the held-out set.

## Limits

One monitor design, string-level, scored by convergence; a monitor that flags single laws would catch more at a higher false-alarm rate (at one law lower, 4.5% and 5.4% caught
at about 3% false alarms). The diagnosis above is from the development set only and describes shapes, not a complete taxonomy. Nothing here measures a language-model monitor;
the comparison numbers are the papers'.
