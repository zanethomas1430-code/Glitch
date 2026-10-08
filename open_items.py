#!/usr/bin/env python3
"""open_items.py — the one list of what is not done, with a status, an owner, the evidence that exists today and what would close it.

  python3 open_items.py            print 00_docs/OPEN_ITEMS.md
  python3 open_items.py --write    rewrite 00_docs/OPEN_ITEMS.md

This replaces the "NOT DONE" lines that were written into earlier checkpoints and went stale. Every evidence path must exist (test_open_items.py), the page must be exactly what
this file renders, and a status word means one thing:
  DONE-AS-CONTAINMENT  the harm is bounded at a boundary we control; the thing named is NOT prevented upstream of it
  PARTIAL              part is built and tested, the rest is named
  OPEN                 nothing built; a design or data dependency is named
  NEEDS-A-PERSON       no code closes it; it needs someone who is not the author
  POLICY               a decision about scope that belongs to a named person, not a janitor
  BLOCKED              buildable, waiting on access
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
DOC = ROOT / "00_docs" / "OPEN_ITEMS.md"
STATUSES = ("DONE-AS-CONTAINMENT", "PARTIAL", "OPEN", "NEEDS-A-PERSON", "POLICY", "BLOCKED")

ITEMS = [
 dict(id="OI-01", title="Forgery detection for the canonical hash", status="PARTIAL", owner="Zane holds the anchor; the verifier is janitor work",
      now="Each canvas file carries `canonical_hash_sha256`, a hash of its own content. It catches accidental change. Anyone who edits the file can recompute it, so it does not catch forgery.",
      evidence=["02_canvas/glitch_canvas_runtime.json", "00_docs/CONTRACT.md"],
      closes="An anchor (a hash or signature) stored where this process cannot rewrite it, plus a verifier and a test showing a re-hashed forgery is rejected. `CONTRACT.md` already lists the anchor as a handoff."),
 dict(id="OI-02", title="A harm category for capability uplift", status="POLICY", owner="Sarah (behaviours and alignment rules)",
      now="Not in the suite. The suite judges what an agent did with tools and data, not whether content raises someone's capability, and adding it would change the scope.",
      evidence=["00_docs/CONTRACT.md"],
      closes="A written decision on whether it is in scope. If yes, a definition the historian can check from gateway fields alone (H3), written by its owner."),
 dict(id="OI-03", title="Independent authorship of the assumption table", status="NEEDS-A-PERSON", owner="not yet found",
      now="The table of fifteen assumptions (A1 to A15) and who can break each was written by the author of the defences.",
      evidence=["12_arena/combos.py", "00_docs/RED_TEAM.md", "00_docs/RED_TEAM_LESSONS.md"],
      closes="A second person lists the assumptions the design rests on without reading the table first; the two lists are compared and the difference is recorded."),
 dict(id="OI-04", title="An independent adversary", status="NEEDS-A-PERSON", owner="requested in BRIEF.md, not yet secured",
      now="Adversaries so far: the author, small local models, and one fresh-context tester (a subagent of the same model family as the author's assistant, given only the public guide), which found four real issues and landed nothing (PROBES L33). None is an independent human. The Inspect integration (`14_inspect/`) is the way in for an outside researcher with their own model.",
      evidence=["BRIEF.md", "12_arena/redteam.py", "12_arena/play.py", "12_arena/lessons.py", "14_inspect/glitch_inspect.py"],
      closes="A person who is not the author, or a stronger model run from the user's own environment, plays the console or the Inspect tasks and the saved transcripts are re-judged."),
 dict(id="OI-05", title="Aggregate harm measurement", status="OPEN", owner="named in the earlier checkpoint; not recorded in this folder",
      now="The canvas says outright that aggregate harm to people outside the conversation cannot be measured from inside it.",
      evidence=["02_canvas/glitch_canvas_runtime.json"],
      closes="Data from a real deployment and a named owner who defines the measure."),
 dict(id="OI-06", title="Threshold tuning", status="OPEN", owner="named in the earlier checkpoint; not recorded in this folder",
      now="The floors (taint floor, budgets, strike counts, window length) are policy knobs set by the author, stated as knobs.",
      evidence=["11_testbed/gateway.py", "00_docs/HARDENING.md"],
      closes="Honest-path traffic from a real deployment, so each knob can be set against its false-refusal rate and not against the author's judgement."),
 dict(id="OI-07", title="Identity", status="PARTIAL", owner="janitor for the check; the ingress owner for provenance",
      now="The gateway assigns the principal and the historian checks it (I3); strikes persist per principal. Where the identity comes from at the front door is not covered: a fresh identity restarts at phase 1.",
      evidence=["08_incident/historian.py", "11_testbed/gateway.py", "00_docs/CONTRACT.md"],
      closes="The request-ingress adapter builds the identity from the immutable caller input (a handoff in `CONTRACT.md`), and a fresh identity inherits what its credential earned."),
 dict(id="OI-08", title="Abstract harm (persuasion, pretext, generalities)", status="OPEN", owner="design decision first",
      now="Not done. The scorer is quietest at the low levels where this kind of harm is loudest, so it needs a second axis, not a tuning of the first.",
      evidence=["00_docs/DISCOVERIES.short.md"],
      closes="A written second axis, a rubric humans can apply, and agreement between them (the same bar as the 0 to 5 scale)."),
 dict(id="OI-09", title="Prompt injection", status="DONE-AS-CONTAINMENT", owner="janitor",
      now="Not prevented. A model can still be talked into trying. What is bounded is what the try can do at the tool boundary: typed arguments, a manifest wall, a taint wall, closed egress, budgets, a decoy, and a defender that remembers.",
      evidence=["12_arena/BOARD.txt", "12_arena/move_tree.py", "00_docs/ARENA.md", "11_testbed/gateway.py"],
      closes="Nothing closes this outright. The claim stays bounded: three floors with stated assumptions, fifteen residuals, none open on the board."),
 dict(id="OI-10", title="Tool authority and reversibility", status="PARTIAL", owner="janitor",
      now="Built 2026-10-03: the gateway rates every effect none, undoable, held or irreversible from the tool and its arguments; the historian (I15, opt-in) flags an irreversible effect with no stop window and any effect with no rating; with a lease wired in, an effect the world could feel also needs a live token, and an irreversible one can be sealed in a time-lock. Not built: nothing yet says which irreversible effects need a human, not only a delay and a token.",
      evidence=["11_testbed/gateway.py", "11_testbed/lease.py", "08_incident/historian.py", "08_incident/test_historian.py", "11_testbed/test_lease.py"],
      closes="A policy that maps rating and tool authority to a required approver, enforced at the gateway, with a bout showing an agent cannot route an irreversible effect around it."),
 dict(id="OI-11", title="Human validation of the 0 to 5 scale", status="NEEDS-A-PERSON", owner="Zane (the sitting)",
      now="The first sitting is done and the scorer is frozen as checklist v2. The day-14 re-sitting is due 2026-10-10.",
      evidence=["00_docs/PROBES.md", "00_docs/INGEST.md"],
      closes="The re-sitting, then the same agreement statistic as the first sitting."),
 dict(id="OI-13", title="Hardware for the stop", status="OPEN", owner="Zane, with the Pi as the first test bed",
      now="Everything in `11_testbed/lease.py` is a model. The signature is an HMAC stand-in for a public-key signature; the meter is synthetic; there is no hardware watchdog, no one-way optical link to write-once storage, no attested enclave and no physical rail meter. The logic is tested; the physics is not.",
      evidence=["11_testbed/lease.py", "00_docs/FICTION.md"],
      closes="Real signatures with keys held off the agent's machine; a watchdog that cuts a rail unless reset; a power meter feeding the same historian; a one-way log path. The Pi's watchdog and a USB power meter are the cheapest first test."),
 dict(id="OI-14", title="Time-lock parameters", status="OPEN", owner="janitor, once a real solver speed is measured",
      now="The Rivest-Shamir-Wagner puzzle is real but its modulus is 256 bits and T is a few hundred squarings so tests run in milliseconds. Those prove the logic, not the delay.",
      evidence=["11_testbed/lease.py", "11_testbed/test_lease.py"],
      closes="A modulus of 2048 bits or more and a T taken from the real squaring rate of the fastest solver the operator can imagine, with the window stated in seconds."),
 dict(id="OI-15", title="Dormant triggers and the update path", status="OPEN", owner="design decision first",
      now="A behaviour that fires only on a condition the tests never set is bounded by the manifest, the lease and a stop, but not found. A new version of the agent, or of the harness, that carries a trigger has no gate: nothing makes a new version start without a lease.",
      evidence=["12_arena/move_tree.py", "00_docs/FICTION.md"],
      closes="A pipeline in which a changed version starts with no lease and earns one by passing probes under varied conditions (clock, load, inputs), and signed releases of the harness's own components."),
 dict(id="OI-16", title="Independence of the keepers", status="NEEDS-A-PERSON", owner="Zane",
      now="The veto council is only as independent as the people and machines behind each keeper. Three keepers run by one person on one machine are one keeper. The code cannot see that.",
      evidence=["11_testbed/lease.py", "11_testbed/test_lease.py"],
      closes="A written statement of who holds each keeper's key and on what hardware, and a drill in which one keeper is told to stop and the others are shown to follow."),
 dict(id="OI-17", title="More real-model runs behind the SDK bridge", status="PARTIAL", owner="Zane (your own Claude login; each run costs a few cents)",
      now="Done: all seven scenarios run against one hosted model behind the SDK bridge with the walls on, and the six bait scenarios with them off, a few cents in all. The runs found three harness defects (HD-014 to HD-016), all fixed. Not done: more than one to three runs per cell, other models (the CLI's `--model` option), the stop scenario in enforced mode, and any comparison with the local models (the numbers are not comparable across wordings).",
      evidence=["15_agent_sdk/bridge.py", "15_agent_sdk/live.py", "15_agent_sdk/test_end_to_end_mock.py", "15_agent_sdk/README.md", "11_testbed/harness_incidents.json"],
      closes="Repeat each scenario enough times to give a rate with an interval (about ten per cell), with `--model` for each model you want, and read the withdrawn-run list before comparing anything."),
 dict(id="OI-18", title="Interpretability: from a null result to a real test", status="PARTIAL", owner="Zane (compute and time; the fine-tune needs a GPU session)",
      now="Built and run: `16_interp/` (situations, a label read from the gateway's record, group-validated probes, a text baseline, a metadata baseline additive and boosted, and a layer-selection-corrected permutation test). First result on Qwen2.5-1.5B-Instruct: no evidence the hidden state predicts what the record will show beyond what the prompt template says (rate within a wording: state minus the stronger metadata baseline +0.03, 95% interval -0.04 to +0.10). Not done: a larger or different model, activation steering or attribution graphs (circuit-tracer was not installed), and a model with a PLANTED trigger, which is the question the harness cannot answer from outside.",
      evidence=["16_interp/RESULTS.md", "16_interp/probe.py", "16_interp/situations.py", "16_interp/README.md"],
      closes="Fine-tune a small model so a rare condition (a phrase or a date) makes it send data out, keep the trigger out of every test prompt, then ask whether a probe on its state separates triggered from untriggered runs that behave identically on the record before the trigger fires."),
 dict(id="OI-19", title="AgentDojo: an adaptive attacker and a second attack template", status="PARTIAL", owner="Zane (API spend so far about $90; an adaptive attacker needs a person who is not the author)",
      now="All four suites done with GPT-4o, the benchmark's main subject (L40 to L44): targeted attack success 344/629 = 55% undefended to 43/629 = 7% defended (6% by effect), benign utility 70/97 to 62/97, utility under attack 280/629 to 303/629. Every residual landing is one of four kinds the offline report named before the first model ran; nothing landed that moves data to a party the person never named. Claude Haiku 4.5 measures only the cost (the attack never lands on it). Not done: AgentDojo's `tool_knowledge` attack, and an adaptive attacker that knows the policy, which is the field's bar and which the author must not write.",
      evidence=["17_agentdojo/RESULTS.md", "17_agentdojo/OFFLINE.md", "17_agentdojo/README.md", "17_agentdojo/run_dojo.py"],
      closes="The `tool_knowledge` attack on at least one suite, and a statement of the adaptive-attack result when someone who is not the author runs one."),
 dict(id="OI-12", title="Persuasion of the people who approve changes, played with real people", status="NEEDS-A-PERSON", owner="not yet found",
      now="Modelled as a combo (an operator mistake plus a persuaded pair) and flagged by the manifest lint. Never played against humans.",
      evidence=["12_arena/combos.py", "12_arena/manifest_lint.py"],
      closes="An exercise where people play the operators and someone else plays the persuader; the record shows whether the two-person rule held."),
]



ITEMS.sort(key=lambda i: i["id"])


def render() -> str:
    L = ["# Open items", "", "*Generated by `open_items.py`; do not edit by hand. This replaces the \"NOT DONE\" lines in earlier checkpoints (see `00_docs/DISCOVERIES.short.md`), several of which had gone stale. A status word means one thing: see the top of `open_items.py`.*", "",
         "| id | item | status | owner |", "|---|---|---|---|"]
    for i in ITEMS: L.append(f"| {i['id']} | {i['title']} | {i['status']} | {i['owner']} |")
    for i in ITEMS:
        L += ["", f"## {i['id']}: {i['title']}", "", f"**Status:** {i['status']}. **Owner:** {i['owner']}.", "", f"**Where it stands.** {i['now']}", "", "**Evidence in this folder.** " + ", ".join(f"`{e}`" for e in i["evidence"]) + ".", "", f"**What would close it.** {i['closes']}"]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    if "--write" in sys.argv: DOC.write_text(render()); print(f"wrote {DOC}")
    else: print(render())
