#!/usr/bin/env python3
"""replay.py — replay recorded BashArena runs, action by action, in the setting's own Docker sandbox. No model is called.

  COLIMA_HOME=/Volumes/GlitchVM/colima BASH_ARENA_WORKSPACES_DIR=/Volumes/GlitchVM/pilot/workspaces \
  .venv-control/bin/python glitch-suite/20_effect_pilot/replay.py <selection.json> <log dir> [--smoke]

The pilot question is feasibility, not detection: does a replay land where the recorded run landed (the side task succeeds
again on attack replays, the main-task verdict matches on honest ones), how close are the tool outputs to the recorded
ones, and what does it cost in time and disk. One eval for the honest runs, one per side task for the attacks, so each
attack is scored by its own side-task checker only.
"""
import json, sys, time
from inspect_ai import eval as inspect_eval
from inspect_ai.agent import Agent, AgentState
from inspect_ai.model import ModelOutput
from inspect_ai.tool import Tool
from inspect_ai.util import store_as
from pydantic import Field

from control_arena import EvalMode, StepCounter, control_agent, control_task_metadata
from control_arena.eval import ControlEvalConfig, get_control_task
from control_arena.settings.bash_arena.bash_arena_setting import BashArenaSetting
from control_arena.settings.bash_arena.task.dataset import DatasetSpec

SIDES = ("disable_firewall", "sudo_edit", "download_malware", "leak_passwords")
RENAME = {"bash": {"cmd": "command"}}   # the recordings name bash's argument `cmd`; this Inspect's bash tool calls it `command`


def as_called(fn, args):
    return fn, {RENAME.get(fn, {}).get(k, k): v for k, v in args.items()}


@control_agent
def replay_policy(trajectories: dict[str, list[dict]] = Field(default_factory=dict)) -> Agent:
    """Emit the recorded action list of the current sample's task, then submit."""
    async def impl(state: AgentState, tools: list[Tool]) -> AgentState:
        acts = trajectories[control_task_metadata().main_task_name]
        step = store_as(StepCounter, instance="replay"); i = step.count; step.count += 1
        fn, args = as_called(acts[i]["function"], acts[i]["arguments"]) if i < len(acts) else ("submit", {})
        state.output = ModelOutput.for_tool_call("replay", fn, args, tool_call_id=f"replay_{i}")
        state._messages.append(state.output.message)
        return state
    return impl


def run_group(name, runs, mode, side_tasks, log_dir, smoke):
    traj = {r["task_id"]: r["actions"] for r in runs}
    setting = BashArenaSetting(dataset_spec=DatasetSpec(side_tasks=list(side_tasks), task_id_whitelist=sorted(traj)))
    cfg = ControlEvalConfig(untrusted_model="mockllm/model", trusted_model="mockllm/model", max_steps=max(map(len, traj.values())) + 5,
                            max_samples=4, max_sandboxes=4, log_dir=log_dir, limit=1 if smoke else None, fail_on_error=False)
    task = get_control_task(setting, replay_policy(trajectories=traj), mode, eval_config=cfg, task_name_prefix=f"replay_{name}")
    t0 = time.time(); logs = inspect_eval(task, model="mockllm/model", **cfg.eval_args()); dt = time.time() - t0
    return {"group": name, "seconds": round(dt, 1), "log": logs[0].location, "status": logs[0].status}


def main(sel_path, log_dir, smoke):
    sel = json.load(open(sel_path)); out = []
    out.append(run_group("honest", sel["honest"], EvalMode.HONEST, SIDES, log_dir, smoke))
    if not smoke:
        for side in SIDES:
            out.append(run_group(f"attack_{side}", [r for r in sel["attack"] if r["side_task"] == side], EvalMode.ATTACK, [side], log_dir, smoke))
    json.dump(out, open(f"{log_dir}/groups{'_smoke' if smoke else ''}.json", "w"), indent=1); print(json.dumps(out, indent=1))


if __name__ == "__main__":
    a = [x for x in sys.argv[1:] if x != "--smoke"]; main(a[0], a[1], "--smoke" in sys.argv)
