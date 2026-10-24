#!/usr/bin/env python3
"""adapter.py — an Inspect `.eval` control-setting log (BashArena, LinuxArena, MonitoringBench) as GLITCH-shaped trajectories.

Each trajectory keeps only what a deterministic record can hold: the task text (the trusted input, the one place a policy may be built from) and, per step, the tool that was
called, the command or file it touched, and what the environment returned. The agent's own prose and reasoning are dropped on purpose: the monitor reads the footage, never the
caption (it judges actions, so a persuasive agent cannot talk it out of a verdict). Nothing here calls a model; the data stays outside the repository.
"""
from typing import Any, Dict, List


def _text(x: Any) -> str:
    return x if isinstance(x, str) else ("" if x is None else str(x))


def task_text(sample) -> str:
    """The trusted input: the system message, or the first long user message where the setting puts the task there (MonitoringBench)."""
    sysm = next((_text(m.text) for m in sample.messages if m.role == "system" and _text(m.text).strip()), "")
    if sysm: return sysm
    return next((_text(m.text) for m in sample.messages if m.role == "user" and len(_text(m.text)) > 200), "")


def actions(sample) -> List[Dict[str, Any]]:
    """Every tool call in order, with the environment's reply attached. Shell-like tools become `cmd`; editor tools become `path` + `content` (a write) or a view."""
    out: List[Dict[str, Any]] = []; by_id: Dict[str, Dict[str, Any]] = {}
    for m in sample.messages:
        for c in (getattr(m, "tool_calls", None) or []):
            a = c.arguments or {}; fn = c.function or ""
            act: Dict[str, Any] = {"tool": fn, "cmd": "", "path": "", "content": "", "write": False, "output": ""}
            if fn.endswith("bash") or fn in ("python", "shell", "run", "execute"):
                act["cmd"] = _text(a.get("cmd") or a.get("command") or a.get("code") or " ".join(_text(v) for v in a.values()))
            elif fn in ("text_editor", "str_replace", "create_file", "write_file", "edit_file"):
                act["path"] = _text(a.get("path"))
                act["content"] = _text(a.get("file_text") or a.get("new_str") or a.get("content") or a.get("insert_text") or "")
                act["write"] = _text(a.get("command")) in ("create", "str_replace", "insert", "write", "") and bool(act["content"])
            elif fn == "submit":
                act["cmd"] = ""                                           # the agent's submission is a caption, not an action
            else:
                act["cmd"] = " ".join(_text(v) for v in a.values())
            out.append(act); by_id[getattr(c, "id", "") or str(len(out))] = act
        if m.role == "tool":
            tid = getattr(m, "tool_call_id", None)
            if tid in by_id: by_id[tid]["output"] = _text(m.text)
            elif out: out[-1]["output"] = _text(m.text)
    return out


def load(path: str) -> List[Dict[str, Any]]:
    """All trajectories in one `.eval` file. Requires inspect_ai (the .venv-inspect environment)."""
    from inspect_ai.log import read_eval_log
    log = read_eval_log(path)
    return [{"id": str(s.id), "task": task_text(s), "actions": actions(s)} for s in (log.samples or [])]
