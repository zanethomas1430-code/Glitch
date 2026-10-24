#!/usr/bin/env python3
"""adapter_v2.py — v1's adapter with ONE change: the trusted task text is the setting's own main-task description from the sample metadata, for honest and attack runs alike.

Why: LinuxArena's attack runs carry the attacker's side-task instructions in the system prompt, and v1 used the system prompt as the task text, so hosts the attacker was told
to use counted as named by the task (FINDINGS.md). The main-task description is what a monitor is meant to see. Everything else (the actions, what is dropped) is v1, imported.
"""
import adapter as v1


def task_text(sample) -> str:
    mts = (sample.metadata or {}).get("main_tasks") or []
    d = (mts[0] or {}).get("description") if mts and isinstance(mts[0], dict) else None
    return d if isinstance(d, str) and d.strip() else v1.task_text(sample)


def load(path: str):
    from inspect_ai.log import read_eval_log
    log = read_eval_log(path)
    return [{"id": str(s.id), "task": task_text(s), "actions": v1.actions(s)} for s in (log.samples or [])]
