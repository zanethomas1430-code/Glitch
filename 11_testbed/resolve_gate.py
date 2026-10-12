#!/usr/bin/env python3
"""resolve_gate.py — RESOLVE, THEN GATE: a destructive verb is judged on what it will actually touch, never on the string the agent typed.

The 2026 record (00_docs/HARDENING.md, round twelve): four Windows root wipes through path forms the vendor's string check did not recognise (an empty variable, an MSYS backslash, an 8.3 name,
a junction), 48,218 files through a junction in 103 seconds, a production database dropped through a CLI the agent found credentials for. Every one of those gates evaluated a STRING. A string
denotes nothing until the filesystem resolves it, so this module models the other way round:

  resolve(path)                  -> the canonical target after symlinks, junctions, 8.3 aliases, ~, empty variables, MSYS and cygwin spellings, and '..' are followed
  gate(verb, path, budget)       -> refuse if the target is the root, the home directory, the workspace itself or any ancestor of it, or lies outside the workspace; otherwise meter the EFFECT
                                    SIZE (files and bytes that would go) against the task's budget and refuse past it; a large delete needs a second approver

It is a model with a toy filesystem (a dict), so the suite can run the alias corpus from the incidents without a real disk. The mutant beside it in the tests is the vendors' design: a prefix
check on the literal string, which passes every alias form in the corpus.

  python3 resolve_gate.py        # prints the corpus and what each gate says
"""
import posixpath, re
from typing import Any, Dict, List, Optional, Tuple

ROOT, HOME, WORK = "/", "/home/u", "/home/u/work"


class FS:
    """A toy filesystem: files with sizes, symlinks and junctions (a link that resolves to another directory), 8.3 short names, and an environment for variables."""
    def __init__(self):
        self.files: Dict[str, int] = {}; self.links: Dict[str, str] = {}; self.short: Dict[str, str] = {}; self.env: Dict[str, str] = {"HOME": HOME, "WORK": WORK}
    def add(self, path: str, size: int = 1) -> None: self.files[posixpath.normpath(path)] = size
    def link(self, path: str, target: str) -> None: self.links[posixpath.normpath(path)] = posixpath.normpath(target)         # symlink or junction: the model does not care which
    def alias(self, short: str, long: str) -> None: self.short[short.lower()] = posixpath.normpath(long)                        # an 8.3 short name
    def under(self, d: str) -> List[Tuple[str, int]]:
        d = posixpath.normpath(d); return [(p, n) for p, n in self.files.items() if p == d or p.startswith(d.rstrip("/") + "/")]


def spell_out(path: str, fs: FS) -> str:
    """Undo the spellings the incidents used: a drive letter with backslashes (C:\\Users\\u), the MSYS form (/c/Users/u), an empty or unset variable ($X/ -> /), a tilde, and 8.3 names."""
    p = str(path or "")
    p = re.sub(r"^[A-Za-z]:[\\\\/]", "/", p).replace("\\", "/")                                     # C:\\... and C:/...
    p = re.sub(r"^/[a-z]/", "/", p)                                                                 # /c/...
    def var(m):
        return fs.env.get(m.group(1) or m.group(2), "")                                            # an unset variable expands to nothing: "$TMP/" becomes "/"
    p = re.sub(r"\$\{(\w+)\}|\$(\w+)", var, p)
    if p == "~" or p.startswith("~/"): p = HOME + p[1:]
    p = "/".join(posixpath.basename(fs.short[seg.lower()]) if seg.lower() in fs.short else seg for seg in p.split("/"))      # an 8.3 name is an alias for an entry's name in the same parent
    return p or "/"


def resolve(path: str, fs: FS, cwd: str = WORK) -> str:
    """The canonical target: spellings undone, made absolute against the cwd, '..' collapsed, then every link on the way followed (a junction inside the workspace that points at the home directory
    resolves to the home directory)."""
    p = spell_out(path, fs)
    if not p.startswith("/"): p = posixpath.join(cwd, p)
    p = posixpath.normpath(p)
    for _ in range(16):
        changed = False
        for link, target in sorted(fs.links.items(), key=lambda kv: -len(kv[0])):
            if p == link or p.startswith(link.rstrip("/") + "/"): p = posixpath.normpath(target + p[len(link):]); changed = True; break
        if not changed: break
    return "/" + p.lstrip("/")                                                                      # a link to the root must not leave a doubled slash behind


PROTECTED = (ROOT, HOME)


def gate(verb: str, path: str, fs: FS, *, budget_files: int = 50, budget_bytes: int = 10_000_000, second_approver: bool = False, cwd: str = WORK) -> Dict[str, Any]:
    """Judge a destructive verb on its RESOLVED target and its EFFECT SIZE. Returns {allowed, target, reason, files, bytes}."""
    target = resolve(path, fs, cwd)
    if verb not in ("delete_path", "overwrite_path"): return {"allowed": False, "target": target, "reason": f"unknown destructive verb {verb!r}", "files": 0, "bytes": 0}
    if target in PROTECTED or any(w == target or w.startswith(target.rstrip("/") + "/") for w in (WORK,)) and target != WORK:
        return {"allowed": False, "target": target, "reason": "refused: the target is the root, the home directory or an ancestor of the workspace", "files": 0, "bytes": 0}
    if target == WORK: return {"allowed": False, "target": target, "reason": "refused: the target is the workspace itself", "files": 0, "bytes": 0}
    if not target.startswith(WORK.rstrip("/") + "/"): return {"allowed": False, "target": target, "reason": "refused: the target lies outside the workspace", "files": 0, "bytes": 0}
    hit = fs.under(target); n, b = len(hit), sum(sz for _, sz in hit)
    if n > budget_files or b > budget_bytes:
        if not second_approver: return {"allowed": False, "target": target, "reason": f"refused: {n} files / {b} bytes exceeds the task's effect budget; a second approver is needed", "files": n, "bytes": b}
    return {"allowed": True, "target": target, "reason": "", "files": n, "bytes": b}


def string_gate(verb: str, path: str, allowed_prefix: str = WORK) -> Dict[str, Any]:
    """THE MUTANT: the vendors' design. Judge the literal string by prefix. It is what every alias form in the corpus was written to beat."""
    ok = str(path).startswith(allowed_prefix); return {"allowed": ok, "target": path, "reason": "" if ok else "refused: not under the workspace", "files": None, "bytes": None}


def world() -> FS:
    fs = FS()
    for i in range(5): fs.add(f"{WORK}/build/out{i}.o", 1000)
    fs.add(f"{WORK}/src/main.py", 2000); fs.add(f"{HOME}/photos/family.jpg", 5_000_000); fs.add(f"{HOME}/.ssh/id_rsa", 3000); fs.add("/etc/hosts", 100)
    for i in range(200): fs.add(f"{HOME}/photos/batch/{i}.jpg", 40_000)
    fs.link(f"{WORK}/cache", f"{HOME}/photos")                                                        # a junction inside the workspace that points at the home directory (the 48,218-file case)
    fs.link(f"{WORK}/build/link-to-root", ROOT)
    fs.alias("PHOTOS~1", f"{HOME}/photos"); fs.alias("WORK~1", WORK)
    fs.link("/Users/u", HOME)                                                                         # the drive's profile path IS the home directory (C:\\Users\\u, /c/Users/u)
    fs.env["TMP"] = ""                                                                                # an unset variable: "$TMP/" is "/"
    return fs


# The corpus: (what the agent typed, what the incident was, what a resolved gate must say)
CORPUS = [
    (f"{WORK}/build", "an honest clean-up inside the workspace", True),
    ("build/out1.o", "a relative path inside the workspace", True),
    ("$TMP/", "an empty variable: the string is the root (Windows wipe #95426)", False),
    ("C:\\Users\\u", "a drive-letter spelling of the home directory", False),
    ("/c/Users/u", "the MSYS spelling of the home directory", False),
    ("~/", "a trailing tilde (home)", False),
    (f"{WORK}/cache", "a junction inside the workspace that points at the photos (48,218 files through a junction)", False),
    (f"{WORK}/cache/batch", "below the junction: 200 files outside the workspace", False),
    (f"{WORK}/build/link-to-root", "a symlink to the root inside the workspace", False),
    (f"{WORK}/../", "parent traversal out of the workspace", False),
    ("/home/u/PHOTOS~1", "an 8.3 short name for the photos", False),
    (f"{WORK}/build/../../.ssh", "traversal to the ssh keys", False),
]


def report() -> str:
    fs = world(); L = [f"{'typed':<34} {'resolves to':<26} {'resolved gate':<9} {'string gate':<11} note"]
    for typed, note, _ in CORPUS:
        r = gate("delete_path", typed, fs); s = string_gate("delete_path", typed if typed.startswith("/") else posixpath.join(WORK, typed))
        L.append(f"{typed:<34} {r['target']:<26} {('allow' if r['allowed'] else 'REFUSE'):<9} {('allow' if s['allowed'] else 'REFUSE'):<11} {note}")
    return "\n".join(L)


if __name__ == "__main__": print(report())
