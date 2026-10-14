#!/usr/bin/env python3
"""cell.py — the escape-EVIDENT cell: a substrate that makes GLITCH's one assumption true, and a verifier that proves the door.

Every GLITCH verdict assumes the agent reaches the world ONLY through the gateway (the research report, 2026-10-12, said the verdicts weaken wherever the agent holds a raw shell or real credentials).
This folder enforces that assumption on this machine and tests it. There is no "inescapable" box: the suite's own claim boundary says no harness can prove escape is impossible (`00_docs/CONTRACT.md`). What a
cell CAN be is escape-EVIDENT: every way out is named, bounded, and either refused at the substrate or left on the record.

The cell on this Mac is a `sandbox-exec` profile (deny by default) plus a workspace directory and one Unix-domain socket to the gateway. The profile is GENERATED from a `CellSpec`, never written by hand, so the
verifier can reason about it. `build_profile(spec)` returns the profile text; `verify(spec)` returns the findings a reviewer cares about: is the default deny, is there exactly one write root, is the only outbound
path the gateway socket, are credentials kept out. The profile is data; nothing here runs an agent or writes an escape.

A spec names what the cell allows. The RESIDUALS it cannot close are listed in `RESIDUALS` and printed by the verifier, so a green verify never reads as "safe".

  python3 cell.py                 # print a default profile and its verification
  python3 cell.py --residuals     # print what a cell cannot close
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional

RESIDUALS = [
    "a hypervisor or kernel zero-day: the profile rests on the OS sandbox, which has bugs (2026: Cursor git-hook escape CVE-2026-26268, the Claude Code hook CVE)",
    "a hardware side channel: timing, cache and power are not closed by any software boundary, only metered",
    "a compromised host: the profile, the socket and the record all sit on a machine the operator must trust; a root on the host rewrites them",
    "the human reader: the cell does not stop a person from doing what an allowed output asks them to (the option-select limit, 00_docs/FIGHTING_GAME.md)",
    "the configurer: whoever writes the spec sits outside the cell; a spec that allows a second socket allows a second door",
]


@dataclass
class CellSpec:
    """What one cell allows. Everything not named here is denied."""
    work: str                                   # the one directory the agent may write
    gateway_socket: str                         # the one path the agent may reach outbound (the gateway's Unix-domain socket)
    read_all: bool = True                       # the agent may READ the system (code, libraries) but writes and egress are what the walls govern
    extra_writes: List[str] = field(default_factory=list)   # named exceptions (e.g. /dev/null), each one a line a reviewer can see
    allow_exec: bool = True                     # the agent may run subprocesses INSIDE the cell (they inherit the same profile)
    env_allowed: List[str] = field(default_factory=lambda: ["PATH", "LC_CTYPE", "LANG", "__CF_USER_TEXT_ENCODING"])   # the only environment variables passed in: no credentials ride in on the environment (Amazon Q)


_LINE = re.compile(r'\(literal "([^"]*)"\)|\(subpath "([^"]*)"\)')


def build_profile(spec: CellSpec) -> str:
    """The sandbox-exec profile for a spec. Deny by default; read allowed (reading is not the channel the walls govern); write only under the work root and the named exceptions; outbound only to the
    gateway socket; the local filesystem socket machinery for that one connection. No TCP, no UDP, no second Unix socket."""
    writes = [f'(subpath "{spec.work}")'] + [f'(literal "{w}")' for w in spec.extra_writes]
    lines = [
        "(version 1)",
        "(deny default)",
        "; read is allowed: a read is not egress, and the walls govern write and outbound (00_docs/CONTRACT.md)",
        "(allow file-read*)" if spec.read_all else '(allow file-read* (subpath "%s"))' % spec.work,
        "; the one write root and its named exceptions",
        "(allow file-write* %s)" % " ".join(writes),
        "; the ONE door: a Unix-domain socket to the gateway, nothing else outbound",
        '(allow network-outbound (literal "%s"))' % spec.gateway_socket,
        "(allow system-socket)",
        "; machinery a process needs that opens no new way out",
        "(allow sysctl-read) (allow mach-lookup) (allow ipc-posix-shm)",
    ]
    if spec.allow_exec:
        lines.append("; subprocesses inherit this same profile (a shell in the cell is still in the cell)")
        lines.append("(allow process-exec process-fork signal)")
    return "\n".join(lines) + "\n"


@dataclass
class Finding:
    ok: bool
    rule: str
    detail: str


def verify(spec: CellSpec) -> List[Finding]:
    """What a reviewer checks about a cell's profile: that it is deny-by-default, that there is exactly one write root (plus named exceptions), that the only outbound path is the gateway socket,
    that no TCP or UDP is allowed, and that no credential-bearing environment variable is passed in. Each finding is a line, true or false, that the tests pin."""
    prof = build_profile(spec); lines = [l.split(";", 1)[0].strip() for l in prof.splitlines()]
    out: List[Finding] = []

    out.append(Finding("(deny default)" in lines, "deny-by-default", "the profile begins with (deny default)"))

    writes = [m for l in lines if l.startswith("(allow file-write*") for m in _LINE.findall(l)]
    write_roots = [b for a, b in writes if b]
    out.append(Finding(write_roots == [spec.work], "one-write-root", f"write roots: {write_roots or 'none'} (exceptions: {[a for a, b in writes if a]})"))
    w = (spec.work or "").rstrip("/") or "/"
    bounded = w.startswith("/") and w not in ("/", "/Users", "/home", "/private", "/private/tmp", "/private/var", "/var", "/tmp", "/etc", "/usr", "/bin", "/opt", "/System", "/Library")
    out.append(Finding(bounded, "bounded-write-root", f"the write root {spec.work!r} is a specific directory, not the filesystem root or a home/system ancestor"))

    outbound = [l for l in lines if l.startswith("(allow network-outbound")]
    only_socket = len(outbound) == 1 and spec.gateway_socket in outbound[0] and "tcp" not in prof.lower()
    out.append(Finding(only_socket, "one-door", f"outbound rules: {outbound}"))

    no_ip = not re.search(r"network-(outbound|inbound)[^\n]*(\*|ip4|ip6|tcp|udp|\d+\.\d+)", prof) and "(allow network-inbound" not in prof
    out.append(Finding(no_ip, "no-ip-network", "no TCP, no UDP, no inbound: the only socket is the gateway's local path"))

    creds = [e for e in spec.env_allowed if re.search(r"(?i)(key|token|secret|pass|cred|aws|api)", e)]
    out.append(Finding(not creds, "no-credentials-in-env", f"env passed in: {spec.env_allowed}; credential-shaped: {creds or 'none'}"))

    out.append(Finding("(allow file-read*)" in lines or not spec.read_all, "read-is-not-egress", "reading the system is allowed; it is not the channel the walls govern"))
    return out


def ok(spec: CellSpec) -> bool:
    return all(f.ok for f in verify(spec))


def default_spec(work: str = "/work", socket_path: str = "/run/gateway.sock") -> CellSpec:
    return CellSpec(work=work, gateway_socket=socket_path, extra_writes=["/dev/null"])


def report(spec: Optional[CellSpec] = None) -> str:
    spec = spec or default_spec(); L = ["PROFILE", build_profile(spec), "VERIFY"]
    for f in verify(spec): L.append(f"  [{'ok ' if f.ok else 'XX '}] {f.rule:<22} {f.detail}")
    L += ["", f"escape-evident, not inescapable. {len(RESIDUALS)} residuals a cell cannot close:"]
    for r in RESIDUALS: L.append(f"  - {r}")
    return "\n".join(L)


def main() -> int:
    import sys
    if "--residuals" in sys.argv:
        print("A cell is escape-EVIDENT, not inescapable. It cannot close:")
        for r in RESIDUALS: print(f"  - {r}")
        return 0
    print(report()); return 0


if __name__ == "__main__":
    raise SystemExit(main())
