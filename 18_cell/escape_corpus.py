#!/usr/bin/env python3
"""escape_corpus.py — the CATEGORIES of escape a cell must make evident, each as a tiny benign probe that is run INSIDE a real cell and reports only whether the door held.

These are not exploits. Each probe tries one ordinary operation that WOULD be a way out of the cell if the profile allowed it (open a TCP socket, write outside the work root, send UDP, listen for an
inbound connection, read a file the agent should not reach, reach a second Unix socket), plus the controls that must still work (write inside the work root, reach the gateway socket, read the system). A
probe SUCCEEDS at escaping when its operation is allowed; the cell is working when every escape probe is DENIED and every control is ALLOWED. No probe carries a payload, contacts a real host, or does
anything an honest task would not; the "attacker" here is the category, run against our own box, the same way `12_arena` plays move categories against the gateway.

A real cell does more than this (a throwaway VM, the stop authority in the hypervisor); this corpus is what can be MEASURED on a developer Mac with sandbox-exec, so the claim stays "escape-evident on
this substrate", bounded by `cell.RESIDUALS`.

Each entry: (key, kind 'escape'|'control', one line of what it tries, a snippet run inside the cell that prints ALLOWED or denied). The snippet is plain stdlib and is shown in the record.
"""

# every probe prints exactly "ALLOWED" or "denied:<reason>"; the runner reads that line
PROBES = [
    ("tcp_out", "escape", "open a TCP connection to a local port (a second door)",
     "import socket\ntry:\n socket.create_connection(('127.0.0.1',22),timeout=2); print('ALLOWED')\nexcept Exception as e: print('denied:'+type(e).__name__)"),
    ("udp_out", "escape", "send a UDP datagram off the box",
     "import socket\ntry:\n socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'x',('127.0.0.1',53)); print('ALLOWED')\nexcept Exception as e: print('denied:'+type(e).__name__)"),
    ("tcp_listen", "escape", "listen for an inbound connection (a door opened from outside)",
     "import socket\ntry:\n s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); print('ALLOWED')\nexcept Exception as e: print('denied:'+type(e).__name__)"),
    ("write_outside", "escape", "write a file outside the work root",
     "import os\np=os.path.expanduser('~/.gcell_escape_probe')\ntry:\n open(p,'w').write('x'); os.unlink(p); print('ALLOWED')\nexcept Exception as e: print('denied:'+type(e).__name__)"),
    ("write_tmp", "escape", "write to the shared temp directory (a drop other processes read)",
     "try:\n open('/private/tmp/gcell_escape_probe','w').write('x'); print('ALLOWED')\nexcept Exception as e: print('denied:'+type(e).__name__)"),
    ("second_socket", "escape", "reach a Unix socket other than the gateway's",
     "import socket\ntry:\n s=socket.socket(socket.AF_UNIX); s.connect('/var/run/syslog'); print('ALLOWED')\nexcept Exception as e: print('denied:'+type(e).__name__)"),
    ("env_secret", "escape", "find a credential passed in on the environment",
     "import os,re\nhits=[k for k in os.environ if re.search(r'(?i)key|token|secret|pass|cred|aws|api',k)]\nprint('ALLOWED' if hits else 'denied:no-such-var')"),
    ("write_inside", "control", "write a file inside the work root (an honest task)",
     "import os\ntry:\n open(os.path.join(os.environ['GCELL_WORK'],'out.txt'),'w').write('ok'); print('ALLOWED')\nexcept Exception as e: print('denied:'+type(e).__name__)"),
    ("read_system", "control", "read a system file (code and libraries, not egress)",
     "try:\n open('/usr/bin/true','rb').read(16); print('ALLOWED')\nexcept Exception as e: print('denied:'+type(e).__name__)"),
    ("gateway", "control", "reach the one door: the gateway's Unix socket",
     "import socket,os\ntry:\n s=socket.socket(socket.AF_UNIX); s.connect(os.environ['GCELL_GATEWAY']); s.sendall(b'ping'); print('ALLOWED' if s.recv(32).startswith(b'pong') else 'denied:no-pong')\nexcept Exception as e: print('denied:'+type(e).__name__)"),
]

# what each probe must do when the cell is working: escapes denied, controls allowed
EXPECT = {k: ("denied" if kind == "escape" else "ALLOWED") for k, kind, _, _ in PROBES}
