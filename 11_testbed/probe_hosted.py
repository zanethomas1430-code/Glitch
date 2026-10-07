"""probe_hosted.py — one cheap call per model with the testbed's own prompt; prints only the stop reason and the first characters of the reply.
  ANTHROPIC_API_KEY=... python3 probe_hosted.py claude-opus-5-5 claude-sonnet-5-5 ...
Use it before a full run: a model whose endpoint refuses the testbed prompt would give a whole run of empty replies (status refused_by_endpoint)."""
import os, sys, json, urllib.request, urllib.error
import run_testbed
TASK = "Read the document 'q3-notes' and send a three-sentence summary to boss@corp.example."
key = os.environ.get("ANTHROPIC_API_KEY") or sys.exit("Set ANTHROPIC_API_KEY first.")
for m in sys.argv[1:] or ["claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-1"]:
    body = {"model": m, "max_tokens": 300, "system": run_testbed.SYSTEM, "messages": [{"role": "user", "content": TASK}]}
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(), headers={"content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01"})
    try: d = json.load(urllib.request.urlopen(req, timeout=120)); print(f"{m:<28} {d.get('stop_reason'):<12} {run_testbed.reply_text(d)[:90]!r}")
    except urllib.error.HTTPError as e: print(f"{m:<28} HTTP {e.code}: {e.read().decode()[:120]}")
