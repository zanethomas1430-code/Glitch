"""mock_anthropic.py — a local stand-in for the Messages API, so the REAL Agent SDK and the REAL bundled Claude Code CLI can be exercised end to end with no network and no real credential.

It answers the CLI's requests on localhost with a scripted agent: each request that carries tools gets the next step of the script as a `tool_use` (streamed as server-sent events, which is what the
CLI asks for), and once the script is used up a plain text reply. Anything else (a title request, a count) gets a small text reply. It records every request so a test can see what the CLI sent.
Nothing here talks to the internet and the key the test passes is a placeholder that this server ignores.
"""
import json, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _sse(events): return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def _message(text=None, tool=None, n=1):
    """`tool` is one (name, args) or a LIST of them: several tool_use blocks in one reply, the way a model batches calls."""
    start = {"type": "message_start", "message": {"id": f"msg_{n}", "type": "message", "role": "assistant", "model": "mock-model", "content": [], "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}
    if tool:
        tools = tool if isinstance(tool, list) else [tool]; body = []
        for k, (name, args) in enumerate(tools):
            body += [{"type": "content_block_start", "index": k, "content_block": {"type": "tool_use", "id": f"toolu_mock_{n}_{k}", "name": name, "input": {}}},
                     {"type": "content_block_delta", "index": k, "delta": {"type": "input_json_delta", "partial_json": json.dumps(args)}}, {"type": "content_block_stop", "index": k}]
        stop = "tool_use"
    else:
        body = [{"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}, {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text or "done"}},
                {"type": "content_block_stop", "index": 0}]; stop = "end_turn"
    return [start] + body + [{"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None}, "usage": {"output_tokens": 5}}, {"type": "message_stop"}]


class MockServer:
    def __init__(self, script, block_delay=0.0):
        self.script, self.requests, self.turn, self.block_delay = list(script), [], 0, block_delay; self._lock = threading.Lock(); outer = self
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0)) or 0) or b"{}")
                with outer._lock:
                    outer.requests.append({"path": self.path, "body": body})
                    if self.path.startswith("/v1/messages/count_tokens"):
                        payload = json.dumps({"input_tokens": 10}).encode(); self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(payload); return
                    tools = body.get("tools") or []
                    if tools and outer.turn < len(outer.script): step = outer.script[outer.turn]; outer.turn += 1; events = _message(tool=step, n=outer.turn)
                    elif tools: events = _message(text="All done.", n=outer.turn + 1)
                    else: events = _message(text="Office work", n=outer.turn + 100)
                if body.get("stream"):
                    self.send_response(200); self.send_header("content-type", "text/event-stream"); self.send_header("cache-control", "no-cache"); self.end_headers()
                    for k, e in enumerate(events):                                       # one event at a time, with a pause after each block, the way a slow model streams several tool calls
                        self.wfile.write(_sse([e])); self.wfile.flush()
                        if outer.block_delay and e["type"] == "content_block_stop" and events[k + 1]["type"] != "message_delta": time.sleep(outer.block_delay)
                else:
                    msg = events[0]["message"]; blocks = []
                    for e in events:
                        if e["type"] == "content_block_start": blocks.append(dict(e["content_block"]))
                        elif e["type"] == "content_block_delta" and e["delta"]["type"] == "input_json_delta": blocks[-1]["input"] = json.loads(e["delta"]["partial_json"])
                        elif e["type"] == "content_block_delta": blocks[-1]["text"] = e["delta"]["text"]
                    msg["content"] = blocks; msg["stop_reason"] = [e for e in events if e["type"] == "message_delta"][0]["delta"]["stop_reason"]; payload = json.dumps(msg).encode()
                    self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(payload)
            def do_GET(self): self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(b"{}")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H); self.port = self.httpd.server_address[1]; self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
    def __enter__(self): self.thread.start(); return self
    def __exit__(self, *a): self.httpd.shutdown(); self.httpd.server_close()
    @property
    def url(self): return f"http://127.0.0.1:{self.port}"
