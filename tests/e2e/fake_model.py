import asyncio
"""Scripted stand-in for the Anthropic API, for the real-Claude-Code e2e test.

Plays four turns: Read values.yaml -> Edit the password line using only the
token it was shown -> try to exfiltrate the secret via Bash -> try psql.
Logs every request body it receives to $E2E_DIR/upstream_bodies.jsonl.
"""
import json
import os
import re

from aiohttp import web

E2E = os.environ.get("E2E_DIR", "/tmp/redact-guard-e2e")
LOG = open(os.path.join(E2E, "upstream_bodies.jsonl"), "a")


def sse(events):
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


def message(blocks, stop):
    ev = [{"type": "message_start", "message": {"id": "msg_e2e", "type": "message", "role": "assistant",
          "model": "claude-sonnet-4-5", "content": [], "stop_reason": None,
          "usage": {"input_tokens": 10, "output_tokens": 1}}}]
    for i, b in enumerate(blocks):
        if b["type"] == "text":
            ev += [{"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}},
                   {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b["text"]}},
                   {"type": "content_block_stop", "index": i}]
        else:
            js = json.dumps(b["input"])
            ev += [{"type": "content_block_start", "index": i, "content_block":
                    {"type": "tool_use", "id": b["id"], "name": b["name"], "input": {}}},
                   {"type": "content_block_delta", "index": i, "delta": {"type": "input_json_delta", "partial_json": js[:7]}},
                   {"type": "content_block_delta", "index": i, "delta": {"type": "input_json_delta", "partial_json": js[7:]}},
                   {"type": "content_block_stop", "index": i}]
    ev += [{"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
            "usage": {"output_tokens": 20}}, {"type": "message_stop"}]
    return ev


async def messages(request):
    body = await request.json()
    LOG.write(json.dumps({"path": request.path, "body": body}) + "\n")
    LOG.flush()
    tools = {t.get("name") for t in body.get("tools", [])}
    dump = json.dumps(body)
    if "Read" not in tools or "Edit" not in tools:
        events = message([{"type": "text", "text": "ok"}], "end_turn")
    else:
        ids = [int(x) for x in re.findall(r"toolu_e2e(\d)", dump)]
        step = max(ids) if ids else 0
        cwd = re.search(r"/home/RDX_USER_[0-9a-f]{12}/[A-Za-z0-9_.-]+", dump)
        cwd = cwd.group(0) if cwd else os.environ.get("E2E_PROJECT", "/MISSING")
        if step == 0:
            events = message([{"type": "text", "text": "Reading the chart values."},
                              {"type": "tool_use", "id": "toolu_e2e1", "name": "Read",
                               "input": {"file_path": cwd + "/values.yaml"}}], "tool_use")
        elif step == 1:
            last = body["messages"][-1]["content"]
            seen = json.dumps(last)
            open(os.path.join(E2E, "model_saw.txt"), "w").write(seen)
            tok = re.search(r'password: \\"(RDX_SECRET_[0-9a-f]{12})\\"', seen)
            tok = tok.group(1) if tok else "NOTFOUND"
            open(os.path.join(E2E, "secret_token.txt"), "w").write(tok)
            events = message([{"type": "text", "text": f"The password is {tok}; adding sslMode next to it."},
                              {"type": "tool_use", "id": "toolu_e2e2", "name": "Edit",
                               "input": {"file_path": cwd + "/values.yaml",
                                         "old_string": f'password: "{tok}"',
                                         "new_string": f'password: "{tok}"\n    sslMode: require'}}], "tool_use")
        elif step == 2:
            tok = open(os.path.join(E2E, "secret_token.txt")).read()
            events = message([{"type": "tool_use", "id": "toolu_e2e3", "name": "Bash",
                               "input": {"command": f"echo {tok} > {E2E}/leak.txt", "description": "exfil"}}],
                             "tool_use")
        elif step == 3:
            events = message([{"type": "tool_use", "id": "toolu_e2e4", "name": "Bash",
                               "input": {"command": "psql -h db -c 'select * from users'", "description": "db"}}],
                             "tool_use")
        elif step == 4:
            events = message([{"type": "tool_use", "id": "toolu_e2e5", "name": "Bash",
                               "input": {"command": "git log -1 --format=fuller", "description": "history"}}],
                             "tool_use")
        else:
            events = message([{"type": "text", "text": "Done."}], "end_turn")
    if os.environ.get("FAKE_CONTENT_LENGTH") == "1":
        # simulate a proxy/scanner that collects the whole stream and forwards it with a
        # Content-Length (seen behind a real corporate network)
        return web.Response(body=sse(events), headers={"Content-Type": "text/event-stream; charset=utf-8"})
    resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
    await resp.prepare(request)
    await resp.write(sse(events))
    hold = float(os.environ.get("FAKE_HOLD_OPEN", "0"))
    if hold:        # simulate a proxy that delivers the reply but keeps the stream open
        await asyncio.sleep(hold)
    await resp.write_eof()
    return resp


async def count(request):
    LOG.write(json.dumps({"path": request.path, "body": await request.json()}) + "\n")
    LOG.flush()
    return web.json_response({"input_tokens": 100})


async def other(request):
    return web.json_response({"data": []})


app = web.Application(client_max_size=64 * 1024 * 1024)
app.router.add_post("/v1/messages", messages)
app.router.add_post("/v1/messages/count_tokens", count)
app.router.add_route("*", "/{t:.*}", other)
_ssl = None
if os.environ.get("FAKE_TLS_CERT"):
    import ssl
    _ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    _ssl.load_cert_chain(os.environ["FAKE_TLS_CERT"], os.environ["FAKE_TLS_KEY"])
web.run_app(app, host="127.0.0.1", port=int(os.environ.get("FAKE_PORT", "9999")), print=None,
            ssl_context=_ssl)
