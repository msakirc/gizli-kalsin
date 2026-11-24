import json
import os

import pytest
from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

from redact_guard.engine import Redactor
from redact_guard.server import Gateway
from redact_guard.vault import TOKEN_RE, Vault

pytestmark = pytest.mark.asyncio

SEEN: list[dict] = []
SEEN_HEADERS: list[dict] = []


def _sse(events):
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


async def fake_messages(request: web.Request):
    body = await request.json()
    SEEN.append(body)
    SEEN_HEADERS.append(dict(request.headers))
    # echo back whatever token appears first in the last tool_result, inside an Edit
    last = json.dumps(body["messages"][-1])
    toks = TOKEN_RE.findall(last)
    tok = TOKEN_RE.search(last).group(0) if toks else "none"
    if not body.get("stream"):
        return web.json_response({"type": "message", "role": "assistant", "content": [
            {"type": "text", "text": f"value is {tok}"}], "stop_reason": "end_turn"})
    resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
    await resp.prepare(request)
    events = [
        {"type": "message_start", "message": {"id": "m1", "type": "message", "role": "assistant",
                                              "content": [], "usage": {"input_tokens": 1, "output_tokens": 1}}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": f"I'll edit {tok[:9]}"}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": f"{tok[9:]} now."}},
        {"type": "content_block_stop", "index": 0},
        {"type": "content_block_start", "index": 1,
         "content_block": {"type": "tool_use", "id": "tu1", "name": "Edit", "input": {}}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta",
         "partial_json": json.dumps({"file_path": "a.env", "old_string": f"X={tok}", "new_string": f"X={tok}"})[:20]}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta",
         "partial_json": json.dumps({"file_path": "a.env", "old_string": f"X={tok}", "new_string": f"X={tok}"})[20:]}},
        {"type": "content_block_stop", "index": 1},
        {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 5}},
        {"type": "message_stop"},
    ]
    for e in events:
        await resp.write(_sse([e]))
    await resp.write(b"event: ping\ndata: {\"type\": \"ping\"}\n\n")
    await resp.write_eof()
    return resp


async def _count(request):
    SEEN.append(await request.json())
    return web.json_response({"input_tokens": 3})


async def _hello(request):
    return web.Response()


async def fake_error(request):
    return web.json_response({"type": "error", "error": {"type": "invalid_request_error",
                                                         "message": "thinking signature invalid"}}, status=400)


@pytest.fixture
async def stack():
    SEEN.clear()
    SEEN_HEADERS.clear()
    up_app = web.Application()
    up_app.router.add_post("/v1/messages", fake_messages)
    up_app.router.add_post("/v1/messages/count_tokens", _count)
    up_app.router.add_post("/v1/error", fake_error)
    up_app.router.add_route("HEAD", "/api/hello", _hello)
    up = TestServer(up_app)
    await up.start_server()
    gw = Gateway(Redactor(Vault(os.urandom(48))), str(up.make_url("")).rstrip("/"))
    gws = TestServer(gw.app())
    await gws.start_server()
    async with ClientSession() as s:
        yield s, str(gws.make_url("")).rstrip("/"), gw
    await gws.close()
    await up.close()


def _body(stream=True):
    env = "DB_HOST=10.0.4.17\nDB_PASSWORD=Zq8!wLm2#rTyy\n"
    return {"model": "claude-x", "max_tokens": 50, "stream": stream, "messages": [
        {"role": "user", "content": "fix the env file"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Read",
                                           "input": {"file_path": "/home/omer/a.env"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": env}]}]}


async def test_streaming_roundtrip(stack):
    s, base, _ = stack
    hdr = {"anthropic-version": "2023-06-01", "anthropic-beta": "oauth-2025-04-20,x",
           "Authorization": "Bearer user-oauth", "x-claude-code-session-id": "abc"}
    async with s.post(base + "/v1/messages?beta=true", json=_body(), headers=hdr) as r:
        assert r.status == 200
        raw = await r.read()
    upstream = json.dumps(SEEN[-1])
    assert "Zq8!wLm2#rTyy" not in upstream and "10.0.4.17" not in upstream and "omer" not in upstream
    assert SEEN_HEADERS[-1]["anthropic-beta"] == "oauth-2025-04-20,x"        # forwarded verbatim
    assert SEEN_HEADERS[-1]["Authorization"] == "Bearer user-oauth"
    text = raw.decode()
    deltas = [json.loads(ln[5:]) for ln in text.splitlines() if ln.startswith("data:")]
    said = "".join(d["delta"].get("text", "") for d in deltas if d.get("type") == "content_block_delta")
    tool = "".join(d["delta"].get("partial_json", "") for d in deltas if d.get("type") == "content_block_delta")
    assert "RDX_" not in said
    edit = json.loads(tool)
    assert edit["old_string"] in ("X=Zq8!wLm2#rTyy", "X=10.0.4.17")  # real value restored for Edit
    assert '"type": "ping"' in text                                          # pings forwarded


async def test_non_streaming_and_count_tokens(stack):
    s, base, _ = stack
    async with s.post(base + "/v1/messages", json=_body(stream=False)) as r:
        data = await r.json()
    assert "RDX_" not in data["content"][0]["text"]
    async with s.post(base + "/v1/messages/count_tokens", json=_body(stream=False)) as r:
        assert (await r.json())["input_tokens"] == 3
    assert "Zq8!wLm2#rTyy" not in json.dumps(SEEN)


async def test_unknown_post_blocked_and_head_passthrough(stack):
    s, base, _ = stack
    async with s.post(base + "/v1/error", json={"x": "Zq8!wLm2#rTyy"}) as r:
        assert r.status == 403
    async with s.head(base + "/api/hello") as r:
        assert r.status == 200


async def test_fail_closed_on_garbage(stack):
    s, base, _ = stack
    async with s.post(base + "/v1/messages", data=b"{not json", headers={"Content-Type": "application/json"}) as r:
        assert r.status == 500
        assert "NOT forwarded" in (await r.json())["error"]["message"]
    assert SEEN == []


async def test_canary_refuses(stack, monkeypatch):
    s, base, gw = stack
    gw.redactor.tokenize("API_KEY=Zq8!wLm2#rTyy")
    body = {"model": "x", "max_tokens": 1, "messages": [
        {"role": "user", "content": [{"type": "new_block_kind", "data": {"x": "Zq8!wLm2#rTyy"}}]}]}
    monkeypatch.setattr(type(gw.redactor), "_walk_content", lambda self, b, stats, key=None: b)
    async with s.post(base + "/v1/messages", json=body) as r:
        assert r.status == 500                  # a field redaction missed: refused, not sent
    assert SEEN == []
