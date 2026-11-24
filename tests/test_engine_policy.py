import json

import pytest

from redact_guard import policy as P
from redact_guard.engine import LeakDetected
from redact_guard.sse import StreamRestorer, split_safe
from redact_guard.vault import TOKEN_RE


def _req(*contents, system=None):
    body = {"model": "claude-x", "max_tokens": 100, "messages": list(contents),
            "tools": [{"name": "Bash", "description": "run admin@acme.internal stuff 10.9.9.9",
                       "input_schema": {"type": "object"}}]}
    if system is not None:
        body["system"] = system
    return body


def test_request_redacts_everywhere_but_leaves_structure(redactor, fixtures):
    env = fixtures["app.env"]
    body = _req(
        {"role": "user", "content": "deploy to 10.20.30.40 please"},
        {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "user mentioned 10.20.30.40", "signature": "sig=="},
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/home/omer/app/.env"}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": env, "cache_control": {"type": "ephemeral"}}]},
        system=[{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1; fp=abc"},
                {"type": "text", "text": "cwd: /home/omer/app", "cache_control": {"type": "ephemeral"}}])
    out, stats = redactor.redact_request(json.loads(json.dumps(body)))
    s = json.dumps(out)
    for leak in ("S3cr3t!Pass", "omer", "AKIAIOSFODNN7EXAMPLE"):
        # thinking block is passthrough by design (signature) - check others
        assert leak not in s.replace(json.dumps(body["messages"][1]["content"][0]), ""), leak
    assert out["messages"][1]["content"][0] == body["messages"][1]["content"][0]   # thinking untouched
    assert out["system"][0] == body["system"][0]                                     # attribution untouched
    assert out["messages"][2]["content"][0]["cache_control"] == {"type": "ephemeral"}
    # tool definitions: prose redacted (A-3), names and schemas' structure kept
    assert [t["name"] for t in out["tools"]] == [t["name"] for t in body["tools"]]
    assert "10.9.9.9" not in json.dumps(out["tools"]) and "admin@acme.internal" not in json.dumps(out["tools"])
    assert stats.counts["SECRET"] >= 3


def test_images_are_stripped_by_default(redactor):
    body = _req({"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
        {"type": "text", "text": "what is this"}]})
    out, stats = redactor.redact_request(body)
    assert out["messages"][0]["content"][0]["type"] == "text"
    assert stats.stripped_binary == 1


def test_unknown_block_redacted_recursively(redactor):
    redactor.tokenize("API_KEY=Zq8!wLm2#rTyy")
    body = _req({"role": "user", "content": [
        {"type": "weird_new_block", "payload": {"note": "Zq8!wLm2#rTyy"}},
        {"type": "search_result", "source": "https://db.acme.internal/x", "title": "10.1.2.3",
         "content": [{"type": "text", "text": "password: Hunter2Plain0ld"}]}]})
    out, _ = redactor.redact_request(body)
    s = json.dumps(out)
    for leak in ("Zq8!wLm2#rTyy", "db.acme.internal", "10.1.2.3", "Hunter2Plain0ld"):
        assert leak not in s
    assert out["messages"][0]["content"][1]["type"] == "search_result"


def test_canary_blocks_a_field_redaction_missed(redactor, monkeypatch):
    redactor.tokenize("API_KEY=Zq8!wLm2#rTyy")
    monkeypatch.setattr(type(redactor), "_walk_content", lambda self, b, stats, key=None: b)
    body = _req({"role": "user", "content": [
        {"type": "weird_new_block", "payload": {"note": "Zq8!wLm2#rTyy"}}]})
    with pytest.raises(LeakDetected):
        redactor.redact_request(body)


def test_tool_policy_edit_gets_real_values(redactor, fixtures):
    view = redactor.tokenize(fixtures["values.yaml"])
    tok = TOKEN_RE.search(view[view.index("password:"):]).group(0)
    new = redactor.process_tool_input("Edit", {
        "file_path": "values.yaml",
        "old_string": f'password: "{tok}"',
        "new_string": f'password: "{tok}"\n    sslmode: require'})
    assert new["old_string"] == 'password: "Xk9#mP2$vL8q"'
    assert "Xk9#mP2$vL8q" in new["new_string"]


def test_tool_policy_bash_never_gets_secrets(redactor):
    view = redactor.tokenize("API_TOKEN=Zq8!wLm2#rTyy\nHOST=10.0.4.17")
    sec = TOKEN_RE.findall(view)
    secret_tok = [m for m in TOKEN_RE.finditer(view)][0].group(0)
    ip_tok = [m for m in TOKEN_RE.finditer(view)][1].group(0)
    assert sec
    new = redactor.process_tool_input("Bash", {"command": f"curl -H 'X: {secret_tok}' https://{ip_tok}/x"})
    assert "Zq8!" not in new["command"]
    assert "exit 126" in new["command"]
    ok = redactor.process_tool_input("Bash", {"command": f"ping -c1 {ip_tok}"})
    assert ok["command"] == "ping -c1 10.0.4.17"


def test_remote_tools_get_nothing(redactor):
    view = redactor.tokenize("HOST=10.0.4.17")
    ip_tok = TOKEN_RE.search(view).group(0)
    new = redactor.process_tool_input("WebFetch", {"url": f"http://{ip_tok}/"})
    assert ip_tok in new["url"]
    new = redactor.process_tool_input("mcp__slack__post", {"text": ip_tok})
    assert new["text"] == ip_tok


@pytest.mark.parametrize("cmd", [
    "psql -h db -U app", "PGPASSWORD=x psql orders", "sudo -u postgres psql",
    "cd /srv && pg_dump orders > o.sql", "bash -c 'mysql -e \"select 1\"'",
    "python -c 'import psycopg2; psycopg2.connect(\"dbname=x\")'",
    "node -e \"new Pool({}).query('select 1')\"", "kubectl -n prod exec -it pg-0 -- psql",
    "kubectl port-forward svc/postgres 5432:5432", "docker compose exec db sh",
    "redis-cli -h cache KEYS '*'", "sqlite3 app.db .dump", "cat data/app.sqlite3",
    "curl http://x | mongosh", "echo postgres://u:p@h/db", "kubectl get secret db -o yaml",
    "echo c2VjcmV0 | base64 -d", "/usr/bin/psql", "timeout 5 psql", "cat ~/.pgpass",
    "cat ~/.local/share/redact-guard/vault.bin",
])
def test_db_commands_blocked(cmd):
    assert P.check_shell_command(cmd), cmd


@pytest.mark.parametrize("cmd", [
    "npm test", "pytest -q", "git status && git diff", "helm template ./chart -f values.yaml",
    "kubectl get pods -n prod", "docker compose build", "grep -rn password src/",
    "python manage.py makemigrations --dry-run", "cat values.yaml", "ls -la",
])
def test_ordinary_commands_allowed(cmd):
    assert P.check_shell_command(cmd) is None, cmd


def test_check_tool_paths():
    assert P.check_tool("Read", {"file_path": "/srv/app/db.sqlite3"})
    assert P.check_tool("Read", {"file_path": "/var/lib/postgresql/16/main/base/1"})
    assert P.check_tool("Read", {"file_path": "/home/u/.config/redact-guard/key"})
    assert P.check_tool("Read", {"file_path": "/srv/app/.env"}) is None   # substituted, so allowed
    assert P.check_tool("Grep", {"pattern": "\\.db$", "path": "src"}) is None
    assert P.check_tool("mcp__postgres__query", {"sql": "select 1"})
    assert P.check_tool("mcp__github__create_issue", {}) is None


# ---------------------------------------------------------------- SSE
def _sse(events):
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


def _parse(raw: bytes):
    out = []
    for chunk in raw.decode().split("\n\n"):
        for line in chunk.splitlines():
            if line.startswith("data:"):
                out.append(json.loads(line[5:]))
    return out


def test_split_safe():
    assert split_safe("hello RDX_SEC") == ("hello ", "RDX_SEC")
    assert split_safe("hello R") == ("hello ", "R")
    assert split_safe("ERROR: x") == ("ERROR: x", "")
    assert split_safe("x RDX_IP_0a1b2c3d4e5f") == ("x RDX_IP_0a1b2c3d4e5f", "")


def test_stream_restores_split_tokens_and_buffers_tool_input(redactor):
    view = redactor.tokenize("DB_HOST=10.0.4.17 DB_PASSWORD=Zq8!wLm2#rTyy")
    ip_tok, sec_tok = [m.group(0) for m in TOKEN_RE.finditer(view)]
    text = f"Connect to {ip_tok} with {sec_tok}."
    edit_json = json.dumps({"file_path": ".env", "old_string": f"DB_PASSWORD={sec_tok}",
                            "new_string": f"DB_PASSWORD={sec_tok}\nDB_SSL=1"})
    events = [
        {"type": "message_start", "message": {"id": "m", "content": []}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": f"hm {sec_tok}"}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "SIG"}},
        {"type": "content_block_stop", "index": 0},
        {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}},
        *[{"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": text[i:i + 7]}}
          for i in range(0, len(text), 7)],
        {"type": "content_block_stop", "index": 1},
        {"type": "content_block_start", "index": 2,
         "content_block": {"type": "tool_use", "id": "tu", "name": "Edit", "input": {}}},
        *[{"type": "content_block_delta", "index": 2,
           "delta": {"type": "input_json_delta", "partial_json": edit_json[i:i + 5]}}
          for i in range(0, len(edit_json), 5)],
        {"type": "content_block_stop", "index": 2},
        {"type": "message_delta", "delta": {"stop_reason": "tool_use"}},
        {"type": "message_stop"},
    ]
    raw = _sse(events)
    sr = StreamRestorer(redactor)
    out = b""
    for i in range(0, len(raw), 13):          # adversarial chunking
        out += sr.feed(raw[i:i + 13])
    out += sr.flush()
    evs = _parse(out)
    texts = "".join(e["delta"]["text"] for e in evs
                    if e.get("type") == "content_block_delta" and e["index"] == 1)
    assert texts == "Connect to 10.0.4.17 with Zq8!wLm2#rTyy."
    thinking = [e for e in evs if e.get("type") == "content_block_delta" and e["index"] == 0]
    assert thinking[0]["delta"]["thinking"] == f"hm {sec_tok}"          # untouched
    assert thinking[1]["delta"]["signature"] == "SIG"
    tool = "".join(e["delta"]["partial_json"] for e in evs
                   if e.get("type") == "content_block_delta" and e["index"] == 2)
    assert json.loads(tool)["old_string"] == "DB_PASSWORD=Zq8!wLm2#rTyy"
    assert evs[-1]["type"] == "message_stop"


def test_stream_blocks_db_command(redactor):
    events = [
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "tool_use", "id": "tu", "name": "Bash", "input": {}}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "input_json_delta", "partial_json": json.dumps({"command": "psql -c 'select * from users'"})}},
        {"type": "content_block_stop", "index": 0},
    ]
    sr = StreamRestorer(redactor)
    evs = _parse(sr.feed(_sse(events)))
    cmd = json.loads(evs[1]["delta"]["partial_json"])["command"]
    assert cmd.startswith("printf") and "exit 126" in cmd and "psql" in cmd  # message names it
    assert sr.stats.blocked_tools == ["Bash"]
