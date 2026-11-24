#!/usr/bin/env bash
# Proxy mode CHAINED behind an existing TLS-inspecting proxy, with the real Claude Code CLI:
#   Claude Code -> redact-guard (proxy mode) -> "corporate" mitmproxy (own CA) -> HTTPS fake model
# Checks: everything works, and the corporate proxy only ever sees redacted traffic.
set -euo pipefail
ROOT="${REDACT_GUARD_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
export E2E_DIR="$(mktemp -d)"
PROJECT="$HOME/redact-guard-chain-e2e"; export E2E_PROJECT="$PROJECT"
rm -rf "$PROJECT"; mkdir -p "$PROJECT"; cp "$ROOT/tests/fixtures/values.yaml" "$PROJECT/"
(cd "$PROJECT" && git init -q && git add -A && \
  git -c user.name="Ayşe Demir" -c user.email="ayse.demir@acme-corp.com.tr" commit -qm "Initial chart")
python3 "$ROOT/tests/e2e/make_test_ca.py" "$E2E_DIR/tls"
# 1. "corporate" TLS-inspecting proxy with its own CA, trusting the fake model's CA
mkdir -p "$E2E_DIR/corp"
mitmdump -q --listen-host 127.0.0.1 --listen-port 8790 --set confdir="$E2E_DIR/corp" \
  --set ssl_verify_upstream_trusted_ca="$E2E_DIR/tls/ca.pem" -s "$ROOT/tests/e2e/corp_proxy_addon.py" \
  > "$E2E_DIR/corp.log" 2>&1 & CORP=$!
# 2. HTTPS fake model
FAKE_TLS_CERT="$E2E_DIR/tls/server.pem" FAKE_TLS_KEY="$E2E_DIR/tls/server.key" FAKE_PORT=9443 \
  python3 "$ROOT/tests/e2e/fake_model.py" > "$E2E_DIR/fake.log" 2>&1 & FAKE=$!
sleep 3
CORP_CA="$E2E_DIR/corp/mitmproxy-ca-cert.pem"
# 3. redact-guard, auto-detecting the existing proxy from its environment and trusting
#    the corporate CA through the OS-store bundle (SSL_CERT_FILE is folded into it)
cat > "$E2E_DIR/px.yaml" <<YAML
proxy: {host: 127.0.0.1, port: 8798}
corporate_proxy: {url: auto, ca: system}
vault: {dir: $E2E_DIR/state, key_file: $E2E_DIR/state/key}
audit_log: $E2E_DIR/state/audit.jsonl
YAML
CA=$(cd "$ROOT" && python3 -m redact_guard proxy --init -c "$E2E_DIR/px.yaml")
(cd "$ROOT" && exec env -i PATH="$PATH" HOME="$HOME" HTTPS_PROXY=http://127.0.0.1:8790 SSL_CERT_FILE="$CORP_CA" \
   REDACT_GUARD_TEST_UPSTREAM=https://127.0.0.1:9443 \
   python3 -m redact_guard proxy -c "$E2E_DIR/px.yaml" >"$E2E_DIR/proxy.out" 2>"$E2E_DIR/proxy.log") & PX=$!
trap 'kill $FAKE $PX $CORP 2>/dev/null; pkill -P $$ 2>/dev/null; rm -rf "$PROJECT"' EXIT
sleep 4
python3 - "$ROOT" "$E2E_DIR" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from render_settings import render
s = render("http://unused", "posix")
for k in ("sandbox", "hooks", "disableRemoteControl"):
    s.pop(k, None)
s["env"] = {}
json.dump(s, open(sys.argv[2] + "/settings.json", "w"))
PY
(cd "$PROJECT" && env -i HOME="$HOME" USER="${USER:-user}" PATH="$PATH" TERM=dumb \
  HTTPS_PROXY=http://127.0.0.1:8798 https_proxy=http://127.0.0.1:8798 \
  NO_PROXY="localhost,127.0.0.1" no_proxy="localhost,127.0.0.1" NODE_EXTRA_CA_CERTS="$CA" \
  ANTHROPIC_API_KEY=sk-ant-e2e-dummy DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1 \
  timeout 120 "$CLAUDE_BIN" -p "Add sslMode: require next to the postgres password in values.yaml (db is at 10.20.30.40)" \
    --settings "$E2E_DIR/settings.json" --permission-mode acceptEdits --allowedTools Read Edit Bash \
    --model claude-sonnet-4-5 --output-format stream-json --verbose < /dev/null > "$E2E_DIR/claude.jsonl" 2>&1) || true
python3 - "$E2E_DIR" "$PROJECT" <<'PY'
import json, os, sys
e2e, project = sys.argv[1:3]
fails = []
corp = open(f"{e2e}/corp_seen.jsonl").read() if os.path.exists(f"{e2e}/corp_seen.jsonl") else ""
model = open(f"{e2e}/upstream_bodies.jsonl").read() if os.path.exists(f"{e2e}/upstream_bodies.jsonl") else ""
if "/v1/messages" not in corp: fails.append("traffic did not go through the corporate proxy")
if not model.strip(): fails.append("nothing reached the model")
for s in ["Xk9#mP2$vL8q", "orders_admin", "registry.acme.internal", "10.20.30.40", "Ayşe Demir",
          "ayse.demir@acme-corp.com.tr", project]:
    if s in corp: fails.append(f"corporate proxy saw: {s}")
    if s in model: fails.append(f"model saw: {s}")
v = open(f"{project}/values.yaml").read()
if 'password: "Xk9#mP2$vL8q"\n    sslMode: require' not in v: fails.append("edit not applied with real value")
up = [json.loads(l) for l in open(f"{e2e}/proxy.log") if '"event":"upstream"' in l.replace(" ", "")]
print("upstream detected:", up[0] if up else "?")
n = len([l for l in corp.splitlines() if "/v1/messages" in l])
print("\n".join(fails) if fails else f"CHAIN E2E PASS: Claude Code -> redact-guard -> TLS-inspecting proxy -> model; "
      f"the corporate proxy saw {n} model requests, all redacted; edit applied with the real value")
sys.exit(1 if fails else 0)
PY
