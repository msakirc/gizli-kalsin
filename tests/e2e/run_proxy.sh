#!/usr/bin/env bash
# End-to-end test of PROXY MODE with the real Claude Code CLI.
# Claude Code keeps its default api.anthropic.com (so Remote Control stays eligible)
# and reaches it through redact-guard's HTTPS proxy, trusting the local CA.
# For the test, the proxy routes api.anthropic.com to a scripted fake model.
# Usage: tests/e2e/run_proxy.sh
set -euo pipefail
ROOT="${REDACT_GUARD_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
export E2E_DIR="$(mktemp -d)"
PROJECT="$HOME/redact-guard-proxy-e2e"
export E2E_PROJECT="$PROJECT"
rm -rf "$PROJECT"; mkdir -p "$PROJECT"; cp "$ROOT/tests/fixtures/values.yaml" "$PROJECT/"
(cd "$PROJECT" && git init -q && git add -A && \
  git -c user.name="Ayşe Demir" -c user.email="ayse.demir@acme-corp.com.tr" commit -qm "Initial chart")
cat > "$E2E_DIR/px.yaml" <<YAML
proxy: {host: 127.0.0.1, port: 8798}
corporate_proxy: {url: none}
vault: {dir: $E2E_DIR/state, key_file: $E2E_DIR/state/key}
audit_log: $E2E_DIR/state/audit.jsonl
YAML
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
CA=$(cd "$ROOT" && python3 -m redact_guard proxy --init -c "$E2E_DIR/px.yaml")
python3 "$ROOT/tests/e2e/fake_model.py" > "$E2E_DIR/fake.log" 2>&1 & FAKE=$!
(cd "$ROOT" && REDACT_GUARD_TEST_UPSTREAM=http://127.0.0.1:9999 \
   exec python3 -m redact_guard proxy -c "$E2E_DIR/px.yaml" >"$E2E_DIR/proxy.out" 2>"$E2E_DIR/proxy.log") & PX=$!
trap 'kill $FAKE $PX 2>/dev/null; rm -rf "$PROJECT"' EXIT
sleep 4
(cd "$PROJECT" && env -i HOME="$HOME" USER="${USER:-user}" PATH="$PATH" TERM=dumb \
  HTTPS_PROXY=http://127.0.0.1:8798 https_proxy=http://127.0.0.1:8798 \
  NO_PROXY="localhost,127.0.0.1" no_proxy="localhost,127.0.0.1" NODE_EXTRA_CA_CERTS="$CA" \
  ANTHROPIC_API_KEY=sk-ant-e2e-dummy DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1 \
  timeout 120 "$CLAUDE_BIN" -p "Add sslMode: require next to the postgres password in values.yaml (db is at 10.20.30.40)" \
    --settings "$E2E_DIR/settings.json" --permission-mode acceptEdits --allowedTools Read Edit Bash \
    --model claude-sonnet-4-5 --output-format stream-json --verbose < /dev/null > "$E2E_DIR/claude.jsonl" 2>&1) || true
python3 - "$E2E_DIR" "$PROJECT" <<'PY'
import os, sys
e2e, project = sys.argv[1:3]
raw = open(f"{e2e}/upstream_bodies.jsonl").read()
fails = []
for s in ["Xk9#mP2$vL8q", "orders_admin", "registry.acme.internal", "orders.acme.internal",
          "sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUv", project, "Ayşe Demir",
          "ayse.demir@acme-corp.com.tr", "10.20.30.40"]:
    if s in raw: fails.append(f"LEAK upstream: {s}")
if not raw.strip(): fails.append("no traffic reached the model through the proxy")
v = open(f"{project}/values.yaml").read()
if 'password: "Xk9#mP2$vL8q"\n    sslMode: require' not in v: fails.append("edit not applied with real value")
if os.path.exists(f"{e2e}/leak.txt"): fails.append("secret exfiltrated through Bash")
if "The password is Xk9#mP2$vL8q" not in open(f"{e2e}/claude.jsonl").read():
    fails.append("terminal did not show the real value")
print("\n".join(fails) if fails else "PROXY E2E PASS: no ANTHROPIC_BASE_URL (Remote Control eligible); model saw only "
      "tokens; edit applied with the real value; exfil and psql blocked")
sys.exit(1 if fails else 0)
PY
