#!/usr/bin/env bash
# End-to-end test with the REAL Claude Code CLI against a scripted fake model.
# Needs: claude on PATH (or CLAUDE_BIN), python3 with aiohttp/pyyaml/cryptography.
# Usage: tests/e2e/run.sh            (uses a throwaway project under $HOME)
set -euo pipefail
ROOT="${REDACT_GUARD_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
export E2E_DIR="$(mktemp -d)"
PROJECT="$HOME/redact-guard-e2e-project"
export E2E_PROJECT="$PROJECT"
rm -rf "$PROJECT"; mkdir -p "$PROJECT"; cp "$ROOT/tests/fixtures/values.yaml" "$PROJECT/"
(cd "$PROJECT" && git init -q && git add -A && \
  git -c user.name="Ayşe Demir" -c user.email="ayse.demir@acme-corp.com.tr" commit -qm "Initial chart" \
  -m "Signed-off-by: Mehmet Kaya <mkaya@acme-corp.com.tr>")
cat > "$E2E_DIR/gw.yaml" <<YAML
upstream: http://127.0.0.1:9999
corporate_proxy: {url: none}
listen: {host: 127.0.0.1, port: 8799}
vault: {dir: $E2E_DIR/state, key_file: $E2E_DIR/state/key}
audit_log: $E2E_DIR/state/audit.jsonl
YAML
python3 - "$ROOT" "$E2E_DIR" <<'PY'
import json, os, sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from render_settings import render
s = render("http://127.0.0.1:8799")
s.pop("sandbox")          # keep the test independent of bubblewrap
if os.environ.get("E2E_DROP_HOOKS") == "1":
    s.pop("hooks")        # for hosts whose Claude Code can't run user hooks (they then fail closed)
json.dump(s, open(sys.argv[2] + "/settings.json", "w"))
PY
python3 "$ROOT/tests/e2e/fake_model.py" > "$E2E_DIR/fake.log" 2>&1 & FAKE=$!
(cd "$ROOT" && exec python3 -m redact_guard serve -c "$E2E_DIR/gw.yaml" 2>"$E2E_DIR/gw.log") & GW=$!
trap 'kill $FAKE $GW 2>/dev/null; rm -rf "$PROJECT"' EXIT
sleep 2
(cd "$PROJECT" && ANTHROPIC_BASE_URL=http://127.0.0.1:8799 REDACT_GUARD_URL=http://127.0.0.1:8799 \
  ANTHROPIC_API_KEY=sk-ant-e2e-dummy CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  timeout 120 "$CLAUDE_BIN" -p "Add sslMode: require next to the postgres password in values.yaml (db is at 10.20.30.40)" \
    --settings "$E2E_DIR/settings.json" --permission-mode acceptEdits --allowedTools Read Edit Bash \
    --model claude-sonnet-4-5 --output-format stream-json --verbose > "$E2E_DIR/claude.jsonl" 2>&1) || true
python3 - "$E2E_DIR" "$PROJECT" "$USER" <<'PY'
import json, os, sys
e2e, project, user = sys.argv[1:4]
raw = open(f"{e2e}/upstream_bodies.jsonl").read()
fails = []
for s in ["Xk9#mP2$vL8q", "orders_admin", "registry.acme.internal", "orders.acme.internal",
          "sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUv", project, "Ayşe Demir", "ayse.demir@acme-corp.com.tr",
          "Mehmet Kaya", "mkaya@acme-corp.com.tr", "10.20.30.40"]:
    if s in raw: fails.append(f"LEAK upstream: {s}")
if user and len(user) > 2 and f"/home/{user}" in raw: fails.append("LEAK upstream: home dir")
v = open(f"{project}/values.yaml").read()
if 'password: "Xk9#mP2$vL8q"\n    sslMode: require' not in v: fails.append("edit not applied with real value")
if os.path.exists(f"{e2e}/leak.txt"): fails.append("secret exfiltrated through Bash")
shown = open(f"{e2e}/claude.jsonl").read()
if "The password is Xk9#mP2$vL8q" not in shown: fails.append("terminal did not show the real value")
if "Ay\\u015fe Demir" not in shown and "Ayşe Demir" not in shown: fails.append("git log output missing locally")
if '"Initial chart' not in raw and "Initial chart" not in raw: fails.append("git log never reached the model")
print("\n".join(fails) if fails else "E2E PASS: model saw only tokens (file, prompt IP, git names/emails); "
      "edit applied with the real value; terminal showed real values; exfil and psql blocked")
sys.exit(1 if fails else 0)
PY
