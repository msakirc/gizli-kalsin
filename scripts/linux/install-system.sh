#!/usr/bin/env bash
# Isolated Linux install (run with sudo from the redact-guard folder):
#   sudo scripts/linux/install-system.sh            # proxy mode (Remote Control works)
#   sudo CORP_PROXY=http://proxy.corp:8080 scripts/linux/install-system.sh
#
# - code copied to /opt/redact-guard, owned by root (Claude can't edit the hooks or config)
# - service runs as the system user `redact-guard`; key + vault + CA key in /var/lib/redact-guard (0700)
# - public files in /etc/redact-guard: ca.pem (for NODE_EXTRA_CA_CERTS), hook-secret, config
# - Claude Code settings are applied for the user who ran sudo
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
USER_NAME="${SUDO_USER:?run this with sudo from your own account}"
OPT=/opt/redact-guard; ETC=/etc/redact-guard; STATE=/var/lib/redact-guard
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }

id redact-guard >/dev/null 2>&1 || useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin redact-guard
rm -rf "$OPT"; mkdir -p "$OPT" "$ETC" "$STATE"
(cd "$SRC" && tar --exclude=./.venv --exclude=./.git --exclude='__pycache__' -cf - .) | (cd "$OPT" && tar -xf -)
python3 -m venv "$OPT/.venv"
"$OPT/.venv/bin/pip" install -q --upgrade pip
"$OPT/.venv/bin/pip" install -q -r "$OPT/requirements.txt"
# make `python -m redact_guard` work from any folder (doctor runs in your project)
"$OPT/.venv/bin/python" -c "import sysconfig,sys; open(sysconfig.get_paths()['purelib']+'/redact_guard_root.pth','w').write(sys.argv[1]+'\n')" "$OPT"
chown -R root:root "$OPT"; chmod -R go-w "$OPT"

# existing proxy: detected from the environment sudo kept, or CORP_PROXY
CORP="${CORP_PROXY:-$(cd "$OPT" && .venv/bin/python -c "from redact_guard import upstream as U; up,_=U.detect('auto',{('127.0.0.1',8788)}); print(up.url or 'none')")}"
echo "existing proxy: $CORP"
[[ -s "$ETC/hook-secret" ]] || (umask 022; python3 -c "import secrets;print(secrets.token_hex(32))" > "$ETC/hook-secret")
"$OPT/.venv/bin/python" - "$OPT/config/redact-guard.yaml" "$ETC/redact-guard.yaml" "$STATE" "$CORP" "$ETC/hook-secret" "$USER_NAME" <<'PY'
import sys, yaml
src, dst, state, corp, secret, me = sys.argv[1:7]
c = yaml.safe_load(open(src, encoding="utf-8")) or {}
det = c.get("detectors") or {}
c["detectors"] = det
own = list(det.get("own_usernames") or [])
if me not in own:
    own.append(me)              # the service account can't know who you are
det["own_usernames"] = own
c.setdefault("vault", {}).update({"dir": state, "key_file": state + "/key"})
c["audit_log"] = state + "/audit.jsonl"
c.setdefault("proxy", {})["confdir"] = state + "/mitm"
cp = c.setdefault("corporate_proxy", {})
if str(cp.get("url", "auto")) == "auto":
    cp["url"] = corp
c["hook_secret_file"] = secret
yaml.safe_dump(c, open(dst, "w", encoding="utf-8"), sort_keys=False, allow_unicode=True)
PY
chmod 644 "$ETC/redact-guard.yaml" "$ETC/hook-secret"
chown -R redact-guard:redact-guard "$STATE"; chmod 700 "$STATE"
(cd "$OPT" && runuser -u redact-guard -- .venv/bin/python -E -m redact_guard proxy --init -c "$ETC/redact-guard.yaml" >/dev/null)
install -m 644 "$STATE/mitm/mitmproxy-ca-cert.pem" "$ETC/ca.pem"

install -m 644 "$OPT/scripts/linux/redact-guard.service" /etc/systemd/system/redact-guard.service
systemctl daemon-reload
systemctl enable --now redact-guard
sleep 3
curl -s --proxy http://127.0.0.1:8788 http://redact-guard.invalid/healthz && echo

runuser -u "$USER_NAME" -- "$OPT/.venv/bin/python" "$OPT/scripts/render_settings.py" \
  --platform posix --mode proxy --ca "$ETC/ca.pem" --guard-root "$OPT" --apply
echo
echo "Done. Check as $USER_NAME (not root):  cd <project> && $OPT/.venv/bin/python -m redact_guard doctor -c $ETC/redact-guard.yaml"
