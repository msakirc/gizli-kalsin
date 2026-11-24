"""Windows-specific behaviour (runs on any OS)."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from redact_guard import policy as P
from redact_guard.vault import ALL_CLASSES

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("cmd", [
    r'& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -h db -U app',
    r"C:\tools\sqlcmd.exe -S sql01 -E -Q ""select * from users""",
    "sqlcmd -S sql01 -E -Q 'select 1'",
    "Invoke-Sqlcmd -ServerInstance sql01 -Query 'select * from dbo.Users'",
    "$c = New-Object System.Data.SqlClient.SqlConnection 'Server=sql01;Database=app;Integrated Security=SSPI'",
    "[System.Data.Odbc.OdbcConnection]::new('DSN=prod')",
    "Add-Type -Path Npgsql.dll; $c = [Npgsql.NpgsqlConnection]::new($cs)",
    "Start-Process psql -ArgumentList '-h db'",
    "cmd /c psql -h db",
    "cmd.exe /c \"mysql -u root\"",
    "powershell -NoProfile -Command \"Invoke-Sqlcmd -Query 'select 1'\"",
    "pwsh -c 'sqlcmd -E'",
    "powershell -enc SQBuAHYAbwBrAGUALQBTAHEAbABjAG0AZAA=",
    "pwsh -EncodedCommand SQBuAHYAbwBrAGUA",
    "wsl psql -h db",
    "cmdkey /list",
    "Get-StoredCredential -Target prod-sql",
    "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))",
    "Get-Content C:\\ProgramData\\MySQL\\data\\ibdata1",
    r"type C:\Users\omer\AppData\Roaming\postgresql\pgpass.conf",
    r"Copy-Item 'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\app.mdf' .",
    "aws dynamodb scan --table-name Users",
    "aws rds-data execute-statement --sql 'select * from users' --resource-arn x --secret-arn y",
    "aws athena start-query-execution --query-string 'select 1'",
    "gcloud sql connect prod --user=postgres",
    "az postgres flexible-server connect -n prod -u admin",
    "ssms.exe",
])
def test_windows_db_access_blocked(cmd):
    assert P.check_shell_command(cmd), cmd
    assert P.check_tool("PowerShell", {"command": cmd}), cmd


@pytest.mark.parametrize("cmd", [
    "Get-ChildItem -Recurse src", "dotnet test", "npm run build", "git status",
    "Select-String -Path *.cs -Pattern 'SqlConnection'",            # searching code is fine
    "aws dynamodb describe-table --table-name Users",               # control plane
    "aws s3 ls", "az group list", "Test-NetConnection github.com -Port 443",
    r"code C:\work\orders\README.md", "helm template .\\charts\\api",
])
def test_windows_ordinary_commands_allowed(cmd):
    assert P.check_shell_command(cmd) is None, cmd


def test_powershell_tool_without_command_fails_closed():
    assert P.check_tool("PowerShell", {"script": "psql"})


def test_crlf_files_redact_and_roundtrip(redactor, fixtures):
    for name in ("app.env", "values.yaml", "secret.yaml", "gitconfig", "git_log.txt", "notes_tr.md"):
        crlf = fixtures[name].replace("\n", "\r\n")
        lf_out = redactor.tokenize(fixtures[name])
        out = redactor.tokenize(crlf)
        assert out == lf_out.replace("\n", "\r\n"), name
        back, _ = redactor.restore(out, ALL_CLASSES)
        assert back == crlf, name


def test_windows_users_and_paths(redactor):
    t = (r"cwd: C:\Users\Omer.Celik\work  C:/Users/omer/x  /c/Users/omer/y  "
         r"whoami: acme\ayse.demir  NT AUTHORITY\SYSTEM  src\main.py  BUILTIN\Administrators")
    out = redactor.tokenize(t)
    for leak in ("Omer.Celik", "/omer/", "ayse.demir"):
        assert leak not in out, out
    for keep in (r"NT AUTHORITY\SYSTEM", r"src\main.py", r"BUILTIN\Administrators"):
        assert keep in out, out
    assert redactor.restore(out, ALL_CLASSES)[0] == t


def _render(*args):
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "render_settings.py"), *args],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def test_render_windows_settings():
    s = _render("--platform", "windows")
    assert "sandbox" not in s                       # would make Claude Code exit on Windows
    assert s["disableRemoteControl"] is True
    cmd = s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert (cmd.startswith('py -3 -I "') or '.venv/Scripts/python.exe" -I "' in cmd) \
        and cmd.endswith('/hooks/guard.py" pre-tool-use')   # -I: a repo's PYTHONPATH can't hijack it
    assert "\\" not in cmd                          # forward slashes work in cmd, PowerShell, bash
    deny = s["permissions"]["deny"]
    assert "PowerShell(psql *)" in deny and "PowerShell(Invoke-Sqlcmd *)" in deny
    m = _render("--platform", "windows", "--managed")
    assert "sandbox" not in m and m["allowedProviders"] == ["customEndpoint"]


def test_render_posix_keeps_sandbox_and_disables_remote_control():
    s = _render("--platform", "posix")
    assert s["sandbox"]["enabled"] is True and s["disableRemoteControl"] is True


def test_hook_reads_utf8_stdin():
    ev = {"tool_name": "Read", "tool_input": {"file_path": "C:/Users/Ömer/app/data.sqlite"}}
    p = subprocess.run([sys.executable, str(ROOT / "hooks" / "guard.py"), "pre-tool-use"],
                       input=json.dumps(ev, ensure_ascii=False).encode("utf-8"), capture_output=True)
    assert b'"permissionDecision": "deny"' in p.stdout


def test_windows_bypass_list_becomes_no_proxy():
    sys.path.insert(0, str(ROOT / "scripts"))
    from render_settings import bypass_to_no_proxy
    got = bypass_to_no_proxy(["10.20.*", "*.corp.example", "eposta.corp.example", "*.gib", "172.28.*",
                              "<local>", "*.anthropic.com", "claude.ai", "8.8.*", "*internal*", "10.*.1.*"])
    assert got == ["10.20.0.0/16", ".corp.example", "eposta.corp.example", ".gib", "172.28.0.0/16"]
