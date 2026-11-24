import os
import re

import pytest

from redact_guard import policy as P
from redact_guard.detectors import vkn_valid
from redact_guard.engine import Redactor
from redact_guard.vault import ALL_CLASSES, TOKEN_RE, Vault


def test_token_format_never_looks_like_an_id_number():
    v = Vault(os.urandom(48))
    for i in range(5000):
        tok = v.token_for(f"value-{i}", "SECRET")
        suffix = tok.rsplit("_", 1)[1]
        assert len(suffix) == 12
        assert not re.search(r"\d{6,}", suffix), tok
        assert not re.search(r"(?<!\d)\d{10,11}(?!\d)", tok)


GIT_LEAKS = {
    "git_log.txt": ["Ömer Çelik", "omer.celik@acme-corp.com.tr", "Ayşe Demir", "ayse.demir@gmail.com",
                    "Mehmet Kaya", "mkaya@acme-corp.com.tr"],
    "git_blame.txt": ["Ömer Çelik", "Ayşe Demir"],
    "shortlog.txt": ["Ömer Çelik", "Ayşe Demir"],
    "gitconfig": ["Ömer Çelik", "omer.celik@", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "omer:"],
    "package.json": ["Ayşe Demir", "ayse.demir@gmail.com"],
    "credentials.txt": ["npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "dXNlcjpwYXNzd29yZDEyMw==",
                        "ZGVwbG95OlMzY3IzdCFQYXNz", "N3tRc!Secret", "glpat-AbCdEfGhIjKlMnOpQrSt",
                        "registry.acme.internal", "api.acme.internal"],
    "notes_tr.md": ["Pr0d!2026x", "St4g!ng99", "Adm1n#Pass", "tk_live_998877", "1234567890",
                    "4840847211", "10000000146"],
}
GIT_KEEP = {
    "git_log.txt": ["Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>", "Fix order totals",
                    "commit 3f9a2c1b7d4e5f60718293a4b5c6d7e8f9012345", "Bump aiohttp",
                    "commit 9b1c2d3e4f5061728394a5b6c7d8e9f001122334"],
    "git_blame.txt": ["total = sum(lines)", "2026-11-20 10:12:01 +0300 12"],
    "gitconfig": ["editor = vim", "github.com/acme/orders.git"],
    "package.json": ['"version": "2.3.1"', '"test": "vitest"'],
    "notes_tr.md": ["1795184935", "If the password is incorrect"],
}


@pytest.mark.parametrize("name", sorted(GIT_LEAKS))
def test_v2_no_leaks(redactor, fixtures, name):
    out = redactor.tokenize(fixtures[name])
    for s in GIT_LEAKS[name]:
        assert s not in out, f"{s!r} leaked from {name}:\n{out}"
    back, _ = redactor.restore(out, ALL_CLASSES)
    assert back == fixtures[name]


@pytest.mark.parametrize("name", sorted(GIT_KEEP))
def test_v2_keeps_structure(redactor, fixtures, name):
    out = redactor.tokenize(fixtures[name])
    for s in GIT_KEEP[name]:
        assert s in out, f"{s!r} over-redacted in {name}:\n{out}"


def test_name_learned_from_git_is_hidden_everywhere(redactor, fixtures):
    redactor.tokenize(fixtures["git_log.txt"])
    out = redactor.tokenize("# TODO(Ayşe Demir): handle refunds")
    assert "Ayşe Demir" not in out


def test_decoded_docker_auth_is_learned(redactor, fixtures):
    redactor.tokenize(fixtures["credentials.txt"])
    out = redactor.tokenize("login failed for deploy:S3cr3t!Pass")
    assert "S3cr3t!Pass" not in out


def test_vkn_checksum():
    assert vkn_valid("4840847211")
    assert not vkn_valid("4840847212")


def test_git_commit_gets_real_name_but_not_secrets(redactor, fixtures):
    view = redactor.tokenize(fixtures["git_log.txt"])
    person = re.search(r"Co-authored-by: (RDX_PERSON_[0-9a-f]{12}) <(RDX_EMAIL_[0-9a-f]{12})>", view)
    cmd = f'git commit -m "fix" -m "Co-authored-by: {person.group(1)} <{person.group(2)}>"'
    out = redactor.process_tool_input("Bash", {"command": cmd})
    assert "Ayşe Demir <ayse.demir@gmail.com>" in out["command"]


def test_ids_never_restored_into_shell(redactor, fixtures):
    view = redactor.tokenize(fixtures["notes_tr.md"])
    vkn = re.search(r"RDX_VKN_[0-9a-f]{12}", view).group(0)
    out = redactor.process_tool_input("Bash", {"command": f"grep {vkn} logs/app.log"})
    assert "exit 126" in out["command"]


def test_numbers_inside_hashes_and_identifiers_untouched(redactor):
    t = ("sha 9b1c2d3e4f5061728394a5b6c7d8e9f0 id ord_10000000146 x4111111111111111y "
         "build-4840847211")
    assert redactor.tokenize(t) == t


def _as_read_output(text: str) -> str:
    return "\n".join(f"{i}\t{ln}" for i, ln in enumerate(text.split("\n"), 1))


@pytest.mark.parametrize("name", ["secret.yaml", "values.yaml", "gitconfig", "credentials.txt",
                                  "app.env", "git_log.txt", "nginx.log", "config.json"])
def test_read_tool_format_is_redacted_like_plain(redactor, fixtures, name):
    """Claude Code's Read prefixes lines with `N<tab>`; detection must not change."""
    plain = redactor.tokenize(fixtures[name])
    read = redactor.tokenize(_as_read_output(fixtures[name]))
    assert read == _as_read_output(plain)
    back, _ = redactor.restore(read, ALL_CLASSES)
    assert back == _as_read_output(fixtures[name])


def test_read_output_of_code_is_not_names(redactor):
    code = "def total(lines):\n    return sum(lines)\n\nHello World\npass\n"
    out = redactor.tokenize(_as_read_output(code))
    assert "RDX_" not in out


def test_grep_n_output(redactor):
    t = "deploy/values.yaml:8:    password: \"Xk9#mP2$vL8q\"\nsrc/db.py:3:HOST = '10.0.4.17'"
    out = redactor.tokenize(t)
    assert "Xk9#mP2$vL8q" not in out and "10.0.4.17" not in out
    assert out.startswith("deploy/values.yaml:8:    password: \"RDX_SECRET_")
