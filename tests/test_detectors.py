import os
import random
import string

import pytest

from redact_guard.vault import ALL_CLASSES, TOKEN_RE, Vault

SECRETS_THAT_MUST_NOT_LEAK = {
    "app.env": ["S3cr3t!Pass", "app_user", "10.20.30.40", "r3d1sPa55w0rd", "cache.prod.internal",
                "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Hv9xYzAbCdEfGh51JkLmNoPq", "omer.celik@acme-corp.com.tr", "postgres://app_user"],
    "values.yaml": ["Xk9#mP2$vL8q", "orders_admin", "orders.acme.internal",
                    "registry.acme.internal", "pg-primary.db.svc.cluster.local",
                    "sk-proj-AbCdEf1234567890GhIjKlMnOpQrStUv"],
    "secret.yaml": ["b3JkZXJzX2FkbWlu", "WGs5I21QMiR2TDhx", "plain-text-api-key-123"],
    "nginx.log": ["203.0.113.77", "ayse.demir@gmail.com", "10.0.4.17", "mehmet.kaya",
                  "Hunter2024!", "eyJhbGciOiJIUzI1NiJ9", "10000000146", "TR330006100519786457841326",
                  "532 123 45 67", "4111 1111 1111 1111", "2001:db8:85a3::8a2e:370:7334",
                  "abcDEF123456ghiJKL789mnoPQR", "/home/omer"],
    "agent.py": ["pr0d-P@ssw0rd-2026"],
    "config.json": ["db01.acme.corp", "svc_orders", "j8Kd#2mZ!q", "MIIEowIBAAKCAQEA1234"],
}

MUST_STAY_READABLE = {
    "app.env": ["LOG_LEVEL=info", "MAX_TOKENS=4096", "DB_PASSWORD_FILE=/run/secrets/db_password",
                "API_TOKEN=${VAULT_API_TOKEN}"],
    "values.yaml": ["replicaCount: 3", 'tag: "1.42.0"', "existingSecret: orders-db-secret",
                    "secretName: orders-tls", "{{ .Values.global.redisPassword }}", "memory: 512Mi",
                    "key: signing-key"],
    "secret.yaml": ["feature: enabled", "kind: ConfigMap"],
    "agent.py": ["max_tokens = 4096", "password = args.password", "token = get_token()",
                 "token_budget: int = 1000", 'os.environ["ANTHROPIC_API_KEY"]'],
    "config.json": ["3f9a2c1b7d4e5f60718293a4b5c6d7e8f9012345", "sha512-z4PhNX7vuL3x", '"port": 5432'],
}


@pytest.mark.parametrize("name", sorted(SECRETS_THAT_MUST_NOT_LEAK))
def test_no_leaks(redactor, fixtures, name):
    out = redactor.tokenize(fixtures[name])
    for s in SECRETS_THAT_MUST_NOT_LEAK[name]:
        assert s not in out, f"{s!r} leaked from {name}:\n{out}"


@pytest.mark.parametrize("name", sorted(MUST_STAY_READABLE))
def test_structure_stays_readable(redactor, fixtures, name):
    out = redactor.tokenize(fixtures[name])
    for s in MUST_STAY_READABLE[name]:
        assert s in out, f"{s!r} was over-redacted in {name}:\n{out}"


def test_roundtrip_all_fixtures(redactor, fixtures):
    for name, text in fixtures.items():
        out = redactor.tokenize(text)
        back, withheld = redactor.restore(out, ALL_CLASSES)
        assert back == text, name
        assert not withheld


def test_deterministic_tokens_across_files(redactor):
    a = redactor.tokenize("DB_PASSWORD=Zq8!wLm2#rT")
    b = redactor.tokenize("password: 'Zq8!wLm2#rT'")
    tok = TOKEN_RE.search(a).group(0)
    assert tok in b


def test_exact_match_catches_value_in_unkeyed_context(redactor):
    redactor.tokenize("DB_PASSWORD=Zq8!wLm2#rT")
    out = redactor.tokenize("connection failed for secret Zq8!wLm2#rT at startup")
    assert "Zq8!wLm2#rT" not in out


def test_k8s_base64_value_learned_in_decoded_form(redactor, fixtures):
    redactor.tokenize(fixtures["secret.yaml"])
    # the decoded password from the Secret shows up later in plain text
    out = redactor.tokenize("echo Xk9#mP2$vL8q")
    assert "Xk9#mP2$vL8q" not in out


def test_dictionary_word_password_not_sprayed_everywhere(redactor):
    redactor.tokenize("POSTGRES_PASSWORD=postgres")
    out = redactor.tokenize("We run postgres 16 in production.")
    assert "postgres 16" in out


def test_turkish_validators():
    from redact_guard.detectors import iban_valid, luhn_valid, tckn_valid
    assert tckn_valid("10000000146")
    assert not tckn_valid("12345678901")
    assert iban_valid("TR330006100519786457841326")
    assert not iban_valid("TR330006100519786457841327")
    assert luhn_valid("4111111111111111")


def test_versions_and_hashes_not_ips(redactor):
    text = "requires node>=18.17.0, python 3.12.1, build 10.0.19041.1, sha 9f86d081884c7d65"
    assert redactor.tokenize(text) == text


def test_private_key_in_escaped_json(redactor):
    t = '{"k": "-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1r\\n-----END OPENSSH PRIVATE KEY-----"}'
    out = redactor.tokenize(t)
    assert "PRIVATE KEY" not in out and "RDX_PRIVKEY_" in out


def test_fuzz_roundtrip():
    rnd = random.Random(1234)
    from redact_guard.engine import Redactor
    r = Redactor(Vault(os.urandom(48)))
    pieces = ["password=", "token: ", "user=", "10.1.2.3", "a@b.co", "/home/x/", " ", "\n", "\"", "'",
              "RDX_", "postgres://u:p@h/db", "AKIA", "-----BEGIN", "=", ":", "{", "}", "eyJ", "+90 532"]
    for _ in range(3000):
        s = "".join(rnd.choice(pieces + [rnd.choice(string.printable)]) for _ in range(rnd.randint(1, 40)))
        out = r.tokenize(s)
        back, _ = r.restore(out, ALL_CLASSES)
        if "RDX_" in s:
            continue  # pre-existing token-looking text is out of scope
        assert back == s, (s, out, back)


def test_vault_persists_encrypted(tmp_path):
    from redact_guard.engine import Redactor
    from redact_guard.vault import load_or_create_key
    key = load_or_create_key(tmp_path / "key")
    if os.name != "nt":                                 # Windows uses an ACL (icacls), not mode bits
        assert (tmp_path / "key").stat().st_mode & 0o077 == 0
    v1 = Vault(key, tmp_path / "vault.bin")
    out1 = Redactor(v1).tokenize("DB_PASSWORD=Zq8!wLm2#rTyy")
    raw = (tmp_path / "vault.bin").read_bytes()
    assert b"Zq8!wLm2" not in raw                       # encrypted at rest
    v2 = Vault(key, tmp_path / "vault.bin")             # restart
    r2 = Redactor(v2)
    tok = TOKEN_RE.search(out1).group(0)
    assert r2.restore(tok, ALL_CLASSES)[0] == "Zq8!wLm2#rTyy"
    assert tok in r2.tokenize("leaked later: Zq8!wLm2#rTyy")  # exact-match survives restart
