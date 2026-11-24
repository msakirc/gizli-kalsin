"""Key shapes from a real project: _MYCUSTOMPASSWORD, _VERIFICATION_RS_URL, MY_SERVER_ADDRESS,
basicAuthenticationPassword and Spring/shell placeholders with defaults (${NAME:default}).
Uses the default config (no internal_domains), so this is the key-based safety net."""
import pytest

from redact_guard.vault import ALL_CLASSES

FILES = ["user_keys.yaml", "user_keys.env", "user_keys.properties"]

MUST_NOT_LEAK = ["Rz7!kLm2Qp", "verify-rs.acme-corp.com.tr", "10.42.7.15",
                 "app-srv-01.prod.acme-corp.com.tr", "B4s1c#Auth2026",
                 "dis-servis.acme-corp.com.tr", "//dis-servis:", "Pg#Dflt2026x"]
YAML_ONLY_MUST_NOT_LEAK = ["svc_orders_basic", "odeme.acme-corp.com.tr",
                           "nested.acme-corp.com.tr", "pg-main.db.acme-corp.com.tr"]

READABLE = {
    "user_keys.yaml": ["_MYCUSTOMPASSWORD: RDX_SECRET_", "/api/v1/verify", ":8443",
                       "${_DIS_SERVIS:http://RDX_HOST_", ":8080/dis/api}",
                       "${_DIS_SERVIS_LOCAL:http://RDX_HOST_", "dbPassword: ${DB_PASSWORD:RDX_SECRET_",
                       "dbPasswordRef: ${DB_PASSWORD}", "logLevel: ${LOG_LEVEL:info}",
                       "basicAuthenticationEnabled: true", "authorizationUrl: ${AUTH_URL}",
                       "serviceClass: com.acme.orders.OrderService",
                       "homepage_url: https://github.com/acme/orders",
                       "callbackUrl: http://127.0.0.1:3000/callback", "port: 8080",
                       "jdbc:postgresql://RDX_HOST_", ":5432/orders", "${OUTER:${INNER:https://RDX_HOST_"],
    "user_keys.env": ["DIS_SERVIS=${_DIS_SERVIS:-http://RDX_HOST_", "LOG_LEVEL=${LOG_LEVEL:-info}",
                      "DB_PASSWORD=${DB_PASSWORD:-RDX_SECRET_", "SERVER_PORT=8080"],
    "user_keys.properties": ["dis.servis=${_DIS_SERVIS:http://RDX_HOST_",
                             "spring.datasource.password=${DB_PASSWORD:RDX_SECRET_",
                             "logging.level.root=${LOG_LEVEL:info}", "server.port=8080"],
}


@pytest.mark.parametrize("name", FILES)
def test_user_keys_do_not_leak(redactor, fixtures, name):
    out = redactor.tokenize(fixtures[name])
    extra = YAML_ONLY_MUST_NOT_LEAK if name.endswith(".yaml") else []
    for s in MUST_NOT_LEAK + extra:
        assert s not in out, f"{s!r} leaked from {name}:\n{out}"


@pytest.mark.parametrize("name", FILES)
def test_user_keys_stay_readable(redactor, fixtures, name):
    out = redactor.tokenize(fixtures[name])
    for s in READABLE[name]:
        assert s in out, f"{s!r} missing from {name}:\n{out}"


@pytest.mark.parametrize("name", FILES)
def test_user_keys_roundtrip(redactor, fixtures, name):
    out = redactor.tokenize(fixtures[name])
    back, withheld = redactor.restore(out, ALL_CLASSES)
    assert back == fixtures[name] and not withheld


def test_same_host_same_token_across_formats(redactor, fixtures):
    outs = [redactor.tokenize(fixtures[n]) for n in FILES]
    import re
    toks = [re.search(r"verify|RDX_HOST_[0-9a-f]{12}(?=/api/v1/verify)", o).group(0) for o in outs]
    assert len(set(toks)) == 1 and toks[0].startswith("RDX_HOST_")


def test_single_label_host_only_replaced_where_used_as_host(redactor):
    out = redactor.tokenize("eureka.client.serviceUrl.defaultZone: http://eureka:8761/eureka/")
    assert out.startswith("eureka.client.") and out.endswith(":8761/eureka/")
    assert "http://RDX_HOST_" in out


def test_edit_with_placeholder_default_lands_real_value(redactor, fixtures):
    """Claude edits the tokenized YAML; the file tool restores real values on disk."""
    red = redactor.tokenize(fixtures["user_keys.yaml"])
    edited = red.replace(":8080/dis/api}", ":8080/dis/api/v2}", 1)
    back, _ = redactor.restore(edited, ALL_CLASSES)
    assert "${_DIS_SERVIS:http://dis-servis.acme-corp.com.tr:8080/dis/api/v2}" in back


@pytest.mark.parametrize("line", [
    "upstream_proxy=up.url, proxy_auth=None",
    "up, creds = U.detect(s.corp_url, own)",
    "dc.internal_domains = list(d['internal_domains'])",
    "serviceUrl = cfg.server",
    "proxy_timeout: 30",
    "endpointClass: com.acme.api.Endpoint",
    "server_config_file: application.yml",
])
def test_code_and_settings_not_mistaken_for_hosts(redactor, line):
    assert redactor.tokenize(line) == line
