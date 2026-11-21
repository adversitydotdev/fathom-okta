"""Okta collection, validation, and the admin check, against replayed Okta API responses.

Cassettes are written from Okta's documented response shapes
(https://developer.okta.com/docs/api/openapi/okta-management/), not recorded
from a live org.
"""

from pathlib import Path

import pytest
from ogrl_integration.http import Request, Response
from ogrl_integration.testing import Cassette, Harness, HarnessError

from okta_integration import app

CASSETTES = Path(__file__).parent / "cassettes"
CONFIG = {"domain": "acme.okta.com"}
TOKEN = {"OKTA_API_TOKEN": "00token"}


@pytest.fixture(autouse=True)
def no_wait(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _s: None)


def tape(name: str) -> Cassette:
    app.transport = Cassette(CASSETTES / f"{name}.json")
    return app.transport


def by_id(items):
    return {i["id"]: i for i in items}


def test_users_carry_factors_and_admin_roles():
    tape("users")
    result = Harness(app).collect("users", 1, CONFIG, TOKEN)
    assert result.complete
    users = by_id(result.items)
    assert list(users) == ["00u1admin", "00u2dev", "00u3sms", "00u4ops", "00u5gone"]

    ada = users["00u1admin"]
    assert (ada["name"], ada["admin"], ada["phishing_resistant"], ada["strong_mfa"]) == (
        "ada@acme.test",
        True,
        True,
        True,
    )
    assert ada["mfa_factors"] == ["push", "webauthn"]

    assert (users["00u2dev"]["strong_mfa"], users["00u2dev"]["phishing_resistant"]) == (True, False)
    # SMS is MFA, but not strong; the security question is not MFA at all.
    assert (users["00u3sms"]["mfa_enrolled"], users["00u3sms"]["strong_mfa"]) == (True, False)
    # A pending WebAuthn enrolment does not count.
    assert (users["00u4ops"]["admin"], users["00u4ops"]["phishing_resistant"]) == (True, False)
    assert users["00u5gone"]["mfa_enrolled"] is False


def test_groups_list_members_across_pages():
    tape("groups")
    groups = by_id(Harness(app).collect("groups", 1, CONFIG, TOKEN).items)
    assert groups["00g1eng"]["members"] == ["00u1admin", "00u2dev", "00u4ops"]
    assert groups["00g2every"]["group_type"] == "BUILT_IN"


def test_rate_limit_mid_collection_keeps_what_was_read():
    tape("rate-limited")
    result = Harness(app).collect("users", 1, CONFIG, TOKEN)
    assert (len(result.items), result.complete) == (2, False)
    assert "429" in result.reason


class Spy:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}

    def send(self, request: Request, timeout: float) -> Response:
        self.headers = request.headers
        return Response(200, {}, b'{"id": "00u9", "profile": {"login": "svc-ogrl@acme.test"}}')


@pytest.mark.parametrize(
    ("secrets", "header"),
    [(TOKEN, "SSWS 00token"), ({"OGRL_ACCESS_TOKEN": "eyJ.oauth"}, "Bearer eyJ.oauth")],
)
def test_validate_uses_an_api_token_or_the_oauth_token(secrets, header):
    app.transport = spy = Spy()
    identity = Harness(app).validate(CONFIG, secrets)
    assert identity["identity"] == "acme.okta.com as svc-ogrl@acme.test"
    assert spy.headers["Authorization"] == header


def test_validate_without_credentials_is_invalid_config():
    tape("me")
    with pytest.raises(HarnessError) as caught:
        Harness(app).validate(CONFIG, {})
    assert caught.value.kind == "invalid_config"


def test_admin_check_names_admins_without_phishing_resistant_mfa():
    tape("users")
    users = Harness(app).collect("users", 1, CONFIG, TOKEN).items
    out = Harness(app).check("admin-mfa-phishing-resistant", 1, {"dev.adversity.okta/users@1": users})
    assert out["outcome"] == "fail"
    assert out["summary"] == "1 of 2 active admins lack phishing-resistant MFA"
    assert out["subjects"] == [{"kind": "account", "name": "dee@acme.test", "external_id": "00u4ops"}]
