from pathlib import Path

from ogrl_integration.testing import Cassette, Harness

from okta_integration import app
from tests.rules import evaluate, template

CONFIG = {"domain": "acme.okta.com"}


def test_mfa_template_selects_interactive_accounts_and_requires_strong_factors():
    app.transport = Cassette(Path(__file__).parent / "cassettes" / "users.json")
    users = Harness(app).collect("users", 1, CONFIG, {"OKTA_API_TOKEN": "t"}).items
    selected, failing, _ = evaluate(template("mfa-enforcement"), users)
    assert selected == ["00u1admin", "00u2dev", "00u3sms", "00u4ops"]  # not the suspended one
    assert failing == ["00u3sms"]
