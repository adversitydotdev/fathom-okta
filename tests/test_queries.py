"""Query sources (OGRL RFC 0006) over the bundled Okta description: common queries validate.

Static only: no network. Catches a description that stops loading, or an Okta release
that renames something these queries rely on, before the package ships.
"""

from pathlib import Path

import pytest
import yaml
from ogrl_integration import openapi

ROOT = Path(__file__).parents[1]
BLOCK = yaml.safe_load((ROOT / "manifest.yaml").read_text())["openapi"]
DESCRIPTION = openapi.Description(yaml.safe_load((ROOT / BLOCK["description"]).read_text()))
SETTINGS = openapi.Settings.from_json(BLOCK)

QUERIES = {
    "applications": openapi.Query(
        "listApplications",
        params={"limit": "200"},
        fields={"id": "id", "name": "label", "status": "status", "sign_on_mode": "signOnMode"},
    ),
    "password policies": openapi.Query(
        "listPolicies",
        params={"type": "PASSWORD"},
        fields={
            "id": "id",
            "name": "name",
            "status": "status",
            "min_length": "settings.password.complexity.minLength",
            "max_age_days": "settings.password.age.maxAgeDays",
        },
    ),
    "sign-on policies": openapi.Query(
        "listPolicies",
        params={"type": "OKTA_SIGN_ON"},
        fields={"id": "id", "name": "name", "status": "status", "priority": "priority"},
    ),
    "members of each group": openapi.Query(
        "listGroupUsers",
        fields={"id": "id", "name": "profile.login", "status": "status", "group": "$parent.profile.name"},
        for_each=openapi.ForEach("listGroups", bind={"groupId": "id"}),
    ),
    "groups": openapi.Query("listGroups", fields={"id": "id", "name": "profile.name", "type": "type"}),
}


@pytest.mark.parametrize("label", sorted(QUERIES))
def test_common_queries_validate(label):
    problems, schema = openapi.validate(DESCRIPTION, SETTINGS, QUERIES[label])
    assert [p for p in problems if not p.warning] == []
    assert schema and set(QUERIES[label].fields) <= set(schema["properties"])


def test_writes_cannot_be_queried():
    problems, _ = openapi.validate(DESCRIPTION, SETTINGS, openapi.Query("deactivateUser", params={"id": "x"}))
    assert "only reads" in problems[0].detail
