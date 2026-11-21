"""Okta for OGRL (RFC 0005): users with MFA factors and admin roles, and groups with members.

Okta's management API: https://developer.okta.com/docs/api/openapi/okta-management/
Rate limits apply per endpoint; the SDK client backs off on 429 and honours
`X-Rate-Limit-Reset` through `Retry-After` when Okta sends it.
"""

from ogrl_integration import Integration, Subject, fail, pass_

app = Integration("dev.adversity.okta", "0.1.1")

ACTIVE = frozenset({"ACTIVE", "PASSWORD_EXPIRED", "LOCKED_OUT", "RECOVERY"})
PHISHING_RESISTANT = frozenset({"webauthn", "u2f", "signed_nonce"})
STRONG = PHISHING_RESISTANT | {"token:software:totp", "token:hardware", "token:hotp", "token"}
WEAK = frozenset({"email", "question"})
PAGE = 200


def _base(ctx) -> str:
    return f"https://{ctx.config['domain']}"


def _auth(ctx) -> dict[str, str]:
    """An API token (SSWS) or the OAuth access token the OGRL host refreshed."""
    if ctx.env.get("OKTA_API_TOKEN"):
        return {"Authorization": f"SSWS {ctx.secret('OKTA_API_TOKEN')}"}
    return {"Authorization": f"Bearer {ctx.access_token}"}


@app.validate
def validate(ctx):
    me = ctx.http.get(f"{_base(ctx)}/api/v1/users/me", headers=_auth(ctx)).json()
    login = me.get("profile", {}).get("login", me.get("id"))
    return ctx.identity(f"{ctx.config['domain']} as {login}")


def _admins(ctx) -> set[str]:
    """Users holding an admin role, from the IAM assignees list (paginated by _links.next)."""
    pages = ctx.http.paginate(
        f"{_base(ctx)}/api/v1/iam/assignees/users",
        params={"limit": PAGE},
        headers=_auth(ctx),
        items=lambda r: r.json().get("value", []),
        next_url=lambda r: r.json().get("_links", {}).get("next", {}).get("href"),
    )
    return {assignee["id"] for assignee in pages}


@app.resource("users", version=1)
def users(ctx):
    admins = _admins(ctx)
    count = 0
    for user in ctx.http.paginate(f"{_base(ctx)}/api/v1/users", params={"limit": PAGE}, headers=_auth(ctx)):
        factors = ctx.http.get(f"{_base(ctx)}/api/v1/users/{user['id']}/factors", headers=_auth(ctx)).json()
        active = sorted({f["factorType"] for f in factors if f.get("status") == "ACTIVE"})
        profile = user.get("profile", {})
        if count % 100 == 0:
            ctx.progress(count)
        yield {
            "id": user["id"],
            "name": profile.get("login", user["id"]),
            "email": profile.get("email"),
            "status": user["status"],
            "user_type": (user.get("type") or {}).get("id"),
            "created": user.get("created"),
            "last_login": user.get("lastLogin"),
            "password_changed": user.get("passwordChanged"),
            "admin": user["id"] in admins,
            "mfa_factors": active,
            "mfa_enrolled": any(f not in WEAK for f in active),
            "strong_mfa": any(f in STRONG for f in active),
            "phishing_resistant": any(f in PHISHING_RESISTANT for f in active),
        }


@app.resource("groups", version=1)
def groups(ctx):
    for group in ctx.http.paginate(f"{_base(ctx)}/api/v1/groups", params={"limit": PAGE}, headers=_auth(ctx)):
        members = ctx.http.paginate(
            f"{_base(ctx)}/api/v1/groups/{group['id']}/users",
            params={"limit": PAGE},
            headers=_auth(ctx),
        )
        profile = group.get("profile", {})
        yield {
            "id": group["id"],
            "name": profile.get("name", group["id"]),
            "description": profile.get("description"),
            "group_type": group.get("type", "OKTA_GROUP"),
            "members": [m["id"] for m in members],
        }


@app.check("admin-mfa-phishing-resistant", version=1)
def admin_mfa_phishing_resistant(ctx, users):
    admins = [u for u in users if u["admin"] and u["status"] in ACTIVE]
    weak = [u for u in admins if not u["phishing_resistant"]]
    if weak:
        return fail(
            f"{len(weak)} of {len(admins)} active admins lack phishing-resistant MFA",
            [Subject.account(u["name"], u["id"]) for u in weak],
        )
    return pass_(f"{len(admins)} active admins use phishing-resistant MFA")
