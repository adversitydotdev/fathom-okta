"""Evaluate this package's rule templates the way OGRL's rule runner does (RFC 0001 7.6).

A test aid only: OGRL owns the real runner. This catches a template that
names a field the resource never emits, or a select that matches nothing.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import cel
import yaml

MANIFEST = yaml.safe_load((Path(__file__).parents[1] / "manifest.yaml").read_text())


def template(name: str) -> dict[str, Any]:
    return next(t for t in MANIFEST["templates"] if t["name"] == name)["test"]["run"]


def evaluate(run: dict[str, Any], items: list[dict[str, Any]], params: dict[str, str] | None = None):
    """(selected ids, failing ids, aggregate) for one rule over snapshot items."""
    observed = datetime(2026, 11, 21, tzinfo=UTC)

    def context(**variables: Any) -> Any:
        ctx = cel.Context()
        ctx.add_function("duplicates", lambda xs: [x for i, x in enumerate(xs) if x in xs[:i]])
        ctx.add_function("days", lambda s: __import__("datetime").timedelta(days=int(s.split()[0])))
        for key, value in {"params": params or {}, "observed": observed, **variables}.items():
            ctx.add_variable(key, value)
        return ctx

    selected = [i for i in items if "select" not in run or cel.evaluate(run["select"], context(item=i))]
    failing = [
        i["id"] for i in selected if "assert" in run and not cel.evaluate(run["assert"], context(item=i))
    ]
    aggregate = cel.evaluate(run["aggregate"], context(items=selected)) if "aggregate" in run else True
    return [i["id"] for i in selected], failing, aggregate
