from __future__ import annotations

import datetime as dt

from risco.canonical import canonical_bytes, canonical_json, sha256_hex, stable_hash, to_jsonable
from risco.models import Finding, Location, Severity


def test_key_order_and_whitespace_independence():
    a = {"b": 1, "a": {"y": 2, "x": 3}}
    b = {"a": {"x": 3, "y": 2}, "b": 1}
    assert canonical_json(a) == canonical_json(b)
    assert canonical_json(a) == '{"a":{"x":3,"y":2},"b":1}'


def test_pydantic_enum_datetime():
    f = Finding(
        id="R-DDL-001",
        category="DDL",
        severity=Severity.HIGH,
        title="DROP TABLE",
        location=Location(repo="r", path="m.sql", line_start=1, line_end=1),
    )
    data = json.loads if False else None
    text = canonical_json(f)
    assert '"severity":"HIGH"' in text
    obj = __import__("json").loads(text)
    assert obj["category"] == "DDL"


def test_stable_hash_deterministic():
    h1 = stable_hash({"x": [1, 2], "y": "z"})
    h2 = stable_hash({"y": "z", "x": [1, 2]})
    assert h1 == h2 == sha256_hex(b'{"x":[1,2],"y":"z"}')


def test_datetime_iso():
    payload = {"t": dt.datetime(2026, 8, 25, 12, 0, 0, tzinfo=dt.timezone.utc)}
    assert canonical_json(payload) == '{"t":"2026-08-25T12:00:00+00:00"}'


def test_nonfinite_rejected():
    import pytest

    with pytest.raises(ValueError):
        canonical_bytes(float("nan"))
