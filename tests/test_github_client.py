from __future__ import annotations

import io
import json
import urllib.error

import pytest

from risco.github.client import Client, parse_next_link


class FakeResponse:
    def __init__(self, status=200, payload=b"", headers=None):
        self.status = status
        self.payload = payload if isinstance(payload, bytes) else payload.encode()
        self.headers = headers or {}

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_parse_next_link():
    header = '<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=9>; rel="last"'
    assert parse_next_link(header) == "https://api.github.com/x?page=2"
    assert parse_next_link("") is None
    assert parse_next_link('<https://x>; rel="prev"') is None


def test_rate_limit_backoff_then_success(monkeypatch):
    c = Client(token="t", max_retries=3, sleep=lambda s: None)
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.HTTPError(
                req.full_url, 403, "rate limited",
                hdrs={"X-RateLimit-Remaining": "0", "Retry-After": "1"},
                fp=io.BytesIO(b"{}"),
            )
        return FakeResponse(200, '{"ok": true}')

    import risco.github.client as gc

    monkeypatch.setattr(gc.urllib.request, "urlopen", fake_urlopen)
    out = c.request("GET", "/x")
    assert out == {"ok": True}
    assert calls["n"] == 2


def test_4xx_raises_after_retries(monkeypatch):
    c = Client(token="t", max_retries=1, sleep=lambda s: None)

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 422, "nope", hdrs={}, fp=io.BytesIO(b'{"message":"bad"}'))

    import risco.github.client as gc

    monkeypatch.setattr(gc.urllib.request, "urlopen", fake_urlopen)
    from risco.errors import GithubApiError

    with pytest.raises(GithubApiError) as ei:
        c.request("GET", "/x")
    assert ei.value.status == 422
