from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from risco.errors import GithubApiError

API_ROOT = "https://api.github.com"
UPLOAD_ROOT = "https://uploads.github.com"


class Client:
    def __init__(self, token: str, api_root: str = API_ROOT, max_retries: int = 4, sleep=time.sleep):
        self.token = token
        self.api_root = api_root.rstrip("/")
        self.max_retries = max_retries
        self._sleep = sleep

    def _raw(self, method: str, url: str, body: Optional[bytes], headers: dict[str, str], timeout: int = 30):
        attempt = 0
        while True:
            req = urllib.request.Request(url, data=body, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.status, resp.read(), dict(resp.headers)
            except urllib.error.HTTPError as e:
                payload = e.read()
                rate_limited = e.code == 403 and e.headers.get("X-RateLimit-Remaining") == "0"
                retry_after = e.headers.get("Retry-After")
                retriable = e.code in (500, 502, 503, 504)
                if attempt < self.max_retries and (retriable or (rate_limited and retry_after)):
                    delay = int(retry_after) if retry_after else min(2**attempt, 30)
                    self._sleep(min(delay, 60))
                    attempt += 1
                    continue
                detail = payload.decode("utf-8", "replace")[:500]
                raise GithubApiError(e.code, detail, rate_limited=rate_limited) from e
            except urllib.error.URLError as e:
                if attempt < self.max_retries:
                    self._sleep(min(2**attempt, 30))
                    attempt += 1
                    continue
                raise GithubApiError(0, str(e)) from e

    def request(
        self,
        method: str,
        path: str,
        body: Optional[dict | list] = None,
        accept: str = "application/vnd.github+json",
    ) -> Any:
        url = path if path.startswith("http") else f"{self.api_root}{path}"
        headers = {
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "risco-action",
            **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
        }
        raw_body = json.dumps(body).encode() if body is not None else None
        if raw_body:
            headers["Content-Type"] = "application/json"
        status, payload, _ = self._raw(method, url, raw_body, headers)
        if status == 204 or not payload:
            return {}
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return {}

    def request_binary(self, url: str, accept: str = "application/octet-stream") -> bytes:
        headers = {
            "Accept": accept,
            "User-Agent": "risco-action",
            **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
        }
        _, payload, _ = self._raw("GET", url, None, headers, timeout=120)
        return payload

    def request_with_headers(self, method: str, path: str, body: Optional[dict | list] = None):
        url = path if path.startswith("http") else f"{self.api_root}{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "risco-action",
            **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
        }
        raw_body = json.dumps(body).encode() if body is not None else None
        if raw_body:
            headers["Content-Type"] = "application/json"
        status, payload, hdrs = self._raw(method, url, raw_body, headers)
        self._link_cache[url] = hdrs.get("Link", "")
        if status == 204 or not payload:
            return {}
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return {}

    def get_paginated2(self, path: str, per_page: int = 100, cap_pages: int = 25) -> list:
        out: list = []
        sep = "&" if "?" in path else "?"
        url: Optional[str] = f"{self.api_root}{path}{sep}per_page={per_page}"
        pages = 0
        while url and pages < cap_pages:
            resp = self.request_with_headers("GET", url)
            if not isinstance(resp, list):
                break
            out.extend(resp)
            next_url = parse_next_link(self._link_cache.get(url, ""))
            pages += 1
            url = next_url
        return out


def parse_next_link(link_header: str) -> Optional[str]:
    if not link_header:
        return None
    for part in link_header.split(","):
        segs = [s.strip() for s in part.split(";")]
        if len(segs) < 2:
            continue
        if any(rel.strip() == 'rel="next"' for rel in segs[1:]):
            return segs[0].strip("<>")
    return None


