from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any

from risco.errors import ToolUnavailable


def find_oasdiff() -> str | None:
    explicit = os.environ.get("RISCO_OASDIFF_BIN")
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    return shutil.which("oasdiff")


def oasdiff_version(binary: str) -> str:
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=20, check=False
        )
        v = (out.stdout or out.stderr).strip().splitlines()
        return v[-1] if v else "unknown"
    except Exception:
        return "unknown"


def _run_json(cmd: list[str]) -> list[dict[str, Any]]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except FileNotFoundError:
        raise ToolUnavailable(cmd[0])
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"{cmd[0]} failed rc={proc.returncode}: {proc.stderr[:400]}")
    text = proc.stdout.strip() or "[]"
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{cmd[0]} produced invalid JSON: {e}") from e
    if isinstance(data, dict):
        data = [data]
    return [item for item in data if isinstance(item, dict)]


def diff_openapi(base_text: str, head_text: str, binary: str | None = None) -> list[dict[str, Any]]:
    binary = binary or find_oasdiff()
    if not binary:
        raise ToolUnavailable("oasdiff", "binary not found on PATH")
    with tempfile.TemporaryDirectory(prefix="risco-oas-") as td:
        base_p = os.path.join(td, "base.yaml")
        head_p = os.path.join(td, "head.yaml")
        with open(base_p, "w") as f:
            f.write(base_text)
        with open(head_p, "w") as f:
            f.write(head_text)
        breaking_items = _run_json([binary, "breaking", base_p, head_p, "--format", "json"])
        changelog_items = _run_json([binary, "changelog", base_p, head_p, "--format", "json"])
    breaking_keys = {
        _item_key(i)
        for i in breaking_items
    }
    merged: dict[tuple, dict[str, Any]] = {}
    for item in changelog_items + breaking_items:
        key = _item_key(item)
        level = int(item.get("level", 3) or 3)
        is_breaking = key in breaking_keys or level <= 2
        rec = dict(item)
        rec["breaking"] = is_breaking
        merged[key] = rec
    return sorted(merged.values(), key=lambda i: (_item_key(i),))


def _item_key(item: dict[str, Any]) -> tuple:
    return (
        str(item.get("id", "")),
        str(item.get("path", "")),
        str(item.get("method", "")).lower(),
        str(item.get("property", "") or ""),
        str(item.get("status", "") or ""),
        int(item.get("level", 0) or 0),
    )
