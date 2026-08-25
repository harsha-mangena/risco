from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

from risco.errors import ToolUnavailable


def find_buf() -> str | None:
    explicit = os.environ.get("RISCO_BUF_BIN")
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    return shutil.which("buf")


def buf_version(binary: str) -> str:
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=20, check=False)
        return (out.stdout or out.stderr).strip() or "unknown"
    except Exception:
        return "unknown"


def diff_proto(base_dir: str, head_dir: str, binary: str | None = None) -> list[dict[str, Any]]:
    binary = binary or find_buf()
    if not binary:
        raise ToolUnavailable("buf", "binary not found on PATH")
    cmd = [binary, "breaking", "--against", os.path.abspath(base_dir), "--error-format", "json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False, cwd=os.path.abspath(head_dir))
    except FileNotFoundError:
        raise ToolUnavailable("buf")
    items: list[dict[str, Any]] = []
    text = proc.stdout.strip()
    if text:
        try:
            data = json.loads(text)
            items = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    if proc.returncode not in (0, 100):
        if not items:
            raise RuntimeError(f"buf breaking failed rc={proc.returncode}: {proc.stderr[:400]}")
    return items
