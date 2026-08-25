from __future__ import annotations

import datetime as _dt
import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any


def to_jsonable(obj: Any) -> Any:
    model_dump = getattr(obj, "model_dump", None)
    if model_dump is not None and hasattr(obj, "__dict__") and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in obj.model_dump(mode="json").items()}
    if isinstance(obj, _dt.datetime | _dt.date):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return to_jsonable(obj.value)
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, set):
        return sorted((to_jsonable(x) for x in obj), key=canonical_json)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            raise ValueError(f"non-finite float not allowed in canonical JSON: {obj}")
        return obj
    return obj


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        to_jsonable(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json(obj: Any) -> str:
    return canonical_bytes(obj).decode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def stable_hash(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))
