from __future__ import annotations

import json
import re
from typing import Any

import yaml

_PATH_PARAM_RE = re.compile(r"\{[^}/]+\}")


def load_openapi_text(text: str, filename: str = "") -> dict[str, Any]:
    stripped = text.lstrip()
    if filename.endswith(".json") or stripped.startswith("{"):
        return json.loads(text)
    doc = yaml.safe_load(text)
    return doc if isinstance(doc, dict) else {}


def template_to_regex(template: str) -> re.Pattern[str]:
    parts = template.split("/")
    out = []
    for p in parts:
        if _PATH_PARAM_RE.fullmatch(p):
            out.append("[^/]+")
        else:
            out.append(re.escape(p))
    return re.compile("^" + "/".join(out) + "$")


def structural_template(template: str) -> tuple[tuple[int, str], ...]:
    segs = []
    for i, p in enumerate(template.strip().split("/")):
        if _PATH_PARAM_RE.fullmatch(p):
            segs.append((i, "*"))
        else:
            segs.append((i, p))
    return tuple(segs)


def templates_compatible(a: str, b: str) -> bool:
    sa, sb = structural_template(a), structural_template(b)
    return len(sa) == len(sb) and all(x[1] == y[1] or (x[1] == "*" and y[1] == "*") or x[1] == y[1] for x, y in zip(sa, sb))


def template_specificity(template: str) -> int:
    literal = sum(1 for p in template.split("/") if not _PATH_PARAM_RE.fullmatch(p))
    return literal


def iter_operations(doc: dict[str, Any]) -> list[dict[str, Any]]:
    methods = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    out: list[dict[str, Any]] = []
    paths = doc.get("paths") or {}
    for path, item in sorted(paths.items()):
        if not isinstance(item, dict):
            continue
        for method in sorted(methods & set(k.lower() for k in item.keys())):
            raw_key = next(k for k in item.keys() if k.lower() == method)
            op = item.get(raw_key) or {}
            if not isinstance(op, dict):
                continue
            refs: set[str] = set()
            collect_refs(op, refs)
            params = item.get("parameters") or []
            collect_refs({"parameters": params}, refs)
            out.append(
                {
                    "method": method.upper(),
                    "path_template": path,
                    "operation_id": op.get("operationId") or "",
                    "refs": refs,
                }
            )
    return out


def collect_refs(node: Any, into: set[str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str):
                into.add(v.split("/")[-1])
            else:
                collect_refs(v, into)
    elif isinstance(node, list):
        for v in node:
            collect_refs(v, into)


def proto_services(proto_text: str) -> list[tuple[str, str]]:
    services: list[tuple[str, str]] = []
    lines = proto_text.splitlines()
    current_service: str | None = None
    depth_in_service = False
    brace_depth = 0
    for line in lines:
        stripped = line.strip()
        m = re.match(r"service\s+(\w+)\s*\{", stripped)
        if m and current_service is None:
            current_service = m.group(1)
            brace_depth = stripped.count("{") - stripped.count("}")
            continue
        if current_service is not None:
            brace_depth += stripped.count("{") - stripped.count("}")
            rpc = re.match(r"rpc\s+(\w+)\s*\(", stripped)
            if rpc:
                services.append((current_service, rpc.group(1)))
            if brace_depth <= 0:
                current_service = None
                depth_in_service = False
    del depth_in_service
    return services


def proto_package(proto_text: str) -> str:
    m = re.search(r"^\s*package\s+([\w.]+)\s*;", proto_text, flags=re.M)
    return m.group(1) if m else ""
