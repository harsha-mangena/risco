from __future__ import annotations

from typing import Any

from risco.contract.openapi_doc import iter_operations
from risco.models import ContractChange, OperationRef

OAS_PREFIX = "OAS-"
BUF_PREFIX = "BUF-"

SCHEMA_PATH_MARKERS = ("#/components/schemas/", "#/definitions/", "#/components/parameters/")


def normalize_oasdiff(items: list[dict[str, Any]], head_doc: dict[str, Any] | None) -> list[ContractChange]:
    ops = iter_operations(head_doc) if head_doc else []
    schema_to_ops: dict[str, list[dict[str, Any]]] = {}
    for op in ops:
        for ref in op["refs"]:
            schema_to_ops.setdefault(ref, []).append(op)

    changes: list[ContractChange] = []
    seen: set[tuple] = set()
    for item in items:
        rule_id = OAS_PREFIX + str(item.get("id", "unknown"))
        path = str(item.get("path", "") or "")
        method = (
            str(item.get("method", "") or "").lower()
            or str(item.get("operation", "") or "").lower()
            or None
        )
        prop = str(item.get("property", "") or "")
        description = str(item.get("text", "") or item.get("description", "") or "")
        breaking = bool(item.get("breaking", False))

        operation = OperationRef(method=method.upper() if method else None, path_template=path or None)

        if any(path.startswith(m) for m in SCHEMA_PATH_MARKERS) or not method:
            schema_name = path.rsplit("/", 1)[-1].replace(".properties", "").strip("~")
            refs_ops = schema_to_ops.get(schema_name, [])
            if refs_ops:
                for op in refs_ops:
                    ch = ContractChange(
                        source="OPENAPI",
                        operation=OperationRef(method=op["method"], path_template=op["path_template"], operation_id=op["operation_id"] or None),
                        change_id=rule_id,
                        breaking=breaking,
                        description=description,
                    )
                    k = (ch.change_id, ch.operation.key(), description)
                    if k not in seen:
                        seen.add(k)
                        changes.append(ch)
                if not breaking and not refs_ops:
                    continue
                continue
            ch = ContractChange(
                source="OPENAPI",
                operation=OperationRef(),
                change_id=rule_id,
                breaking=breaking,
                description=f"{description} ({path})".strip(),
            )
            k = (ch.change_id, "", description)
            if k not in seen:
                seen.add(k)
                changes.append(ch)
            continue

        op_id = str(item.get("operationId", "") or "") or _find_operation_id(ops, method, path)
        operation.operation_id = op_id
        ch = ContractChange(
            source="OPENAPI",
            operation=operation,
            change_id=rule_id,
            breaking=breaking,
            description=(f"{prop}: {description}" if prop and prop not in description else description),
        )
        k = (ch.change_id, ch.operation.key(), description)
        if k not in seen:
            seen.add(k)
            changes.append(ch)

    changes.sort(key=lambda c: (c.change_id, c.operation.key(), c.description))
    return changes


def _find_operation_id(ops: list[dict[str, Any]], method: str | None, template: str | None) -> str | None:
    if not method or not template:
        return None
    for op in ops:
        if op["method"].lower() == method.lower() and op["path_template"] == template:
            return op["operation_id"] or None
    return None


def normalize_buf(items: list[dict[str, Any]]) -> list[ContractChange]:
    changes = []
    for item in items:
        rule = BUF_PREFIX + str(item.get("type", "UNKNOWN"))
        path = str(item.get("path", "") or "")
        field_desc = ", ".join(
            str(v) for k, v in sorted(item.items()) if k not in {"type", "path"} and v
        )
        changes.append(
            ContractChange(
                source="PROTOBUF",
                operation=OperationRef(rpc=str(item.get("field", "") or "") or None),
                change_id=rule,
                breaking=True,
                description=f"{path}: {field_desc}".rstrip(": ").strip(),
            )
        )
    changes.sort(key=lambda c: (c.change_id, c.operation.rpc or ""))
    return changes
