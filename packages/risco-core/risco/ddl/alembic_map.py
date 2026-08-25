from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from risco.ddl.sqlrules import (
    RuleHit,
    extract_typesign_from_str,
    hit,
    is_widening,
)
from risco.errors import ParseFailure

SA_TYPE_MAP = {
    "String": "varchar",
    "VARCHAR": "varchar",
    "Text": "text",
    "INTEGER": "int4",
    "Integer": "int4",
    "INT": "int4",
    "BIGINT": "int8",
    "BigInteger": "int8",
    "SMALLINT": "int2",
    "SmallInteger": "int2",
    "NUMERIC": "numeric",
    "Numeric": "numeric",
    "DECIMAL": "numeric",
    "Float": "float8",
    "FLOAT": "float8",
    "DOUBLE_PRECISION": "float8",
    "BOOLEAN": "bool",
    "Boolean": "bool",
    "DateTime": "timestamp",
    "TIMESTAMP": "timestamp",
    "DATE": "date",
}

OP_RULE_MAP = {
    "drop_table": "R-DDL-001",
    "drop_column": "R-DDL-002",
    "rename_table": "R-DDL-003",
    "rename_column": "R-DDL-003",
    "create_index": "R-DDL-007",
    "create_foreign_key": "R-DDL-008",
    "drop_index": "R-DDL-013",
}


@dataclass
class AlembicAnalysis:
    hits: list[RuleHit]
    executed_sql: list[tuple[str, int]]
    unmapped_ops: list[tuple[str, int]]


def _call_name(node: ast.Call) -> tuple[str | None, str | None]:
    f = node.func
    if isinstance(f, ast.Attribute):
        obj = f.value
        base = obj.id if isinstance(obj, ast.Name) else None
        return base, f.attr
    if isinstance(f, ast.Name):
        return None, f.id
    return None, None


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _kw(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _type_repr(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        base = SA_TYPE_MAP.get(node.func.attr)
        if base is None:
            return node.func.attr.lower()
        length = None
        precision = None
        scale = None
        if node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, int):
                length = first.value
        for kw in node.keywords:
            if kw.arg == "length" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                length = kw.value.value
            if kw.arg == "precision" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                precision = kw.value.value
            if kw.arg == "scale" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                scale = kw.value.value
        if base == "numeric" and precision is not None:
            return f"numeric({precision},{scale or 0})"
        if base in ("varchar", "bpchar") and length is not None:
            return f"{base}({length})"
        return base
    if isinstance(node, ast.Attribute):
        return SA_TYPE_MAP.get(node.attr, node.attr.lower())
    return None


def _truthy(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and bool(node.value)


def _arg_str(node: ast.Call, index: int) -> str:
    if len(node.args) > index:
        s = _const_str(node.args[index])
        if s is not None:
            return s
    return ""


def map_alembic(source: str, path_for_errors: str = "<migration>") -> AlembicAnalysis:
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        raise ParseFailure(path_for_errors, f"python syntax error: {e.msg}") from e
    hits: list[RuleHit] = []
    executed: list[tuple[str, int]] = []
    unmapped: list[tuple[str, int]] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            base, attr = _call_name(node)
            if base == "op" and attr:
                self._handle_op(attr, node)
            self.generic_visit(node)

        def _line(self, node: ast.Call) -> int:
            return getattr(node, "lineno", 1)

        def _handle_op(self, attr: str, node: ast.Call) -> None:
            line = self._line(node)
            if attr == "execute":
                sql = _const_str(_first_arg(node))
                if sql is not None:
                    executed.append((sql, line))
                else:
                    unmapped.append(("execute(non-literal)", line))
                return
            if attr in ("add_column",):
                table = _arg_str(node, 0)
                col_node = node.args[1] if len(node.args) > 1 else None
                cname = ""
                nullable = True
                server_default = None
                if isinstance(col_node, ast.Call):
                    cname = _arg_str(col_node, 0)
                    nk = _kw(col_node, "nullable")
                    if nk is not None and isinstance(nk, ast.Constant):
                        nullable = bool(nk.value)
                    server_default = _kw(col_node, "server_default")
                sd_volatile = False
                if server_default is not None:
                    txt = _const_str(server_default)
                    if txt is None and isinstance(server_default, ast.Call):
                        txt = _const_str(_first_arg(server_default))
                    if isinstance(txt, str):
                        low = txt.strip().lower()
                        sd_volatile = any(
                            fn in low
                            for fn in (
                                "now()",
                                "current_timestamp",
                                "gen_random_uuid",
                                "random(",
                                "clock_timestamp",
                                "nextval",
                                "uuid_generate_v4",
                            )
                        )
                if not nullable and server_default is None:
                    hits.append(hit("R-DDL-005", line, table=table, column=cname))
                if server_default is not None and sd_volatile:
                    hits.append(hit("R-DDL-006", line, table=table, column=cname))
                return
            if attr == "alter_column":
                table = _arg_str(node, 0)
                column = _arg_str(node, 1)
                new_type = _type_repr(_kw(node, "type_") or (node.args[3] if len(node.args) > 3 and isinstance(node.args[3], (ast.Call, ast.Attribute)) else None))
                existing = _type_repr(_kw(node, "existing_type"))
                nullable_kw = _kw(node, "nullable")
                if new_type and existing:
                    oldsig = extract_typesign_from_str(existing)
                    newsig = extract_typesign_from_str(new_type)
                    rule = "R-DDL-004a" if is_widening(oldsig, newsig) else "R-DDL-004"
                    hits.append(hit(rule, line, table=table, column=column, new_type=new_type))
                elif new_type:
                    hits.append(hit("R-DDL-004", line, table=table, column=column, new_type=new_type))
                if nullable_kw is not None and isinstance(nullable_kw, ast.Constant) and nullable_kw.value is False:
                    hits.append(hit("R-DDL-009", line, table=table, column=column))
                return
            if attr in OP_RULE_MAP:
                rule_id = OP_RULE_MAP[attr]
                if attr == "drop_table":
                    hits.append(hit(rule_id, line, table=_arg_str(node, 0)))
                elif attr == "drop_column":
                    hits.append(hit(rule_id, line, table=_arg_str(node, 0), column=_arg_str(node, 1)))
                elif attr in ("rename_table", "rename_column"):
                    names = [_arg_str(node, i) for i in range(min(3, len(node.args)))]
                    hits.append(hit(rule_id, line, table=" -> ".join(names)))
                elif attr == "create_index":
                    concurrently = _truthy(_kw(node, "postgresql_concurrently"))
                    if not concurrently:
                        hits.append(hit(rule_id, line, table=_arg_str(node, 1), index=_arg_str(node, 0)))
                elif attr == "create_foreign_key":
                    hits.append(
                        hit(
                            rule_id,
                            line,
                            table=_arg_str(node, 0),
                            referenced_table=_arg_str(node, 3),
                        )
                    )
                elif attr == "drop_index":
                    concurrently = _truthy(_kw(node, "postgresql_concurrently"))
                    if not concurrently:
                        hits.append(hit(rule_id, line, index=_arg_str(node, 0)))
                return
            unmapped.append((attr, line))

    V().visit(tree)
    return AlembicAnalysis(hits=hits, executed_sql=executed, unmapped_ops=unmapped)


def _first_arg(node: ast.Call) -> ast.AST | None:
    return node.args[0] if node.args else None


_PROTO_RPC_RE = re.compile(r"rpc\s+(\w+)\s*\(")
