from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterator

from risco.errors import ParseFailure
from risco.models import Severity

try:
    import pglast
    from pglast import parse_sql
    from pglast import enums as pg_enums

    PGLAST_AVAILABLE = True
    PGLAST_VERSION = getattr(pglast, "__version__", "unknown")
except Exception:
    pglast = None
    parse_sql = None
    pg_enums = None
    PGLAST_AVAILABLE = False
    PGLAST_VERSION = "unavailable"


DDL_TAGS = {
    "DropStmt",
    "AlterTableStmt",
    "RenameStmt",
    "IndexStmt",
    "CreateStmt",
    "TruncateStmt",
    "AlterObjectDependsStmt",
    "AlterObjSpaceOptsStmt",
    "AlterOwnerStmt",
}

DML_TAGS = {"InsertStmt", "UpdateStmt", "DeleteStmt", "MergeStmt", "TruncateStmt"}


def loc_line(sql_text: str, location: Any) -> int:
    if isinstance(location, int) and 0 <= location < len(sql_text):
        return sql_text.count("\n", 0, location) + 1
    return 1


def _slots(obj: Any) -> Iterator[Any]:
    slots = getattr(obj, "__slots__", None)
    if not slots:
        return
    for s in slots:
        try:
            yield getattr(obj, s)
        except Exception:
            continue


def iter_nodes(node: Any) -> Iterator[Any]:
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur is None:
            continue
        yield cur
        for child in _slots(cur):
            if isinstance(child, list | tuple):
                stack.extend(reversed([c for c in child if c is not None and hasattr(c, "__slots__")]))
            elif child is not None and hasattr(child, "__slots__"):
                stack.append(child)


def node_name(node: Any, attr: str) -> str:
    val = getattr(node, attr, None)
    return _stringify_name(val)


def _stringify_name(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    parts: list[str] = []

    def rec(v: Any) -> None:
        sval = getattr(v, "sval", None)
        if isinstance(sval, str):
            parts.append(sval)
        elif isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list | tuple):
            for x in v:
                rec(x)

    rec(val)
    return ".".join(parts)


def relation_name(rv: Any) -> str:
    if rv is None:
        return ""
    schema = getattr(rv, "schemaname", None) or ""
    name = getattr(rv, "relname", None) or ""
    cat = getattr(rv, "catalogname", None) or ""
    full = ".".join(x for x in (cat, schema, name) if x)
    return full


def drop_objects(objects: Any) -> list[str]:
    names = []
    if isinstance(objects, list | tuple):
        for obj in objects:
            n = _stringify_name(obj)
            if n:
                names.append(n)
    return names


@dataclass(frozen=True)
class TypeSig:
    base: str
    length: int | None = None
    precision: int | None = None
    scale: int | None = None


_TYPE_ALIASES = {
    "smallint": "int2",
    "integer": "int4",
    "int": "int4",
    "bigint": "int8",
    "real": "float4",
    "double precision": "float8",
    "character varying": "varchar",
    "character": "bpchar",
    "decimal": "numeric",
    "time without time zone": "time",
    "timestamp without time zone": "timestamp",
    "timestamp with time zone": "timestamptz",
}


def normalize_type(name: str) -> str:
    n = name.strip().lower()
    return _TYPE_ALIASES.get(n, n)


_INT_ORDER = {"int2": 0, "int4": 1, "int8": 2}
_FLOAT_ORDER = {"float4": 0, "float8": 1}


def is_widening(src: TypeSig, dst: TypeSig) -> bool:
    a, b = src.base, dst.base
    if a == b:
        if a in ("varchar", "bpchar"):
            if dst.length is None:
                return True
            return src.length is not None and dst.length >= src.length
        if a == "numeric":
            if src.precision is None or dst.precision is None:
                return dst.precision is None
            if dst.precision < src.precision:
                return False
            ss = src.scale if src.scale is not None else 0
            ds = dst.scale if dst.scale is not None else 0
            return ds >= ss
        if a in ("timestamp", "timestamptz", "time"):
            sp = src.precision if src.precision is not None else 6
            dp = dst.precision if dst.precision is not None else 6
            return dp >= sp
        return True
    if a in ("varchar", "bpchar") and b == "text":
        return True
    if a in _INT_ORDER and b in _INT_ORDER:
        return _INT_ORDER[b] > _INT_ORDER[a]
    if a in _INT_ORDER and b == "numeric":
        return True
    if a in _FLOAT_ORDER and b in _FLOAT_ORDER:
        return _FLOAT_ORDER[b] > _FLOAT_ORDER[a]
    return False


def extract_typesign(typename_node: Any) -> TypeSig:
    names = getattr(typename_node, "names", None) or []
    base_raw = _stringify_name(names[-1]) if names else ""
    base = normalize_type(base_raw)
    length = None
    precision = None
    scale = None
    typmods = getattr(typename_node, "typmods", None) or []
    nums: list[int] = []
    for tm in typmods:
        arg = getattr(tm, "arg", None)
        val = getattr(getattr(arg, "val", None), "ival", None)
        if isinstance(val, int):
            nums.append(val)
    if base in ("varchar", "bpchar") and nums:
        length = nums[0]
    elif base in ("timestamp", "timestamptz", "time") and nums:
        precision = nums[0]
    elif base == "numeric":
        if len(nums) >= 1:
            precision = nums[0]
        if len(nums) >= 2:
            scale = nums[1]
    return TypeSig(base=base, length=length, precision=precision, scale=scale)


VOLATILE_FUNCTIONS = {
    "now",
    "current_timestamp",
    "clock_timestamp",
    "statement_timestamp",
    "transaction_timestamp",
    "random",
    "gen_random_uuid",
    "uuid_generate_v1",
    "uuid_generate_v4",
    "nextval",
}


def expr_has_volatile(expr: Any) -> bool:
    for node in iter_nodes(expr):
        if type(node).__name__ == "FuncCall":
            raw = getattr(node, "funcname", None) or getattr(node, "func", None)
            fname = _stringify_name(raw).lower()
            short = fname.rsplit(".", 1)[-1].rsplit("(", 1)[0]
            if short in VOLATILE_FUNCTIONS:
                return True
    return False


def stmt_sha(sql_text: str, start: int, end: int) -> str:
    chunk = sql_text[start:end] if start is not None else sql_text
    return hashlib.sha256(chunk.strip().encode()).hexdigest()[:16]


@dataclass
class ParsedFile:
    ok: bool
    error: str = ""
    statements: list[tuple[str, Any, int]] = field(default_factory=list)
    sql_text: str = ""


def parse_sql_file(sql_text: str) -> ParsedFile:
    if not PGLAST_AVAILABLE:
        return ParsedFile(ok=False, error="pglast unavailable", sql_text=sql_text)
    try:
        raw_stmts = parse_sql(sql_text)
    except Exception as e:
        msg = str(e).splitlines()[0][:200]
        return ParsedFile(ok=False, error=msg, sql_text=sql_text)
    stmts = []
    bounds = []
    for rs in raw_stmts:
        stmt = getattr(rs, "stmt", rs)
        loc = getattr(rs, "stmt_location", -1)
        if not isinstance(loc, int):
            loc = -1
        stmts.append((type(stmt).__name__, stmt, loc))
        bounds.append(loc)
    parsed = ParsedFile(ok=True, sql_text=sql_text)
    for i, (tag, stmt, loc) in enumerate(stmts):
        end = bounds[i + 1] if i + 1 < len(bounds) and bounds[i + 1] > loc >= 0 else len(sql_text)
        parsed.statements.append((tag, stmt, loc))
        del end
    return parsed
