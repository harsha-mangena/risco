from __future__ import annotations

from dataclasses import dataclass, field

from risco.canonical import stable_hash
from risco.ddl.pgparse import (
    DDL_TAGS,
    DML_TAGS,
    drop_objects,
    expr_has_volatile,
    extract_typesign,
    is_widening,
    loc_line,
    node_name,
    normalize_type,
    parse_sql_file,
    relation_name,
)
from risco.models import Severity
from risco.policy.loader import PolicyError  # noqa: F401  (re-export guard)

RULE_TITLES = {
    "R-DDL-001": "DROP TABLE",
    "R-DDL-002": "DROP COLUMN",
    "R-DDL-003": "RENAME TABLE or RENAME COLUMN",
    "R-DDL-004": "ALTER COLUMN TYPE (non-widening)",
    "R-DDL-004a": "ALTER COLUMN TYPE (widening)",
    "R-DDL-005": "ADD COLUMN NOT NULL without DEFAULT",
    "R-DDL-006": "ADD COLUMN with volatile DEFAULT",
    "R-DDL-007": "CREATE INDEX without CONCURRENTLY",
    "R-DDL-008": "ADD FOREIGN KEY without NOT VALID",
    "R-DDL-009": "ALTER COLUMN SET NOT NULL",
    "R-DDL-010": "ADD CHECK/UNIQUE constraint without NOT VALID",
    "R-DDL-011": "Destructive DML in migration (TRUNCATE / DELETE / UPDATE without WHERE)",
    "R-DDL-012": "DDL and DML mixed in one migration file",
    "R-DDL-013": "DROP INDEX without CONCURRENTLY",
}

SEVERITY = {
    "R-DDL-001": Severity.HIGH,
    "R-DDL-002": Severity.HIGH,
    "R-DDL-003": Severity.HIGH,
    "R-DDL-004": Severity.HIGH,
    "R-DDL-004a": Severity.MEDIUM,
    "R-DDL-005": Severity.HIGH,
    "R-DDL-006": Severity.MEDIUM,
    "R-DDL-007": Severity.MEDIUM,
    "R-DDL-008": Severity.MEDIUM,
    "R-DDL-009": Severity.MEDIUM,
    "R-DDL-010": Severity.MEDIUM,
    "R-DDL-011": Severity.HIGH,
    "R-DDL-012": Severity.MEDIUM,
    "R-DDL-013": Severity.LOW,
}


@dataclass
class RuleHit:
    id: str
    severity: Severity
    title: str
    line: int
    details: dict = field(default_factory=dict)


def hit(rule_id: str, line: int, **details) -> RuleHit:
    return RuleHit(
        id=rule_id,
        severity=SEVERITY[rule_id],
        title=RULE_TITLES[rule_id],
        line=line,
        details=details,
    )


def _at_consts():
    from pglast import enums as E

    return {
        "AT_AddColumn": int(E.AlterTableType.AT_AddColumn),
        "AT_DropColumn": int(E.AlterTableType.AT_DropColumn),
        "AT_AlterColumnType": int(E.AlterTableType.AT_AlterColumnType),
        "AT_SetNotNull": int(E.AlterTableType.AT_SetNotNull),
        "AT_AddConstraint": int(E.AlterTableType.AT_AddConstraint),
    }


def _constr_consts():
    from pglast import enums as E

    return {
        "NOTNULL": int(E.ConstrType.CONSTR_NOTNULL),
        "DEFAULT": int(E.ConstrType.CONSTR_DEFAULT),
        "FK": int(E.ConstrType.CONSTR_FOREIGN),
        "CHECK": int(E.ConstrType.CONSTR_CHECK),
        "UNIQUE": int(E.ConstrType.CONSTR_UNIQUE),
    }


def _object_type_const(name: str) -> int | None:
    try:
        from pglast import enums as E

        return int(getattr(E.ObjectType, name))
    except Exception:
        return None


def _table_of_alter(stmt) -> str:
    rel = getattr(stmt, "relation", None)
    return relation_name(rel)


def _column_def_facts(coldef, cconsts):
    not_null = bool(getattr(coldef, "is_not_null", False))
    has_default = False
    default_volatile = False
    if not_null is False:
        for c in getattr(coldef, "constraints", None) or []:
            if getattr(c, "contype", None) == cconsts["NOTNULL"]:
                not_null = True
            elif getattr(c, "contype", None) == cconsts["DEFAULT"]:
                has_default = True
                default_volatile = expr_has_volatile(getattr(c, "raw_expr", None))
    else:
        raw_default = getattr(coldef, "raw_default", None)
        if raw_default is not None:
            has_default = True
            default_volatile = expr_has_volatile(raw_default)
        for c in getattr(coldef, "constraints", None) or []:
            if getattr(c, "contype", None) == cconsts["DEFAULT"]:
                has_default = True
                default_volatile = default_volatile or expr_has_volatile(getattr(c, "raw_expr", None))
    typesig = extract_typesign(getattr(coldef, "typeName", None)) if getattr(coldef, "typeName", None) else None
    return not_null, has_default, default_volatile, typesig


def analyze_statements(sql_text: str, parsed) -> tuple[list[RuleHit], dict[str, list[str]]]:
    atc = _at_consts()
    cc = _constr_consts()
    hits: list[RuleHit] = []
    tables_touched: dict[str, list[str]] = {}
    saw_ddl = False
    saw_dml = False
    obj_table = _object_type_const("OBJECT_TABLE")
    obj_index = _object_type_const("OBJECT_INDEX")

    def note_table(table: str, kind: str) -> None:
        if table:
            tables_touched.setdefault(table, []).append(kind)

    n_stmts = len(parsed.statements)
    for idx, (tag, stmt, loc) in enumerate(parsed.statements):
        end = parsed.statements[idx + 1][2] if idx + 1 < n_stmts and parsed.statements[idx + 1][2] > loc >= 0 else len(sql_text)
        sha = stable_hash(sql_text[loc:end])[:16] if loc >= 0 else stable_hash(tag)[:16]
        line = loc_line(sql_text, loc)
        base_details = {"statement_sha": sha}
        if tag == "DropStmt":
            remove_type = getattr(stmt, "removeType", None)
            names = drop_objects(getattr(stmt, "objects", []))
            if remove_type == obj_table and names:
                saw_ddl = True
                for tname in names:
                    short = tname.rsplit(".", 1)[-1]
                    note_table(short, "drop")
                    h = hit("R-DDL-001", line, table=short, **base_details)
                    hits.append(h)
            elif remove_type == obj_index and names:
                concurrently = bool(getattr(stmt, "concurrent", False))
                if not concurrently:
                    saw_ddl = True
                    hits.append(hit("R-DDL-013", line, index=names[0], **base_details))
                else:
                    saw_ddl = True
        elif tag == "AlterTableStmt":
            saw_ddl = True
            table = _table_of_alter(stmt)
            note_table(table, "alter")
            for cmd in getattr(stmt, "cmds", []) or []:
                subtype = getattr(cmd, "subtype", None)
                colname = getattr(cmd, "name", None) or ""
                if subtype == atc["AT_DropColumn"]:
                    hits.append(hit("R-DDL-002", line, table=table, column=colname, **base_details))
                elif subtype == atc["AT_AlterColumnType"]:
                    newtype_node = getattr(cmd, "def_", None)
                    newsig = extract_typesign(newtype_node) if newtype_node is not None else None
                    widening = False
                    if newsig is not None:
                        widening = _guess_widening(table, colname, newsig)
                    rule = "R-DDL-004a" if widening else "R-DDL-004"
                    hits.append(
                        hit(
                            rule,
                            line,
                            table=table,
                            column=colname,
                            new_type=newsig.base if newsig else "",
                            **base_details,
                        )
                    )
                elif subtype == atc["AT_SetNotNull"]:
                    hits.append(hit("R-DDL-009", line, table=table, column=colname, **base_details))
                elif subtype == atc["AT_AddColumn"]:
                    coldef = getattr(cmd, "def_", None)
                    if coldef is not None:
                        cname = getattr(coldef, "colname", "") or ""
                        not_null, has_default, volatile, ts = _column_def_facts(coldef, cc)
                        if not_null and not has_default:
                            hits.append(hit("R-DDL-005", line, table=table, column=cname, **base_details))
                        if has_default and volatile:
                            hits.append(hit("R-DDL-006", line, table=table, column=cname, **base_details))
                elif subtype == atc["AT_AddConstraint"]:
                    con = getattr(cmd, "def_", None)
                    if con is not None:
                        contype = getattr(con, "contype", None)
                        skip_validation = bool(getattr(con, "skip_validation", False))
                        initially_valid = bool(getattr(con, "initially_valid", True))
                        not_valid = skip_validation or not initially_valid
                        if contype == cc["FK"] and not not_valid:
                            pk = relation_name(getattr(con, "pktable", None))
                            hits.append(
                                hit("R-DDL-008", line, table=table, referenced_table=pk, **base_details)
                            )
                        elif contype in (cc["CHECK"], cc["UNIQUE"]) and not not_valid:
                            hits.append(
                                hit(
                                    "R-DDL-010",
                                    line,
                                    table=table,
                                    constraint=getattr(con, "conname", "") or "",
                                    kind="CHECK" if contype == cc["CHECK"] else "UNIQUE",
                                    **base_details,
                                )
                            )
        elif tag == "RenameStmt":
            rename_type = getattr(stmt, "renameType", None)
            obj_column = _object_type_const("OBJECT_COLUMN")
            rel = relation_name(getattr(stmt, "relation", None))
            sub = getattr(stmt, "subname", "") or ""
            new = getattr(stmt, "newname", "") or ""
            saw_ddl = True
            if rel:
                note_table(rel, "rename")
            if rename_type == obj_column and rel:
                hits.append(hit("R-DDL-003", line, table=rel, column=f"{sub} -> {new}", **base_details))
            elif rel:
                hits.append(hit("R-DDL-003", line, table=f"{rel} -> {new}", **base_details))
        elif tag == "IndexStmt":
            saw_ddl = True
            rel = relation_name(getattr(stmt, "relation", None))
            note_table(rel, "index")
            if not bool(getattr(stmt, "concurrently", False)):
                idxname = getattr(stmt, "idxname", "") or ""
                unique = bool(getattr(stmt, "unique", False))
                hits.append(hit("R-DDL-007", line, table=rel, index=idxname, unique=unique, **base_details))
        elif tag == "TruncateStmt":
            saw_dml = True
            rels = [relation_name(r) for r in getattr(stmt, "relations", []) or []]
            for r in rels:
                note_table(r, "truncate")
            hits.append(hit("R-DDL-011", line, statement="truncate", tables=rels, **base_details))
        elif tag == "DeleteStmt":
            where = getattr(stmt, "whereClause", None)
            rel = relation_name(getattr(stmt, "relation", None))
            note_table(rel, "delete")
            if where is None:
                saw_dml = True
                hits.append(hit("R-DDL-011", line, statement="delete", tables=[rel], **base_details))
        elif tag == "UpdateStmt":
            where = getattr(stmt, "whereClause", None)
            rels = []
            r = getattr(stmt, "relation", None)
            if r is not None:
                rels.append(relation_name(r))
            for rr in getattr(stmt, "fromClause", []) or []:
                rels.append(relation_name(rr))
            for t in rels:
                note_table(t, "update")
            if where is None:
                saw_dml = True
                hits.append(hit("R-DDL-011", line, statement="update", tables=rels, **base_details))

    if saw_ddl and saw_dml:
        hits.append(RuleHit(id="R-DDL-012", severity=Severity.MEDIUM, title=RULE_TITLES["R-DDL-012"], line=1, details={"file_level": True}))
    return hits, tables_touched


_WIDENING_HISTORY: dict[tuple[str, str], str] = {}


def register_prior_type(table: str, column: str, sig_str: str) -> None:
    _WIDENING_HISTORY[(table, column)] = sig_str


def _guess_widening(table: str, column: str, newsig) -> bool:
    prior = _WIDENING_HISTORY.get((table, column))
    if not prior:
        return False
    parts = prior.split(":")
    oldsig = extract_typesign_from_str(parts[0])
    if oldsig is None:
        return False
    return is_widening(oldsig, newsig)


def extract_typesign_from_str(spec: str):
    base, _, rest = spec.partition("(")
    base = normalize_type(base.strip())
    nums = []
    if rest:
        for piece in rest.rstrip(")").split(","):
            piece = piece.strip()
            if piece.isdigit():
                nums.append(int(piece))
    if base in ("varchar", "bpchar") and nums:
        from risco.ddl.pgparse import TypeSig

        return TypeSig(base, length=nums[0])
    if base in ("timestamp", "timestamptz", "time") and nums:
        from risco.ddl.pgparse import TypeSig

        return TypeSig(base, precision=nums[0])
    if base == "numeric" and nums:
        from risco.ddl.pgparse import TypeSig

        return TypeSig(base, precision=nums[0], scale=nums[1] if len(nums) > 1 else 0)
    from risco.ddl.pgparse import TypeSig

    return TypeSig(base)


def analyze_sql(sql_text: str):
    parsed = parse_sql_file(sql_text)
    if not parsed.ok:
        return None, parsed.error or "unparseable", {}
    hits, tables = analyze_statements(sql_text, parsed)
    return hits, "", tables


DDL_TAG_NAMES = DDL_TAGS
DML_TAG_NAMES = DML_TAGS
