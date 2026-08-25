from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from risco.ddl.alembic_map import map_alembic
from risco.ddl.pgparse import loc_line
from risco.ddl.sqlrules import analyze_sql
from risco.errors import ParseFailure

from risco.models import Category, FileCategory, Finding, Location, Severity

UNPARSEABLE_ID = "R-DDL-900"
UNMAPPED_OP_ID = "R-DDL-901"
COUPLED_SOURCE_ID = "R-DDL-014"

RULE_DOC = {
    UNPARSEABLE_ID: ("Migration file unparseable", Severity.MEDIUM),
    UNMAPPED_OP_ID: ("Unmapped migration operation", Severity.LOW),
    COUPLED_SOURCE_ID: (
        "Migration table/column also referenced by changed source in this PR",
        Severity.INFO,
    ),
}


@dataclass
class DdlAnalysis:
    findings: list[Finding] = field(default_factory=list)
    unparseable: bool = False
    tables_touched: set[str] = field(default_factory=set)


def _finding(rule_id: str, severity: Severity, title: str, repo: str, path: str, line: int, details: dict) -> Finding:
    return Finding(
        id=rule_id,
        category=Category.DDL,
        severity=severity,
        title=title,
        location=Location(repo=repo, path=path, line_start=line, line_end=line),
        details=details,
    )


def analyze_migration_file(repo: str, path: str, text: str) -> DdlAnalysis:
    out = DdlAnalysis()
    if path.endswith(".py"):
        try:
            al = map_alembic(text, path)
        except ParseFailure as e:
            out.unparseable = True
            out.findings.append(
                _finding(
                    UNPARSEABLE_ID,
                    Severity.MEDIUM,
                    RULE_DOC[UNPARSEABLE_ID][0],
                    repo,
                    path,
                    getattr(e, "what", 1) if isinstance(getattr(e, "what", None), int) else 1,
                    {"reason": str(e)},
                )
            )
            return out
        out.findings.extend(
            _finding(h.id, h.severity, h.title, repo, path, h.line, dict(h.details)) for h in al.hits
        )
        for attr, line in al.unmapped_ops:
            out.findings.append(
                _finding(UNMAPPED_OP_ID, Severity.LOW, RULE_DOC[UNMAPPED_OP_ID][0], repo, path, line, {"operation": attr})
            )
        for sql, line in al.executed_sql:
            hits, err, tables = analyze_sql(sql)
            if err:
                out.findings.append(
                    _finding(
                        UNPARSEABLE_ID,
                        Severity.MEDIUM,
                        RULE_DOC[UNPARSEABLE_ID][0],
                        repo,
                        path,
                        line,
                        {"reason": f"embedded SQL failed to parse: {err}"},
                    )
                )
                out.unparseable = True
                continue
            for h in hits:
                adjusted = dict(h.details)
                adjusted["via"] = "op.execute"
                out.findings.append(_finding(h.id, h.severity, h.title, repo, path, line, adjusted))
            for t in tables:
                out.tables_touched.add(t)
        return out

    hits, err, tables = analyze_sql(text)
    if err or hits is None:
        out.unparseable = True
        out.findings.append(
            _finding(UNPARSEABLE_ID, Severity.MEDIUM, RULE_DOC[UNPARSEABLE_ID][0], repo, path, 1, {"reason": err or "unparseable"})
        )
        return out
    out.findings.extend(_finding(h.id, h.severity, h.title, repo, path, h.line, dict(h.details)) for h in hits)
    for t in tables:
        out.tables_touched.add(t)
    return out


def analyze_migrations(
    repo: str,
    migration_texts: dict[str, str],
    changed_source_texts: Optional[dict[str, str]] = None,
) -> DdlAnalysis:
    combined = DdlAnalysis()
    all_tables: set[str] = set()
    saw_unparseable = False
    per_file_tables: dict[str, set[str]] = {}

    for path in sorted(migration_texts):
        text = migration_texts[path]
        res = analyze_migration_file(repo, path, text)
        combined.findings.extend(res.findings)
        saw_unparseable = saw_unparseable or res.unparseable
        all_tables.update(res.tables_touched)
        per_file_tables[path] = set(res.tables_touched)

    identifiers = set(all_tables)
    for f in combined.findings:
        col = f.details.get("column") if isinstance(f.details, dict) else None
        if isinstance(col, str) and col:
            identifiers.add(col)
        table = f.details.get("table") if isinstance(f.details, dict) else None
        if isinstance(table, str) and table:
            identifiers.add(table.split(" -> ")[0])
    if changed_source_texts and identifiers:
        word_re = {t: re.compile(rf"\b{re.escape(t)}\b", re.IGNORECASE) for t in identifiers}
        del identifiers
        matched_sources: dict[str, list[str]] = {}
        for spath in sorted(changed_source_texts):
            body = changed_source_texts[spath]
            for t, rx in word_re.items():
                if rx.search(body):
                    matched_sources.setdefault(t, []).append(spath)
        if matched_sources:
            anchor_path = sorted(per_file_tables.keys())[0] if per_file_tables else ""
            anchor_line = 1
            for f in combined.findings:
                if f.location.path == anchor_path:
                    anchor_line = f.location.line_start
                    break
            combined.findings.append(
                _finding(
                    COUPLED_SOURCE_ID,
                    Severity.INFO,
                    RULE_DOC[COUPLED_SOURCE_ID][0],
                    repo,
                    anchor_path,
                    anchor_line,
                    {
                        "tables": sorted(t for t in matched_sources if t in all_tables),
                        "identifiers": sorted(matched_sources),
                        "source_files": sorted({p for v in matched_sources.values() for p in v}),
                    },
                )
            )

    combined.unparseable = saw_unparseable
    combined.tables_touched = all_tables
    combined.findings.sort(key=lambda f: (f.location.path, f.location.line_start, f.id))
    dedup: list[Finding] = []
    seen: set[tuple] = set()
    for f in combined.findings:
        key = (f.id, f.location.path, f.location.line_start, stable_key(f))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(f)
    combined.findings = dedup
    return combined


def stable_key(f: Finding) -> str:
    import json as _json

    return _json.dumps(f.details, sort_keys=True)[:200]
