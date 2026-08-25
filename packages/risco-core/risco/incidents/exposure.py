from __future__ import annotations

import fnmatch
import sqlite3
from dataclasses import dataclass
from typing import Iterable

from risco.incidents.schema import days_between
from risco.models import Category, Finding, Location, Severity

INCIDENT_RULE_ID = "R-INC-001"
MAX_LISTED = 20


@dataclass(frozen=True)
class ExposureMatch:
    incident_id: str
    title: str
    severity: str
    started_at: str
    precedence: str
    matched_on: str
    age_days: float


def _path_matches(changed_path: str, pattern: str) -> bool:
    pat = pattern.rstrip("*")
    if pattern.endswith("/**") or pattern.endswith("/"):
        return changed_path.startswith(pat)
    return bool(fnmatch.fnmatch(changed_path, pattern)) or changed_path.startswith(pat)


def evaluate_exposure(
    conn: sqlite3.Connection,
    repo_full: str,
    changed_paths: Iterable[str],
    touched_services: Iterable[str],
    lookback_days: int,
    now_iso: str,
) -> list[Finding]:
    changed = sorted(set(changed_paths))
    services = sorted(set(touched_services))
    matches: dict[tuple[str, str], ExposureMatch] = {}
    cur = conn.execute(
        "SELECT i.id,i.title,i.severity,i.started_at,m.kind,m.value FROM mappings m JOIN incidents i ON i.id=m.incident_id ORDER BY m.precedence ASC"
    )
    for iid, title, sev, started, kind, value in cur.fetchall():
        best: str | None = None
        prec_rank = {"prs": 0, "commits": 1, "paths": 2, "services": 3, "repos": 4}[kind]
        if kind == "paths":
            for p in changed:
                if _path_matches(p, value):
                    best = p
                    break
        elif kind == "services":
            hit = next((s for s in services if s == value), None)
            if hit:
                best = hit
        elif kind == "repos":
            if repo_full == value or repo_full.endswith("/" + value):
                best = repo_full
        if best is None:
            continue
        try:
            age = days_between(started, now_iso) if started and now_iso else 9999.0
        except Exception:
            age = 9999.0
        if age > lookback_days:
            continue
        key = (iid, kind)
        existing = matches.get(key)
        if existing is None or prec_rank < {"prs": 0, "commits": 1, "paths": 2, "services": 3, "repos": 4}[existing.precedence]:
            matches[key] = ExposureMatch(
                incident_id=iid,
                title=title,
                severity=sev,
                started_at=started,
                precedence=kind,
                matched_on=best,
                age_days=round(age, 1),
            )

    findings: list[Finding] = []
    ordered = sorted(matches.values(), key=lambda m: (m.precedence != "prs", m.age_days, m.incident_id))
    best_per_incident: dict[str, ExposureMatch] = {}
    prec_rank = {"prs": 0, "commits": 1, "paths": 2, "services": 3, "repos": 4}
    for m in ordered:
        cur = best_per_incident.get(m.incident_id)
        if cur is None or prec_rank[m.precedence] < prec_rank[cur.precedence]:
            best_per_incident[m.incident_id] = m
    chosen = sorted(
        best_per_incident.values(),
        key=lambda m: (prec_rank[m.precedence], m.age_days, m.incident_id),
    )
    for m in chosen:
        findings.append(
            Finding(
                id=INCIDENT_RULE_ID,
                category=Category.INCIDENT,
                severity=Severity.INFO,
                title=f"Path/service implicated in prior incident ({m.incident_id})",
                location=Location(repo=repo_full, path=m.matched_on.lstrip("/"), line_start=1),
                details={
                    "incidents": [
                        {
                            "id": m.incident_id,
                            "severity": m.severity,
                            "age_days": m.age_days,
                            "precedence": m.precedence,
                        }
                    ]
                },
            )
        )
    return findings
