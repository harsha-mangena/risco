from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

PRECEDENCE = {"prs": 0, "commits": 1, "paths": 2, "services": 3, "repos": 4}


@dataclass(frozen=True)
class IncidentRecord:
    id: str
    title: str
    started_at: str
    severity: str


@dataclass(frozen=True)
class MappingRow:
    incident_id: str
    kind: str
    value: str
    precedence: int


def load_incidents_json(text: str) -> list[dict[str, Any]]:
    data = json.loads(text)
    items = data.get("incidents", []) if isinstance(data, dict) else data
    out = []
    for it in items:
        out.append(
            {
                "id": str(it["id"]),
                "title": str(it.get("title", "")),
                "started_at": str(it.get("started_at", "")),
                "severity": str(it.get("severity", "")),
                "services": [str(x) for x in it.get("services", [])],
                "repos": [str(x) for x in it.get("repos", [])],
                "paths": [str(x) for x in it.get("paths", [])],
                "prs": [str(x) for x in it.get("prs", [])],
                "commits": [str(x) for x in it.get("commits", [])],
            }
        )
    out.sort(key=lambda x: x["id"])
    return out


def expand_mappings(incidents: list[dict[str, Any]]) -> tuple[list[IncidentRecord], list[MappingRow]]:
    records = [
        IncidentRecord(id=i["id"], title=i["title"], started_at=i["started_at"], severity=i["severity"])
        for i in incidents
    ]
    rows: list[MappingRow] = []
    for inc in incidents:
        for pr in inc["prs"]:
            rows.append(MappingRow(inc["id"], "prs", str(pr), PRECEDENCE["prs"]))
        for c in inc["commits"]:
            rows.append(MappingRow(inc["id"], "commits", c.strip().lower(), PRECEDENCE["commits"]))
        for p in inc["paths"]:
            rows.append(MappingRow(inc["id"], "paths", p.rstrip("/") + "/", PRECEDENCE["paths"]))
        for s in inc["services"]:
            rows.append(MappingRow(inc["id"], "services", s, PRECEDENCE["services"]))
        for r in inc["repos"]:
            rows.append(MappingRow(inc["id"], "repos", r, PRECEDENCE["repos"]))
    rows.sort(key=lambda m: (m.incident_id, m.precedence, m.kind, m.value))
    dedup = []
    seen = set()
    for m in rows:
        k = (m.incident_id, m.kind, m.value)
        if k not in seen:
            seen.add(k)
            dedup.append(m)
    return records, dedup


def normalize_pr_ref(pr: str) -> tuple[str, int]:
    if "#" in pr:
        repo, num = pr.rsplit("#", 1)
        return (repo.strip(), int(num))
    if "/pull/" in pr:
        repo, tail = pr.split("/pull/", 1)
        return (repo, int(tail.split("/")[0]))
    return ("", int(pr) if pr.isdigit() else 0)


def days_between(iso_a: str, iso_b: str) -> float:
    from datetime import datetime

    def parse(s: str) -> datetime:
        s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            from datetime import timezone

            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    return abs((parse(iso_b) - parse(iso_a)).total_seconds()) / 86400.0
