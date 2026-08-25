from __future__ import annotations

import sqlite3

from risco.incidents.exposure import evaluate_exposure
from risco.incidents.schema import expand_mappings, load_incidents_json

INCIDENTS = """
{
  "incidents": [
    {"id": "INC-1", "title": "t", "started_at": "2026-08-01T00:00:00Z", "severity": "SEV2",
     "services": ["orders-api"],
     "paths": ["db/migrations/", "src/orders/"], "prs": ["acme/orders-api#812"], "commits": ["deadbeef"]}
  ]
}
"""


def _conn_with(incidents_text=INCIDENTS):
    records, rows = expand_mappings(load_incidents_json(incidents_text))
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE incidents(id TEXT PRIMARY KEY, title TEXT, started_at TEXT, severity TEXT)")
    conn.execute("CREATE TABLE mappings(incident_id TEXT, kind TEXT, value TEXT, precedence INTEGER)")
    for r in records:
        conn.execute("INSERT INTO incidents VALUES(?,?,?,?)", (r.id, r.title, r.started_at, r.severity))
    for m in rows:
        conn.execute(
            "INSERT INTO mappings VALUES(?,?,?,?)",
            (m.incident_id, m.kind, m.value, m.precedence),
        )
    return conn


NOW = "2026-08-25T12:00:00+00:00"


def test_expand_precedence_ordering():
    records, rows = expand_mappings(load_incidents_json(INCIDENTS))
    prs_row = next(r for r in rows if r.kind == "prs")
    paths_row = next(r for r in rows if r.kind == "paths")
    assert prs_row.precedence < paths_row.precedence


def test_exposure_path_match_within_window():
    conn = _conn_with()
    findings = evaluate_exposure(conn, "acme/orders-api", ["db/migrations/0099_x.sql"], [], 180, NOW)
    assert len(findings) == 1
    assert findings[0].id == "R-INC-001"
    assert findings[0].details["incidents"][0]["precedence"] == "paths"


def test_exposure_service_match_when_no_paths_touched():
    conn = _conn_with()
    findings = evaluate_exposure(conn, "acme/other-repo", ["src/util.py"], ["orders-api"], 180, NOW)
    assert len(findings) == 1
    assert findings[0].details["incidents"][0]["precedence"] == "services"


def test_exposure_outside_lookback_ignored():
    conn = _conn_with()
    findings = evaluate_exposure(conn, "acme/orders-api", ["db/migrations/x.sql"], [], 7, NOW)
    assert findings == []


def test_pr_precedence_wins(tmp_path):
    text = INCIDENTS.replace('"prs": ["acme/orders-api#812"]', '"prs": []')
    records, rows = expand_mappings(load_incidents_json(text))
    assert not [r for r in rows if r.kind == "prs"]
