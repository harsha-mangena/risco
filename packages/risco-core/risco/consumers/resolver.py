from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from risco.contract.openapi_doc import templates_compatible
from risco.models import Confidence, Consumer, OperationRef, Strategy

_CONF_RANK = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}


@dataclass
class Resolution:
    by_operation: dict[str, list[Consumer]] = field(default_factory=dict)
    service_wide: dict[str, list[Consumer]] = field(default_factory=dict)
    unresolved_matching: list[dict] = field(default_factory=list)
    all_consumers: list[Consumer] = field(default_factory=list)

    def consumers_for(self, op_key: str) -> list[Consumer]:
        return self.by_operation.get(op_key, [])

    def services_for(self, op_key: str) -> list[str]:
        seen: dict[str, Consumer] = {}
        for c in self.consumers_for(op_key):
            if c.service not in seen or _CONF_RANK[c.confidence.value] > _CONF_RANK[seen[c.service].confidence.value]:
                seen[c.service] = c
        return sorted(seen)

    def highest_per_service(self, op_key: str) -> list[Consumer]:
        best: dict[str, Consumer] = {}
        for c in self.consumers_for(op_key):
            cur = best.get(c.service)
            if (
                cur is None
                or _CONF_RANK[c.confidence.value] > _CONF_RANK[cur.confidence.value]
                or (
                    _CONF_RANK[c.confidence.value] == _CONF_RANK[cur.confidence.value]
                    and (c.path, c.line) < (cur.path, cur.line)
                )
            ):
                best[c.service] = c
        return [best[s] for s in sorted(best)]


def resolve_consumers(
    conn: sqlite3.Connection,
    target_service: str,
    operation_refs: list[OperationRef],
) -> Resolution:
    res = Resolution()
    for ref in sorted(operation_refs, key=lambda r: r.key()):
        rows = conn.execute(
            "SELECT consumer_repo, consumer_service, file, line, strategy, confidence, method, operation_id, path_template "
            "FROM consumers WHERE target_service = ? ORDER BY file, line",
            (target_service,),
        ).fetchall()
        matched: list[Consumer] = []
        for repo, csvc, file, line, strat, conf, method, op_id, tmpl in rows:
            if ref.path_template and tmpl and not templates_compatible(ref.path_template, tmpl):
                continue
            if ref.method and method and method.upper() != ref.method.upper():
                continue
            if ref.operation_id and op_id and op_id != ref.operation_id:
                continue
            matched.append(
                Consumer(
                    service=csvc or repo,
                    repo=repo,
                    path=file,
                    line=int(line),
                    strategy=Strategy(strat),
                    confidence=Confidence(conf),
                    operation=OperationRef(method=method or None, path_template=tmpl or None, operation_id=op_id or None),
                )
            )
        res.by_operation[ref.key()] = matched
        res.all_consumers.extend(matched)

    service_wide_rows = conn.execute(
        "SELECT consumer_repo, consumer_service, file, line, strategy, confidence, method, operation_id, path_template "
        "FROM consumers WHERE target_service = ? ORDER BY file, line",
        (target_service,),
    ).fetchall()
    agg: list[Consumer] = []
    for repo, csvc, file, line, strat, conf, method, op_id, tmpl in service_wide_rows:
        agg.append(
            Consumer(
                service=csvc or repo,
                repo=repo,
                path=file,
                line=int(line),
                strategy=Strategy(strat),
                confidence=Confidence(conf),
                operation=OperationRef(method=method or None, path_template=tmpl or None, operation_id=op_id or None),
            )
        )
    res.service_wide["*"] = agg

    for row in conn.execute(
        "SELECT consumer_repo, consumer_service, file, line, hint_service, reason FROM unresolved WHERE hint_service = ? ORDER BY file, line",
        (target_service,),
    ).fetchall():
        res.unresolved_matching.append(
            {
                "consumer_repo": row[0],
                "consumer_service": row[1],
                "file": row[2],
                "line": int(row[3]),
                "hint_service": row[4],
                "reason": row[5],
            }
        )
    return res


def consumer_owners(conn: sqlite3.Connection, consumers: list[Consumer]) -> dict[str, list[str]]:
    repos_needed = sorted({c.repo for c in consumers})
    owners: dict[str, list[str]] = {}
    for repo in repos_needed:
        row = conn.execute("SELECT codeowners FROM repos WHERE name = ?", (repo,)).fetchone()
        text = row[0] if row else ""
        owners[repo] = text
    return owners


def teams_table(conn: sqlite3.Connection) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for team, member in conn.execute("SELECT team, member FROM teams ORDER BY team, member"):
        out.setdefault(team, []).append(member)
    return out


def base_url_env_index(conn: sqlite3.Connection) -> dict[str, str]:
    idx: dict[str, str] = {}
    for name, env_json in conn.execute("SELECT name, base_url_env FROM services"):
        try:
            envs = json.loads(env_json or "[]")
        except json.JSONDecodeError:
            envs = []
        for e in envs:
            idx.setdefault(str(e), name)
    return idx


def index_age_hours(manifest: dict, now_iso: str | None = None) -> float | None:
    from datetime import datetime, timezone

    generated = manifest.get("generated_at") or ""
    if not generated:
        return None
    try:
        dt = datetime.fromisoformat(generated.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if now_iso:
            nowdt = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
            if nowdt.tzinfo is None:
                nowdt = nowdt.replace(tzinfo=timezone.utc)
        else:
            nowdt = datetime.now(timezone.utc)
        return max(0.0, (nowdt - dt).total_seconds() / 3600.0)
    except Exception:
        return None
