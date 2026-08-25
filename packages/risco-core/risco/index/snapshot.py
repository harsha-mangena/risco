from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from dataclasses import dataclass, field
from typing import Any

from risco.canonical import sha256_hex

SNAPSHOT_FILENAME = "snapshot.sqlite"
MANIFEST_FILENAME = "manifest.json"
INDEXER_VERSION = "risco-indexer-0.1.0"

DDL = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE repos(
  name TEXT PRIMARY KEY,
  default_branch TEXT DEFAULT '',
  last_indexed_sha TEXT DEFAULT '',
  manifested INTEGER DEFAULT 0,
  service TEXT DEFAULT '',
  codeowners TEXT DEFAULT ''
);
CREATE TABLE services(
  name TEXT PRIMARY KEY,
  repo TEXT DEFAULT '',
  base_url_env TEXT DEFAULT '[]'
);
CREATE TABLE registry(
  service TEXT NOT NULL,
  method TEXT NOT NULL,
  path_template TEXT NOT NULL,
  path_regex TEXT NOT NULL,
  specificity INTEGER NOT NULL DEFAULT 0,
  operation_id TEXT DEFAULT '',
  source_repo TEXT DEFAULT '',
  source_file TEXT DEFAULT ''
);
CREATE TABLE registry_proto(
  service TEXT NOT NULL,
  rpc TEXT NOT NULL,
  package TEXT DEFAULT '',
  source_repo TEXT DEFAULT '',
  source_file TEXT DEFAULT ''
);
CREATE TABLE consumers(
  consumer_repo TEXT NOT NULL,
  consumer_service TEXT DEFAULT '',
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  strategy TEXT NOT NULL,
  confidence TEXT NOT NULL,
  method TEXT DEFAULT '',
  operation_id TEXT DEFAULT '',
  path_template TEXT DEFAULT '',
  target_service TEXT DEFAULT ''
);
CREATE TABLE unresolved(
  consumer_repo TEXT NOT NULL,
  consumer_service TEXT DEFAULT '',
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  hint_service TEXT DEFAULT '',
  reason TEXT DEFAULT ''
);
CREATE TABLE teams(team TEXT NOT NULL, member TEXT NOT NULL);
CREATE TABLE incidents(
  id TEXT PRIMARY KEY,
  title TEXT DEFAULT '',
  started_at TEXT DEFAULT '',
  severity TEXT DEFAULT ''
);
CREATE TABLE mappings(
  incident_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  precedence INTEGER NOT NULL
);
CREATE INDEX idx_consumers_target ON consumers(target_service, path_template, method);
CREATE INDEX idx_unresolved_hint ON unresolved(hint_service);
CREATE INDEX idx_mappings_value ON mappings(kind, value);
"""


@dataclass
class IndexData:
    repos: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    registry: list[dict[str, Any]] = field(default_factory=list)
    registry_proto: list[dict[str, Any]] = field(default_factory=list)
    consumers: list[dict[str, Any]] = field(default_factory=list)
    unresolved: list[dict[str, Any]] = field(default_factory=list)
    teams: list[dict[str, Any]] = field(default_factory=list)
    incidents: list[dict[str, Any]] = field(default_factory=list)
    mappings: list[dict[str, Any]] = field(default_factory=list)


def _insert_many(conn: sqlite3.Connection, sql: str, rows: list[tuple]) -> int:
    conn.executemany(sql, rows)
    return len(rows)


def build_snapshot_bytes(data: IndexData, indexer_version: str = INDEXER_VERSION) -> tuple[bytes, dict[str, Any]]:
    fd, tmp = tempfile.mkstemp(suffix=".sqlite", prefix="risco-snap-")
    os.close(fd)
    try:
        conn = sqlite3.connect(tmp)
        conn.executescript(DDL)
        _insert_many(
            conn,
            "INSERT OR REPLACE INTO repos(name,default_branch,last_indexed_sha,manifested,service,codeowners) VALUES(?,?,?,?,?,?)",
            [
                (
                    r["name"],
                    r.get("default_branch", ""),
                    r.get("last_indexed_sha", ""),
                    1 if r.get("manifested") else 0,
                    r.get("service", ""),
                    r.get("codeowners", ""),
                )
                for r in data.repos
            ],
        )
        _insert_many(
            conn,
            "INSERT OR REPLACE INTO services(name,repo,base_url_env) VALUES(?,?,?)",
            [(s["name"], s.get("repo", ""), json.dumps(sorted(s.get("base_url_env", [])))) for s in data.services],
        )
        _insert_many(
            conn,
            "INSERT INTO registry(service,method,path_template,path_regex,specificity,operation_id,source_repo,source_file) VALUES(?,?,?,?,?,?,?,?)",
            [
                (
                    r["service"],
                    r["method"],
                    r["path_template"],
                    r["path_regex"],
                    r.get("specificity", 0),
                    r.get("operation_id", "") or "",
                    r.get("source_repo", ""),
                    r.get("source_file", ""),
                )
                for r in data.registry
            ],
        )
        _insert_many(
            conn,
            "INSERT INTO registry_proto(service,rpc,package,source_repo,source_file) VALUES(?,?,?,?,?)",
            [
                (r["service"], r["rpc"], r.get("package", ""), r.get("source_repo", ""), r.get("source_file", ""))
                for r in data.registry_proto
            ],
        )
        _insert_many(
            conn,
            "INSERT INTO consumers(consumer_repo,consumer_service,file,line,strategy,confidence,method,operation_id,path_template,target_service) VALUES(?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    c["consumer_repo"],
                    c.get("consumer_service", ""),
                    c["file"],
                    int(c["line"]),
                    c["strategy"],
                    c["confidence"],
                    c.get("method", "") or "",
                    c.get("operation_id", "") or "",
                    c.get("path_template", "") or "",
                    c.get("target_service", "") or "",
                )
                for c in data.consumers
            ],
        )
        _insert_many(
            conn,
            "INSERT INTO unresolved(consumer_repo,consumer_service,file,line,hint_service,reason) VALUES(?,?,?,?,?,?)",
            [
                (
                    u["consumer_repo"],
                    u.get("consumer_service", ""),
                    u["file"],
                    int(u["line"]),
                    u.get("hint_service", ""),
                    u.get("reason", ""),
                )
                for u in data.unresolved
            ],
        )
        _insert_many(
            conn,
            "INSERT OR IGNORE INTO teams(team,member) VALUES(?,?)",
            [(t["team"], t["member"]) for t in data.teams],
        )
        _insert_many(
            conn,
            "INSERT OR REPLACE INTO incidents(id,title,started_at,severity) VALUES(?,?,?,?)",
            [(i["id"], i.get("title", ""), i.get("started_at", ""), i.get("severity", "")) for i in data.incidents],
        )
        _insert_many(
            conn,
            "INSERT INTO mappings(incident_id,kind,value,precedence) VALUES(?,?,?,?)",
            [(m["incident_id"], m["kind"], m["value"], m["precedence"]) for m in data.mappings],
        )
        conn.execute("INSERT INTO meta(key,value) VALUES('indexer_version',?)", (indexer_version,))
        conn.commit()
        counts = {
            "repos": conn.execute("SELECT COUNT(*) FROM repos").fetchone()[0],
            "registry": conn.execute("SELECT COUNT(*) FROM registry").fetchone()[0],
            "registry_proto": conn.execute("SELECT COUNT(*) FROM registry_proto").fetchone()[0],
            "consumers": conn.execute("SELECT COUNT(*) FROM consumers").fetchone()[0],
            "unresolved": conn.execute("SELECT COUNT(*) FROM unresolved").fetchone()[0],
            "teams": conn.execute("SELECT COUNT(*) FROM teams").fetchone()[0],
            "incidents": conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        }
        conn.close()
        with open(tmp, "rb") as f:
            payload = f.read()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    snapshot_id = sha256_hex(payload)
    manifest = {
        "snapshot_id": snapshot_id,
        "generated_at": data.generated_at if hasattr(data, "generated_at") else "",
        "indexer_version": indexer_version,
        "repos": {r["name"]: r.get("last_indexed_sha", "") for r in sorted(data.repos, key=lambda x: x["name"])},
        "counts": counts,
    }
    return payload, manifest


@dataclass
class Snapshot:
    conn: sqlite3.Connection
    manifest: dict[str, Any]
    path: str

    @property
    def snapshot_id(self) -> str:
        return str(self.manifest.get("snapshot_id", ""))

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass


class SnapshotHashMismatch(Exception):
    pass


def read_snapshot(path: str, verify_hash: bool = True) -> Snapshot:
    if os.path.isdir(path):
        db_path = os.path.join(path, SNAPSHOT_FILENAME)
        mf_path = os.path.join(path, MANIFEST_FILENAME)
    else:
        db_path = path
        if os.path.basename(db_path) == SNAPSHOT_FILENAME:
            mf_path = os.path.join(os.path.dirname(db_path), MANIFEST_FILENAME)
        else:
            mf_path = os.path.splitext(path)[0] + ".json"
    with open(mf_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    if verify_hash:
        import hashlib

        h = hashlib.sha256()
        with open(db_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != manifest.get("snapshot_id"):
            raise SnapshotHashMismatch(f"{db_path} does not match manifest snapshot_id")
    conn = sqlite3.connect(db_path)
    return Snapshot(conn=conn, manifest=manifest, path=db_path)


def write_snapshot_dir(data: IndexData, out_dir: str, indexer_version: str = INDEXER_VERSION, generated_at: str = "") -> dict[str, Any]:
    data.generated_at = generated_at
    payload, manifest = build_snapshot_bytes(data, indexer_version)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, SNAPSHOT_FILENAME), "wb") as f:
        f.write(payload)
    with open(os.path.join(out_dir, MANIFEST_FILENAME), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    return manifest
