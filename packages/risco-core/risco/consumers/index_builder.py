from __future__ import annotations

import json
import os
from typing import Optional

from risco.consumers.registry import (
    build_registry_from_openapi,
    build_registry_from_proto,
)
from risco.consumers.scanner import scan_repo
from risco.diff import SOURCE_EXTENSIONS
from risco.globs import match_path
from risco.index.snapshot import IndexData
from risco.incidents.schema import expand_mappings, load_incidents_json
from risco.policy.loader import load_policy_text

DEFAULT_OPENAPI_GLOBS = [
    "openapi.yaml",
    "openapi.yml",
    "openapi.json",
    "openapi/*.yaml",
    "openapi/*.yml",
    "api/openapi*.yaml",
]
DEFAULT_PROTO_GLOBS = ["proto/**/*.proto", "**/*.proto"]


def _repo_files(repo_path: str) -> dict[str, str]:
    files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__", ".venv", "dist", "build")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, repo_path).replace(os.sep, "/")
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    files[rel] = f.read()
            except OSError:
                continue
    return files


def _content_sha(texts: dict[str, str]) -> str:
    from risco.canonical import sha256_hex

    joined = "\x00".join(f"{p}\x01{texts[p]}" for p in sorted(texts))
    return sha256_hex(joined)[:40]


def discover_repos(root: str, org_prefix: str = "") -> dict[str, str]:
    repos: dict[str, str] = {}
    for entry in sorted(os.listdir(root)):
        full = os.path.join(root, entry)
        if os.path.isdir(full) and entry not in (".git",):
            name = f"{org_prefix}{entry}" if org_prefix else entry
            if "/" in name and not name.endswith("/" + entry):
                pass
            repos[name] = full
    return repos


def build_index_data(
    repos: dict[str, str],
    incidents_text: str = "",
    teams_json_text: str = "",
    org_codeowners_text: str = "",
) -> tuple[IndexData, list[str]]:
    data = IndexData()
    warnings: list[str] = []
    registries: list[dict] = []
    protos: list[dict] = []
    services_meta: list[dict] = []

    for repo_name in sorted(repos):
        path = repos[repo_name]
        files = _repo_files(path)
        policy_file = files.get("risco.yml")
        manifested = policy_file is not None
        svc_name = repo_name.split("/")[-1]
        base_url_env: list[str] = []
        openapi_globs = DEFAULT_OPENAPI_GLOBS
        proto_globs: list[str] = []
        try:
            if manifested:
                lp = load_policy_text(policy_file)
                resolved = lp.policy.service.resolved()
                if lp.policy.service.name:
                    svc_name = lp.policy.service.name
                base_url_env = list(lp.policy.service.base_url_env)
                if resolved.contracts_openapi:
                    openapi_globs = resolved.contracts_openapi
                proto_globs = resolved.contracts_protobuf or DEFAULT_PROTO_GLOBS
        except Exception as e:
            warnings.append(f"{repo_name}: invalid risco.yml ({e}); using defaults")
            manifested = False

        codeowners_text = org_codeowners_text
        for co_path in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
            if co_path in files:
                codeowners_text = files[co_path]
                break

        data.repos.append(
            {
                "name": repo_name,
                "default_branch": "",
                "last_indexed_sha": _content_sha(files),
                "manifested": manifested,
                "service": svc_name,
                "codeowners": codeowners_text,
            }
        )
        services_meta.append({"name": svc_name, "repo": repo_name, "base_url_env": base_url_env})

        for rel in sorted(files):
            if match_path(rel, openapi_globs):
                build = build_registry_from_openapi(svc_name, repo_name, rel, files[rel])
                registries.extend(build.registry)
                if not build.registry:
                    warnings.append(f"{repo_name}: contract file {rel} could not be parsed")
            elif match_path(rel, proto_globs or DEFAULT_PROTO_GLOBS):
                build = build_registry_from_proto(svc_name, repo_name, rel, files[rel])
                protos.extend(build.registry_proto)

    env_index: dict[str, str] = {}
    for s in services_meta:
        for e in s["base_url_env"]:
            env_index.setdefault(e, s["name"])

    data.registry.extend(sorted(registries, key=lambda r: (r["service"], r["method"], r["path_template"])))
    data.registry_proto.extend(sorted(protos, key=lambda r: (r["service"], r["rpc"])))
    data.services.extend(services_meta)

    for repo_name in sorted(repos):
        path = repos[repo_name]
        files = _repo_files(path)
        source_files = {
            rel: text for rel, text in files.items() if os.path.splitext(rel)[1] in SOURCE_EXTENSIONS
        }
        if not source_files:
            continue
        res = scan_repo(repo_name, source_files, data.registry, data.registry_proto, env_index)
        data.consumers.extend(res.consumers)
        data.unresolved.extend(res.unresolved)

    if teams_json_text:
        try:
            teams = json.loads(teams_json_text)
            for team, members in sorted(teams.items()):
                for m in members:
                    data.teams.append({"team": team.lstrip("@"), "member": str(m).lstrip("@")})
        except json.JSONDecodeError as e:
            warnings.append(f"teams file invalid: {e}")

    if incidents_text:
        try:
            records, mappings = expand_mappings(load_incidents_json(incidents_text))
            data.incidents.extend(
                {"id": r.id, "title": r.title, "started_at": r.started_at, "severity": r.severity}
                for r in records
            )
            data.mappings.extend(
                {"incident_id": m.incident_id, "kind": m.kind, "value": m.value, "precedence": m.precedence}
                for m in mappings
            )
        except Exception as e:
            warnings.append(f"incidents file invalid: {e}")

    return data, warnings


def dedupe_rows(data: IndexData) -> IndexData:
    seen_c: set[tuple] = set()
    consumers = []
    for c in data.consumers:
        key = (
            c["consumer_repo"],
            c.get("file"),
            c.get("line"),
            c.get("strategy"),
            c.get("target_service"),
            c.get("operation_id") or "",
        )
        if key in seen_c:
            continue
        seen_c.add(key)
        consumers.append(c)
    data.consumers = consumers
    seen_u: set[tuple] = set()
    unresolved = []
    for u in data.unresolved:
        key = (u["consumer_repo"], u.get("file"), u.get("line"), u.get("reason"))
        if key in seen_u:
            continue
        seen_u.add(key)
        unresolved.append(u)
    data.unresolved = unresolved
    return data


def size_budget_bytes() -> int:
    return 50 * 1024 * 1024
