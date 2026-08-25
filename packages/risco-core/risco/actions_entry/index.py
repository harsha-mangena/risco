"""GitHub Action entrypoint for Context A (scheduled org indexer + outcomes).

Enumerates in-scope repos with an org read token, builds the snapshot, publishes
it as a Release asset on the risco-index repo and attaches a calibration report.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name) or default


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clone_or_fetch(repo_full: str, dest: Path, token: str) -> bool:
    url = f"https://x-access-token:{token}@github.com/{repo_full}.git"
    if dest.exists():
        proc = subprocess.run(
            ["git", "-C", str(dest), "fetch", "--all", "--prune"], capture_output=True, text=True, check=False
        )
        if proc.returncode == 0:
            subprocess.run(["git", "-C", str(dest), "reset", "--hard", "origin/HEAD", "-q"], check=False)
            return True
        subprocess.run(["rm", "-rf", str(dest)], check=False)
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "-q", url, str(dest)], capture_output=True, text=True, check=False
    )
    return proc.returncode == 0


def _enumerate_repos(client, org: str, globs: list[str], excludes: list[str]) -> list[str]:
    import fnmatch

    names: list[str] = []
    page = 1
    while True:
        resp = client.request("GET", f"/orgs/{org}/repos?per_page=100&page={page}")
        if not isinstance(resp, list) or not resp:
            break
        for r in resp:
            full = r.get("full_name") or ""
            if r.get("archived") or r.get("disabled"):
                continue
            names.append(full)
        page += 1
        if page > 30:
            break
    selected = []
    for name in names:
        matched = any(fnmatch.fnmatch(name, g) or fnmatch.fnmatch(name.split("/")[-1], g) for g in globs)
        excluded = any(fnmatch.fnmatch(name, e) or fnmatch.fnmatch(name.split("/")[-1], e) for e in excludes)
        if matched and not excluded:
            selected.append(name)
    return sorted(selected)


def main() -> int:
    from risco.consumers.index_builder import build_index_data, dedupe_rows

def main() -> int:
    token = _env("INPUT_ORG_TOKEN")
    if not token:
        print("org-token is required", file=sys.stderr)
        return 1
    repo_full_env = os.environ.get("GITHUB_REPOSITORY", "")
    globs = [g.strip() for g in _env("INPUT_REPOS", "*").split(",") if g.strip()]
    excludes = [g.strip() for g in _env("INPUT_EXCLUDE").split(",") if g.strip()]
    incidents_input = _env("INPUT_INCIDENTS", "incidents.json")
    with_outcomes = _env("INPUT_OUTCOMES", "true") not in ("false", "0", "")

    org = repo_full_env.split("/", 1)[0] if "/" in repo_full_env else ""
    index_repo = repo_full_env
    from risco.github.client import Client

    client = Client(token)
    try:
        repos = _enumerate_repos(client, org, globs or ["*"], excludes)
    except Exception as e:
        print(f"repo enumeration failed: {e}", file=sys.stderr)
        return 1
    if index_repo in repos:
        repos.remove(index_repo)
    print(f"indexing {len(repos)} repos: {repos[:20]}{'…' if len(repos) > 20 else ''}")

    workdir = Path(tempfile.mkdtemp(prefix="risco-index-"))
    local_repos = {}
    incidents_text = ""
    teams_text = load_org_teams(client, org) if org else ""
    for full in repos:
        name, _, short = full.partition("/")
        dest = workdir / full.replace("/", "__")
        if _clone_or_fetch(full, dest, token):
            local_repos[full] = str(dest)

    inc_path = Path(os.environ.get("GITHUB_WORKSPACE", ".")) / incidents_input
    if inc_path.is_file():
        incidents_text = inc_path.read_text()

    data, warnings = build_index_data(local_repos, incidents_text, teams_text, org_codeowners_text="")
    data = dedupe_rows(data)

    out_dir = workdir / "snapshot-out"
    from risco.index.snapshot import write_snapshot_dir

    manifest = write_snapshot_dir(data, str(out_dir), generated_at=_now_iso())
    snapshot_bytes = (out_dir / "snapshot.sqlite").read_bytes()
    manifest_bytes = (out_dir / "manifest.json").read_bytes()
    tag = f"snapshot-{manifest['snapshot_id'][:12]}"

    files = {"snapshot.sqlite": snapshot_bytes, "manifest.json": manifest_bytes}
    report_text = ""
    if with_outcomes:
        try:
            report_text = build_calibration_section(client, repo_full_env, repos, local_repos, manifest)
        except Exception as e:
            print(f"calibration failed (non-fatal): {e}", file=sys.stderr)
    if report_text:
        files["calibration-report.md"] = report_text.encode()

    try:
        client2 = Client(token)
        from risco.github.client import create_release_with_assets

        create_release_with_assets(client2, index_repo, tag, files, body=f"snapshot {manifest['snapshot_id'][:12]}")
        print(f"published release {tag} with {len(files)} assets")
    except Exception as e:
        print(f"release publish failed: {e}", file=sys.stderr)
        return 1
    return 0


def load_org_teams(client, org: str) -> str:
    try:
        teams = client.get_paginated2(f"/orgs/{org}/teams")
        out = {}
        for t in teams:
            slug = t.get("slug")
            if not slug:
                continue
            members = client.get_paginated2(f"/orgs/{org}/teams/{slug}/members")
            out[slug] = sorted(m.get("login", "") for m in members if m.get("login"))
        return json.dumps(out)
    except Exception as e:
        print(f"team fetch failed (continuing without): {e}", file=sys.stderr)
        return ""


def build_calibration_section(client, index_repo: str, repo_names, local_repos, manifest) -> str:
    import datetime as dt

    from risco.outcomes.calibration import render_calibration_report
    from risco.outcomes.detect import IncidentRef, PrMeta, label_pr

    window_days = 14
    now_iso = _now_iso()
    incidents_text = ""
    inc_path = Path(os.environ.get("GITHUB_WORKSPACE", ".")) / _env("INPUT_INCIDENTS", "incidents.json")
    if inc_path.is_file():
        incidents_text = inc_path.read_text()
    incident_refs: list[IncidentRef] = []
    if incidents_text:
        try:
            data = json.loads(incidents_text)
            items = data.get("incidents", []) if isinstance(data, dict) else data
            for it in items:
                pr_refs = []
                for pr in it.get("prs", []):
                    ref = str(pr)
                    if "#" in ref:
                        r, _, num = ref.rpartition("#")
                        try:
                            pr_refs.append((r, int(num)))
                        except ValueError:
                            pass
                incident_refs.append(
                    IncidentRef(
                        id=str(it.get("id", "")),
                        started_at=str(it.get("started_at", "")),
                        pr_refs=pr_refs,
                        commit_shas=[str(c) for c in it.get("commits", [])],
                        paths=[str(p) for p in it.get("paths", [])],
                    )
                )
        except json.JSONDecodeError:
            pass

    outcomes = []
    for full in repo_names:
        local = local_repos.get(full)
        if not local:
            continue
        log = subprocess.run(
            ["git", "-C", local, "log", "--merges", f"--since={window_days}.days", "--pretty=%H|%s|%b|%cI|%d"],
            capture_output=True, text=True, check=False,
        ).stdout
        for line in log.splitlines():
            parts = line.split("|", 4)
            if len(parts) < 4:
                continue
            sha, title, body, date = parts[0], parts[1], parts[2], parts[3]
            branch = ""
            if len(parts) == 5 and "hotfix/" in parts[4]:
                branch = "hotfix/"
            meta = PrMeta(
                repo=full,
                number=0,
                title=title,
                body=body,
                merge_sha=sha,
                merged_at=date,
                files=[],
                head_branch=branch,
                labels=["hotfix"] if branch else [],
            )
            outcomes.append(label_pr(meta, [], incident_refs, window_days, None))
    if not outcomes:
        return "# Risco calibration report\n\nNo merge data available in this run.\n"
    return render_calibration_report(outcomes)
