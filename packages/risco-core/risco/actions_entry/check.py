"""GitHub Action entrypoint for Context B (per-PR analyzer).

Reads GITHUB_* and INPUT_* environment variables, runs the analysis pipeline,
writes the check run, sticky comment, reviewer requests and action outputs.
Every internal failure degrades to a neutral check so Risco never blocks CI.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

CHECK_NAME = "Risco / merge-risk"
COMMENT_MARKER_CONST = "<!-- risco:sticky-comment:v1 -->"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name) or default


def _outputs(mapping: dict[str, str]) -> None:
    out_file = os.environ.get("GITHUB_OUTPUT")
    if not out_file:
        for k, v in mapping.items():
            print(f"{k}={v}")
        return
    with open(out_file, "a", encoding="utf-8") as f:
        for k, v in mapping.items():
            f.write(f"{k}={v}\n")


def _event() -> dict:
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if path and Path(path).is_file():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _git(repo_dir: str, *args: str) -> str:
    proc = subprocess.run(["git", "-C", repo_dir, *args], capture_output=True, text=True, check=False)
    return proc.stdout if proc.returncode == 0 else ""


def _git_show(repo_dir: str, ref: str, path: str) -> str:
    out = _git(repo_dir, "show", f"{ref}:{path}")
    if not out:
        candidate = Path(repo_dir) / path
        if candidate.is_file():
            try:
                return candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
    return ""


def _pr_context(event: dict) -> tuple[int, str, str]:
    if "pull_request" in event:
        pr = event["pull_request"]
        return int(pr.get("number") or 0), str(pr.get("head", {}).get("sha", "")), ""
    if "issue_comment" in event and event.get("issue", {}).get("pull_request"):
        body = str(event.get("comment", {}).get("body", ""))
        return int(event["issue"].get("number") or 0), "", body
    if "pull_request_review" in event:
        pr = event.get("pull_request", {})
        return int(pr.get("number") or 0), str(pr.get("head", {}).get("sha", "")), ""
    return 0, "", ""


def _base_sha(workspace: str, head_sha: str, base_branch: str) -> str:
    for candidate in (
        ["merge-base", f"origin/{base_branch}", head_sha],
        ["merge-base", base_branch, head_sha],
        ["rev-parse", f"{head_sha}^"],
    ):
        out = _git(workspace, *candidate).strip()
        if out:
            return out
    return head_sha


def _download_snapshot(policy_lp, token: str, override_repo: str, cache_dir: Path):
    cfg = policy_lp.policy.index
    repo = override_repo or cfg.repo
    if not token or not repo:
        return None, {}
    try:
        client = gh_client(token)
        release = gh_latest_release(client, repo)
        tag = release.get("tag_name", "")
        snap_asset = gh_find_asset(release, "snapshot.sqlite")
        man_asset = gh_find_asset(release, "manifest.json")
        if not tag or not snap_asset or not man_asset:
            return None, {}
        snap_path = cache_dir / f"snapshot-{tag}.sqlite"
        if not snap_path.exists():
            snap_path.write_bytes(gh_download(client, int(snap_asset["id"])))
            (cache_dir / f"manifest-{tag}.json").write_bytes(gh_download(client, int(man_asset["id"])))
        from risco.index.snapshot import read_snapshot

        snap = read_snapshot(str(snap_path))
        return snap.conn, snap.manifest
    except Exception as e:
        print(f"index download failed: {e}", file=sys.stderr)
        return None, {}


def gh_client(token: str):
    from risco.github.client import Client

    return Client(token)


def gh_latest_release(client, repo):
    return client.request("GET", f"/repos/{repo}/releases/latest")


def gh_find_asset(release, name):
    for a in release.get("assets", []) or []:
        if a.get("name") == name:
            return a
    return None


def gh_download(client, asset_id: int) -> bytes:
    return client.request_binary(f"{client.api_root}/repos/x/y/releases/assets/{asset_id}".replace("/repos/x/y/", f"/repos/{os.environ.get('GITHUB_REPOSITORY','')}/"))


def main() -> int:
    event = _event()
    repo_full = os.environ.get("GITHUB_REPOSITORY", "")
    token = _env("INPUT_GITHUB_TOKEN")
    workspace = _env("GITHUB_WORKSPACE", os.getcwd())
    pr_number, head_sha, comment_body = _pr_context(event)
    action = str(event.get("action", ""))

    policy_path = _env("INPUT_POLICY", "risco.yml")
    index_token = _env("INPUT_INDEX_TOKEN")
    index_repo_override = _env("INPUT_INDEX_REPO")
    incidents_path = _env("INPUT_INCIDENTS")
    mode_override = _env("INPUT_MODE") or None
    fail_on = _env("INPUT_FAIL_ON", "never")

    def finish(tier_out="NEUTRAL", score_out=0, bundle_hash="", evidence_path="", neutral=False):
        _outputs(
            {
                "tier": tier_out,
                "score": str(score_out),
                "bundle-hash": bundle_hash,
                "evidence-path": evidence_path,
            }
        )
        return 0

    if "issue_comment" in event:
        from risco.render.render import parse_override_command

        ok, tier_arg, reason = parse_override_command(comment_body)
        if not ok:
            return 0
        print(f"/risco override requested ({tier_arg}) — handled on next synchronize/review run", file=sys.stderr)
        return 0

    if not pr_number or not head_sha:
        print("not a pull-request context; skipping", file=sys.stderr)
        return finish()

    base_ref = os.environ.get("RISCO_BASE_REF") or ""
    base_sha = _base_sha(workspace, head_sha, base_ref or "main")

    entries_raw = _git(workspace, "diff", "--name-status", "-M", base_sha, head_sha)
    entries = from_git_name_status(entries_raw)
    paths: set[str] = set()
    for p, st, old in entries:
        paths.add(p)
        if old:
            paths.add(old)

    head_texts = {p: _git_show(workspace, head_sha, p) for p in sorted(paths)}
    base_texts = {p: _git_show(workspace, base_sha, p) for p in sorted(paths)}

    try:
        from risco.policy.loader import load_policy

        lp = load_policy(policy_path if Path(policy_path).is_file() else str(Path(workspace) / policy_path))
    except Exception as e:
        print(f"policy invalid: {e}", file=sys.stderr)
        summary = f"**{CHECK_NAME} — NEUTRAL**\n\nPolicy could not be loaded: {e}"
        _post_check(token, repo_full, head_sha, "neutral", None, summary)
        return finish()

    cache_dir = Path(tempfile.gettempdir()) / "risco-index-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    conn, manifest = _download_snapshot(lp, index_token, index_repo_override, cache_dir)

    approvals = []
    if token:
        try:
            client = gh_client(token)
            reviews = client.get_paginated2(f"/repos/{repo_full}/pulls/{pr_number}/reviews")
        except Exception:
            reviews = []
    for r in reviews:
        state = str(r.get("state", "")).upper()
        if state in ("APPROVED", "CHANGES_REQUESTED", "COMMENTED"):
            approvals.append(
                {
                    "user": str(r.get("user", {}).get("login", "")),
                    "team_memberships": [],
                    "state": state,
                    "sha": str(r.get("commit_id", "")),
                }
            )
    from risco.models import Approval

    approval_models = [Approval(**a) for a in approvals]

    tool_versions = {}
    try:
        from risco.contract.bufdiff import buf_version, find_buf
        from risco.contract.oasdiff import find_oasdiff, oasdiff_version

        oas_bin = find_oasdiff()
        buf_bin = find_buf()
        if oas_bin:
            tool_versions["oasdiff"] = oasdiff_version(oas_bin)
        if buf_bin:
            tool_versions["buf"] = buf_version(buf_bin)
    except Exception:
        pass

    from risco.pipeline import Analyzer, AnalysisSources, write_evidence

    analyzer = Analyzer(
        lp,
        conn,
        manifest,
        repo_full=repo_full,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        mode_override=mode_override,
        now_iso=_now_iso(),
        tool_versions=tool_versions,
    )
    result = analyzer.run(
        entries,
        AnalysisSources(base_texts=base_texts, head_texts=head_texts),
        approval_models,
    )

    evidence_path = ""
    bundle_hash = ""
    tier_out = result.tier or "NEUTRAL"
    score_out = result.score
    if result.bundle is not None:
        out_dir = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "risco"
        evidence_path, bundle_hash = write_evidence(result, str(out_dir))

    conclusion = None
    status = "completed"
    if result.is_neutral:
        summary = result.summary_markdown
        conclusion = "neutral"
    else:
        summary = result.summary_markdown
        if (mode_override or lp.policy.mode) == "enforce":
            conclusion = "success" if result.satisfied else "failure"

    _post_check(token, repo_full, head_sha, status, conclusion, summary)

    if token and result.bundle is not None and not result.is_neutral:
        try:
            client = gh_client(token)
            comment_body = result.comment_markdown
            gh_upsert_comment(client, repo_full, pr_number, COMMENT_MARKER_CONST, comment_body)
            rr = result.bundle.verdict.required_reviewers
            users: list[str] = []
            teams: list[str] = []
            if conclusion == "failure":
                missing_users = [u for u in rr.owner_users if u]
                teams = list(rr.teams) + [
                    t.split("/")[-1] for t in rr.consumer_owner_teams if "/" in t or t
                ]
                users = missing_users[:10]
            request_reviewers_safe(client, repo_full, pr_number, users, sorted(set(teams)))
        except Exception as e:
            print(f"comment/review step failed: {e}", file=sys.stderr)
    elif token:
        try:
            client = gh_client(token)
            gh_upsert_comment(client, repo_full, pr_number, COMMENT_MARKER_CONST, result.summary_markdown)
        except Exception:
            pass

    should_fail_step = False
    if fail_on != "never" and not result.is_neutral:
        rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        threshold = 1 if fail_on == "medium" else 2
        should_fail_step = rank.get(tier_out, 0) >= threshold

    finish(tier_out, score_out, bundle_hash, evidence_path)
    return 1 if should_fail_step else 0


def _post_check(token: str, repo: str, head_sha: str, status: str, conclusion, summary: str) -> None:
    if not token or not head_sha:
        return
    try:
        client = gh_client(token)
        from risco.render.render import CHECK_NAME, build_annotations

        batches = []
        conclusion_arg = conclusion
        gh_create_check(client, repo, head_sha, CHECK_NAME, status, conclusion_arg, summary, batches)
    except Exception as e:
        print(f"check-run publish failed: {e}", file=sys.stderr)


def gh_upsert_comment(client, repo: str, pr_number: int, marker: str, body: str) -> None:
    _upsert_comment_impl(client, repo, pr_number, marker, body)


def _upsert_comment_impl(client, repo: str, pr_number: int, marker: str, body: str) -> None:
    comments = client.get_paginated2(f"/repos/{repo}/issues/{pr_number}/comments")
    for c in comments:
        if marker in str(c.get("body", "")):
            client.request("PATCH", f"/repos/{repo}/issues/comments/{c['id']}", {"body": body})
            return
    client.request("POST", f"/repos/{repo}/issues/{pr_number}/comments", {"body": body})


def request_reviewers_safe(client, repo: str, pr_number: int, users, teams) -> None:
    if not users and not teams:
        return
    try:
        payload = {}
        if users:
            payload["reviewers"] = [u.lstrip("@") for u in users]
        if teams:
            payload["team_reviewers"] = [t.split("/")[-1].lstrip("@") for t in teams]
        if payload:
            client.request("POST", f"/repos/{repo}/pulls/{pr_number}/requested_reviewers", payload)
    except Exception as e:
        print(f"reviewer request failed (non-fatal): {e}", file=sys.stderr)


def gh_create_check(client, repo, head_sha, name, status, conclusion, summary, batches):
    body = {
        "name": name,
        "head_sha": head_sha,
        "status": status,
        "output": {"title": name, "summary": (summary or "")[:65535]},
    }
    if conclusion:
        body["conclusion"] = conclusion
    try:
        client.request("POST", f"/repos/{repo}/check-runs", body)
    except Exception as e:
        print(f"check-run create failed: {e}", file=sys.stderr)
