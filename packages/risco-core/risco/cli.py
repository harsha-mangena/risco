from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from risco.errors import PolicyError, RiscoError


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="risco", description="Risco: deterministic merge-risk router")
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate-policy", help="validate a risco.yml policy file")
    p_val.add_argument("policy", nargs="?", default="risco.yml")

    p_an = sub.add_parser("analyze", help="run PR analysis (Context B)")
    p_an.add_argument("--repo", default="")
    p_an.add_argument("--pr", type=int, default=0)
    p_an.add_argument("--base-sha", default="")
    p_an.add_argument("--head-sha", default="")
    p_an.add_argument("--repo-dir", default="", help="git checkout to derive diff from")
    p_an.add_argument("--base-ref", default="")
    p_an.add_argument("--head-ref", default="HEAD")
    p_an.add_argument("--base-dir", default="", help="materialized base tree (offline mode)")
    p_an.add_argument("--head-dir", default="", help="materialized head tree (offline mode)")
    p_an.add_argument("--policy", default="risco.yml")
    p_an.add_argument("--index", default="", help="snapshot dir or sqlite path")
    p_an.add_argument("--incidents", default="")
    p_an.add_argument("--mode", choices=["advisory", "enforce"], default=None)
    p_an.add_argument("--out", default=".risco")
    p_an.add_argument("--json-out", default="")
    p_an.add_argument("--summary-out", default="")
    p_an.add_argument("--comment-out", default="")
    p_an.add_argument("--approvals-json", default="", help='[{"user","state","sha"}] for offline enforce tests')
    p_an.add_argument("--now", default="", help="ISO timestamp override (determinism/testing)")

    p_ix = sub.add_parser("index", help="build an org index snapshot (Context A)")
    p_ix.add_argument("--repos-dir", required=True)
    p_ix.add_argument("--org-prefix", default="")
    p_ix.add_argument("--out", required=True)
    p_ix.add_argument("--incidents", default="")
    p_ix.add_argument("--teams", default="")
    p_ix.add_argument("--org-codeowners", default="")
    p_ix.add_argument("--now", default="")

    p_rp = sub.add_parser("replay", help="replay historical merged PRs")
    p_rp.add_argument("--cases", required=True, help="JSON: [{name, repo_full, pr_number, base_dir, head_dir, merged_at?, outcome_labels?}]")
    p_rp.add_argument("--policy", default="risco.yml")
    p_rp.add_argument("--index", required=True)
    p_rp.add_argument("--mode", default=None)
    p_rp.add_argument("--report-out", default="")
    p_rp.add_argument("--results-out", default="")
    p_rp.add_argument("--now", default="")

    p_cal = sub.add_parser("calibrate", help="build calibration report from outcomes")
    p_cal.add_argument("--outcomes", required=True)
    p_cal.add_argument("--bundles-dir", default="")
    p_cal.add_argument("--weights-json", default="")
    p_cal.add_argument("--report-out", default="")

    args = parser.parse_args(argv)

    try:
        if args.command == "validate-policy":
            return cmd_validate_policy(args)
        if args.command == "analyze":
            return cmd_analyze(args)
        if args.command == "index":
            return cmd_index(args)
        if args.command == "replay":
            return cmd_replay(args)
        if args.command == "calibrate":
            return cmd_calibrate(args)
    except PolicyError as e:
        print(f"policy error: {e}", file=sys.stderr)
        return 2
    except RiscoError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def _write(path: str, content: str) -> None:
    if not path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def cmd_validate_policy(args) -> int:
    from risco.policy.loader import load_policy

    lp = load_policy(args.policy if args.policy else "risco.yml")
    print(f"OK version={lp.policy.version} hash={lp.policy_hash[:12]} mode={lp.policy.mode}")
    return 0


def _open_snapshot(index_path: str):
    if not index_path:
        return None, {}
    from risco.index.snapshot import read_snapshot

    snap = read_snapshot(index_path)
    return snap.conn, snap.manifest


def _load_approvals(path: str):
    if not path:
        import json as _j
        return []
    with open(path, "r", encoding="utf-8") as f:
        raw = _j.load(f)
    from risco.models import Approval

    return [Approval(**item) for item in raw]


def _git_show(repo_dir: str, ref: str, path: str) -> str:
    import subprocess

    proc = subprocess.run(
        ["git", "-C", repo_dir, "show", f"{ref}:{path}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout


def _head_tree_texts(repo_dir: str, paths: list[str], head_ref: str = "HEAD") -> dict[str, str]:
    out: dict[str, str] = {}
    for p in paths:
        text = _git_show(repo_dir, head_ref, p)
        if text or os.path.isfile(os.path.join(repo_dir, p)):
            out[p] = text if text else ""
            if not text and os.path.isfile(os.path.join(repo_dir, p)):
                with open(os.path.join(repo_dir, p), "r", encoding="utf-8", errors="replace") as f:
                    out[p] = f.read()
    return out


def cmd_analyze(args) -> int:
    from risco.pipeline import AnalysisSources, Analyzer
    from risco.policy.loader import load_policy

    lp = load_policy(args.policy)
    conn, manifest = _open_snapshot(args.index)

    if args.base_dir and args.head_dir:
        from risco.replay.replay import diff_entries

        from risco.pipeline import sources_from_dirs

        entries = diff_entries(args.base_dir, args.head_dir)
        sources = sources_from_dirs(args.base_dir, args.head_dir)
    else:
        if not args.repo_dir:
            raise RiscoError("analyze requires --repo-dir (with --base-ref/--head-ref) or --base-dir/--head-dir")
        entries_raw = changed_entries_git(args.repo_dir, args.base_ref, args.head_ref)
        entries = [(p, s, o) for p, s, o in entries_raw]
        all_paths = []
        for p, s, o in entries:
            all_paths.append(p)
            if o:
                all_paths.append(o)
        head_texts = _head_tree_texts(args.repo_dir, sorted(set(all_paths)), args.head_ref)
        base_texts = {}
        for p, s, o in entries:
            key = o or p
            base_texts[key] = _git_show(args.repo_dir, args.base_ref, key)
        sources = AnalysisSources(base_texts=base_texts, head_texts=head_texts)

    approvals = _load_approvals(args.approvals_json)

    tool_versions = {}
    from risco.contract.bufdiff import find_buf, buf_version
    from risco.contract.oasdiff import find_oasdiff, oasdiff_version

    oas_bin = find_oasdiff()
    buf_bin = find_buf()
    if oas_bin:
        tool_versions["oasdiff"] = oasdiff_version(oas_bin)
    if buf_bin:
        tool_versions["buf"] = buf_version(buf_bin)
    try:
        import pglast

        tool_versions["pglast"] = getattr(pglast, "__version__", "unknown")
    except Exception:
        pass

    analyzer = Analyzer(
        lp,
        conn,
        manifest,
        repo_full=args.repo,
        pr_number=args.pr,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        mode_override=args.mode,
        now_iso=args.now,
        tool_versions=tool_versions,
    )
    result = analyzer.run(entries, sources, approvals)

    evidence_path = ""
    bundle_hash = ""
    if result.bundle is not None:
        from risco.pipeline import write_evidence

        evidence_path, bundle_hash = write_evidence(result, args.out)

    payload = {
        "status": result.status,
        "neutral_reason": result.neutral_reason,
        "tier": result.tier,
        "score": result.score,
        "bundle_hash": bundle_hash,
        "evidence_path": evidence_path,
        "flags": result.flags,
        "enforcement_missing": result.enforcement_missing,
    }
    _write(args.json_out, json.dumps(payload, indent=2))
    if result.bundle is not None:
        _write(args.summary_out, result.summary_markdown)
        _write(args.comment_out, result.comment_markdown)
        print(json.dumps(payload))
    else:
        print(json.dumps(payload))
        _write(args.summary_out, result.summary_markdown)
    return 0


def changed_entries_git(repo_dir: str, base_ref: str, head_ref: str):
    from risco.diff import git_diff_name_status

    return git_diff_name_status(repo_dir, base_ref, head_ref)


def cmd_index(args) -> int:
    from risco.consumers.index_builder import build_index_data, dedupe_rows, discover_repos
    from risco.index.snapshot import write_snapshot_dir

    repos = discover_repos(args.repos_dir, args.org_prefix)
    incidents_text = ""
    if args.incidents:
        with open(args.incidents, "r", encoding="utf-8") as f:
            incidents_text = f.read()
    teams_text = ""
    if args.teams:
        with open(args.teams, "r", encoding="utf-8") as f:
            teams_text = f.read()
    org_co = ""
    if args.org_codeowners:
        with open(args.org_codeowners, "r", encoding="utf-8") as f:
            org_co = f.read()
    data, warnings = build_index_data(repos, incidents_text, teams_text, org_co)
    data = dedupe_rows(data)
    manifest = write_snapshot_dir(data, args.out, generated_at=args.now)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    print(json.dumps({"snapshot_id": manifest["snapshot_id"], "counts": manifest["counts"], "out": args.out}, indent=2))
    return 0


def cmd_replay(args) -> int:
    from risco.policy.loader import load_policy
    from risco.replay.replay import ReplayCase, run_replay

    lp = load_policy(args.policy)
    conn, manifest = _open_snapshot(args.index)
    with open(args.cases, "r", encoding="utf-8") as f:
        raw = json.load(f)
    cases = [ReplayCase(**c) for c in raw]
    results, report = run_replay(
        cases,
        lp,
        conn,
        manifest,
        mode=args.mode,
        now_iso=args.now,
    )
    if args.report_out:
        _write(args.report_out, report)
    else:
        print(report)
    if args.results_out:
        _write(
            args.results_out,
            json.dumps([r.__dict__ | {} for r in results], indent=2, default=str),
        )
    return 0


def cmd_calibrate(args) -> int:
    from risco.outcomes.calibration import load_outcomes_json, render_calibration_report

    with open(args.outcomes, "r", encoding="utf-8") as f:
        outcomes = load_outcomes_json(f.read())
    bundles = None
    if args.bundles_dir and os.path.isdir(args.bundles_dir):
        bundles = []
        for fn in sorted(os.listdir(args.bundles_dir)):
            if fn.endswith(".json"):
                with open(os.path.join(args.bundles_dir, fn), "r", encoding="utf-8") as f:
                    bundles.append(json.load(f))
    weights = None
    if args.weights_json:
        with open(args.weights_json, "r", encoding="utf-8") as f:
            weights = json.load(f)
    report = render_calibration_report(outcomes, bundles, weights)
    if args.report_out:
        _write(args.report_out, report)
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
