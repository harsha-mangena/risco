from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Optional

from risco.models import Outcome, OutcomeLabel, Tier


@dataclass
class PrMeta:
    repo: str
    number: int
    title: str = ""
    body: str = ""
    merge_sha: str = ""
    merged_at: str = ""
    files: list[str] = field(default_factory=list)
    head_branch: str = ""
    labels: list[str] = field(default_factory=list)


@dataclass
class IncidentRef:
    id: str
    started_at: str = ""
    pr_refs: list[tuple[str, int]] = field(default_factory=list)
    commit_shas: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)


def _parse_iso(s: str):
    import datetime as dt

    d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d


def _within_window(earlier: str, later: str, days: int) -> bool:
    try:
        delta = (_parse_iso(later) - _parse_iso(earlier)).total_seconds() / 86400.0
        return 0 <= delta <= max(days, 0)
    except Exception:
        return False


def detect_revert(target: PrMeta, all_prs: list[PrMeta]) -> Optional[PrMeta]:
    for other in sorted(all_prs, key=lambda p: (p.merged_at, p.repo, p.number)):
        if (other.repo, other.number) == (target.repo, target.number):
            continue
        if not other.title.lower().startswith("revert"):
            continue
        if f"This reverts commit {target.merge_sha}" in (other.body or ""):
            return other
        stripped = target.title.lower().strip()
        if stripped and stripped in other.title.lower():
            return other
    return None


def detect_hotfix(target: PrMeta, all_prs: list[PrMeta], window_days: int) -> Optional[PrMeta]:
    candidates = []
    for other in all_prs:
        if (other.repo, other.number) == (target.repo, target.number):
            continue
        if other.repo != target.repo:
            continue
        if not _within_window(target.merged_at, other.merged_at, window_days):
            continue
        flagged = (
            "hotfix" in [l.lower() for l in other.labels]
            or other.head_branch.lower().startswith("hotfix/")
            or other.head_branch.lower() == "hotfix"
        )
        if not flagged:
            continue
        overlap = set(other.files) & set(target.files)
        if overlap:
            candidates.append((other.merged_at, other))
    if not candidates:
        return None
    return sorted(candidates, key=lambda x: x[0])[0][1]


def detect_incident_link(target: PrMeta, incidents: list[IncidentRef], window_days: int) -> Optional[IncidentRef]:
    for inc in incidents:
        if (target.repo, target.number) in inc.pr_refs:
            return inc
        if target.merge_sha and target.merge_sha.lower() in {c.lower() for c in inc.commit_shas}:
            return inc
    best: tuple[str, IncidentRef] | None = None
    for inc in incidents:
        if not _within_window(target.merged_at, inc.started_at, window_days) and not _within_window(
            inc.started_at, target.merged_at, window_days
        ):
            continue
        for pat in inc.paths:
            norm = pat.rstrip("*").rstrip("/")
            if any(f.startswith(norm + "/") or fnmatch.fnmatch(f, pat) for f in target.files):
                key = inc.started_at
                if best is None or key < best[0]:
                    best = (key, inc)
                break
    return best[1] if best else None


def label_pr(
    target: PrMeta,
    all_prs: list[PrMeta],
    incidents: list[IncidentRef],
    window_days: int,
    tier_at_merge: Optional[Tier],
    ci_failed: bool = False,
) -> Outcome:
    labels: list[OutcomeLabel] = []
    refs: list[str] = []

    revert = detect_revert(target, all_prs)
    if revert:
        labels.append(OutcomeLabel.REVERTED)
        refs.append(f"{revert.repo}#{revert.number}")

    hotfix = detect_hotfix(target, all_prs, window_days)
    if hotfix:
        labels.append(OutcomeLabel.HOTFIX_FOLLOWED)
        refs.append(f"{hotfix.repo}#{hotfix.number}")

    incident = detect_incident_link(target, incidents, window_days)
    if incident:
        labels.append(OutcomeLabel.INCIDENT_LINKED)
        refs.append(incident.id)

    if ci_failed:
        labels.append(OutcomeLabel.MAIN_CI_FAILED)

    if not labels:
        labels.append(OutcomeLabel.CLEAN)

    refs = list(dict.fromkeys(refs))
    return Outcome(
        repo=target.repo,
        pr_number=target.number,
        merge_sha=target.merge_sha,
        tier_at_merge=tier_at_merge,
        labels=labels,
        evidence_refs=refs,
        window_days=window_days,
    )


def load_incident_refs(incidents_json_text: str) -> list[IncidentRef]:
    import json

    data = json.loads(incidents_json_text)
    items = data.get("incidents", []) if isinstance(data, dict) else data
    out: list[IncidentRef] = []
    for it in items:
        pr_refs = []
        for pr in it.get("prs", []):
            ref = str(pr)
            if "#" in ref:
                repo, num = ref.rsplit("#", 1)
                try:
                    pr_refs.append((repo.strip(), int(num)))
                except ValueError:
                    pass
        out.append(
            IncidentRef(
                id=str(it.get("id", "")),
                started_at=str(it.get("started_at", "")),
                pr_refs=pr_refs,
                commit_shas=[str(c) for c in it.get("commits", [])],
                paths=[str(p) for p in it.get("paths", [])],
            )
        )
    return out


def outcome_from_dict(d: dict[str, Any]) -> Outcome:
    return Outcome(
        repo=d["repo"],
        pr_number=int(d["pr_number"]),
        merge_sha=d.get("merge_sha", ""),
        tier_at_merge=Tier(d["tier_at_merge"]) if d.get("tier_at_merge") else None,
        labels=[OutcomeLabel(l) for l in d.get("labels", [])],
        evidence_refs=list(d.get("evidence_refs", [])),
        window_days=int(d.get("window_days", 14)),
    )
