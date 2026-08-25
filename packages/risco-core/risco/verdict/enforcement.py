from __future__ import annotations

from dataclasses import dataclass, field

from risco.models import Approval, RequiredReviewers, Verdict


@dataclass
class EnforcementResult:
    satisfied: bool
    approvals_count: int = 0
    required_approvals: int = 0
    missing: list[str] = field(default_factory=list)


def _approved_users(approvals: list[Approval], head_sha: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for a in approvals:
        if a.state.upper() != "APPROVED":
            continue
        if head_sha and a.sha and a.sha != head_sha:
            continue
        u = a.user.lstrip("@")
        if u not in seen:
            seen.add(u)
            out.append(u)
    return sorted(out)


def _expand_owner_token(token: str, team_members: dict[str, list[str]]) -> set[str]:
    t = token.strip().lstrip("@")
    if "/" in t:
        t = t.split("/")[-1]
    members = team_members.get(t)
    if members:
        return {m.lstrip("@") for m in members}
    return {t}


def _owner_users(tokens: list[str], team_members: dict[str, list[str]]) -> set[str]:
    out: set[str] = set()
    for tok in tokens:
        out |= _expand_owner_token(tok, team_members)
    return out


def evaluate_enforcement(
    verdict: Verdict,
    approvals: list[Approval],
    head_sha: str,
    changed_paths: list[str],
    owners_by_path: dict[str, list[str]],
    consumer_owners_by_service: dict[str, list[str]],
    team_members: dict[str, list[str]],
) -> EnforcementResult:
    rr = verdict.required_reviewers
    approved = _approved_users(approvals, head_sha)
    approved_set = set(approved)
    result = EnforcementResult(
        satisfied=True,
        approvals_count=len(approved),
        required_approvals=rr.min_approvals,
    )

    if len(approved) < rr.min_approvals:
        result.satisfied = False
        result.missing.append(
            f"{rr.min_approvals} approval(s) on head {head_sha[:7] or '(head)'} — have {len(approved)}"
        )

    if rr.require_owners:
        unowned_paths: dict[str, list[str]] = {}
        for p in sorted(set(changed_paths)):
            owners = _owner_users(owners_by_path.get(p, []), team_members)
            if not owners & approved_set:
                unowned_paths.setdefault(",".join(sorted(o for o in owners_by_path.get(p, []))) or "(no owners)", []).append(p)
        if unowned_paths:
            result.satisfied = False
            for owner_key, paths in sorted(unowned_paths.items()):
                shown = ", ".join(paths[:3])
                more = "" if len(paths) <= 3 else f" (+{len(paths) - 3} more)"
                label = ", ".join("@" + o.lstrip("@") for o in owner_key.split(",") if o and o != "(no owners)")
                if not label:
                    result.missing.append(f"Owner approval missing for {shown}{more}")
                else:
                    result.missing.append(f"Owner of {shown}{more} — {label}")

    for team in rr.teams:
        members = {m.lstrip("@") for m in team_members.get(team, [])}
        if not members & approved_set:
            result.satisfied = False
            result.missing.append(f"Team — @{team}")

    if rr.require_consumer_owners and consumer_owners_by_service:
        for svc in sorted(consumer_owners_by_service):
            owners = _owner_users(consumer_owners_by_service.get(svc, []), team_members)
            if not owners & approved_set:
                result.satisfied = False
                label = ", ".join("@" + o.lstrip("@") for o in sorted(consumer_owners_by_service.get(svc, []))[:3])
                result.missing.append(f"Consumer owner of {svc} — {label}" if label else f"Consumer owner of {svc}")

    return result
