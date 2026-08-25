from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from risco.models import (
    Category,
    Confidence,
    Consumer,
    ContractChange,
    Finding,
    RequiredReviewers,
    Tier,
    UncertaintyFlag,
    Verdict,
)
from risco.policy.loader import ENGINE_VERSION, Policy

CONF_MULT_KEY = {
    Confidence.HIGH.value: "HIGH_confidence_service",
    Confidence.MEDIUM.value: "MEDIUM_confidence_service",
    Confidence.LOW.value: "LOW_confidence_service",
}

UNCERTAINTY_FLAG_TO_CONFIG = {
    UncertaintyFlag.INDEX_MISSING.value: "index_missing",
    UncertaintyFlag.INDEX_STALE.value: "index_stale",
    UncertaintyFlag.UNRESOLVED_CONSUMERS.value: "unresolved_consumers",
    UncertaintyFlag.MIGRATION_UNPARSEABLE.value: "migration_unparseable",
    UncertaintyFlag.CONTRACT_TOOL_UNAVAILABLE.value: "contract_tool_unavailable",
}


@dataclass
class OwnershipInput:
    owners_by_path: dict[str, list[str]] = field(default_factory=dict)
    sensitive_paths_fired: list[tuple[str, list[str]]] = field(default_factory=list)


@dataclass
class EvalInputs:
    repo: str = ""
    changed_paths: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    contract_changes: list[ContractChange] = field(default_factory=list)
    consumers_by_change: dict[str, list[Consumer]] = field(default_factory=dict)
    unresolved_relevant: list[dict] = field(default_factory=list)
    ownership: OwnershipInput = field(default_factory=OwnershipInput)
    consumer_owners: dict[str, list[str]] = field(default_factory=dict)
    policy_hash: str = ""
    policy: Optional[object] = None
    index_present: bool = False
    index_age_hours: Optional[float] = None
    tool_flags: list[str] = field(default_factory=list)


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            f.category.value,
            f.id,
            f.location.path,
            f.location.line_start,
            f.title,
        ),
    )


def _change_key(c: ContractChange) -> str:
    return c.operation.key()


def evaluate(inputs: EvalInputs) -> Verdict:
    policy = inputs.policy
    findings = _sorted_findings(inputs.findings)
    sev_weights = policy.weights.severity

    weighted: list[Finding] = []
    for f in findings:
        w = sev_weights.get(f.severity.value, 0)
        if f.id == "R-INC-001":
            w = 0
        nf = f.model_copy(update={"weight": w})
        weighted.append(nf)

    score = sum(f.weight for f in weighted)

    inc_findings = [f for f in weighted if f.id == "R-INC-001"]
    inc_count = 0
    for f in inc_findings:
        incidents = f.details.get("incidents", []) or []
        inc_count += len(incidents)
    if inc_count:
        per = policy.weights.incident_exposure.get("per_incident", 5)
        cap = policy.weights.incident_exposure.get("cap", 20)
        score += min(inc_count * per, cap)

    consumer_bonus = 0
    mult_cap = policy.weights.consumer_multiplier.get("cap", 30)
    consumer_details: list[str] = []
    for change in sorted(inputs.contract_changes, key=_change_key):
        if not change.breaking:
            continue
        key = _change_key(change)
        consumers = inputs.consumers_by_change.get(key, [])
        best_per_service: dict[str, Consumer] = {}
        for c in consumers:
            cur = best_per_service.get(c.service)
            if cur is None or _rank(c.confidence.value) > _rank(cur.confidence.value):
                best_per_service[c.service] = c
        for svc in sorted(best_per_service):
            c = best_per_service[svc]
            mkey = CONF_MULT_KEY.get(c.confidence.value)
            bonus = int(policy.weights.consumer_multiplier.get(mkey, 0)) if mkey else 0
            consumer_bonus += bonus
            consumer_details.append(f"{change.change_id} consumed by {svc} ({c.confidence.value})")
    score += min(consumer_bonus, mult_cap)

    tier_name = policy.tier_for_score(score)
    tier = Tier(tier_name)

    hard_fired: list[str] = []
    finding_ids = {f.id for f in weighted}
    for rule in policy.hard_rules:
        matched = False
        if rule.trigger == "finding" and isinstance(rule.value, str):
            matched = rule.value in finding_ids
        elif rule.trigger == "any_breaking_contract_with_consumers":
            if rule.value:
                matched = _breaking_with_consumers(inputs.contract_changes, inputs.consumers_by_change)
        elif rule.trigger == "paths":
            if isinstance(rule.value, list):
                matched = any(rule.applies_to_path(p) for p in inputs.changed_paths)
        if not matched:
            continue
        label = f"{rule.trigger}:{rule.value}"
        hard_fired.append(label)
        if rule.tier:
            t = Tier(str(rule.tier))
            tier = t
        elif rule.min_tier:
            t = Tier(str(rule.min_tier))
            if t.rank > tier.rank:
                tier = t

    if any(f.id == "R-POL-001" for f in weighted):
        floor = Tier("MEDIUM")
        if floor.rank > tier.rank:
            tier = floor

    flags = _uncertainty_flags(inputs)
    for flag in flags:
        cfg_key = UNCERTAINTY_FLAG_TO_CONFIG.get(flag)
        if not cfg_key:
            continue
        floor_name = getattr(policy.uncertainty, cfg_key, None)
        if not floor_name:
            continue
        floor = Tier(floor_name)
        if floor.rank > tier.rank:
            tier = floor

    rr = _required_reviewers(policy, tier.value, inputs)

    reasons = _reasons(weighted, hard_fired, flags, consumer_details, score, tier)

    return Verdict(
        tier=tier,
        score=int(score),
        hard_rules_fired=hard_fired,
        reasons=reasons,
        required_reviewers=rr,
        uncertainty_flags=sorted(flags),
        policy_hash=inputs.policy_hash,
        engine_version=ENGINE_VERSION,
    )


def _rank(conf: str) -> int:
    return {"HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(conf, 0)


def _breaking_with_consumers(changes: list[ContractChange], cmap: dict[str, list[Consumer]]) -> bool:
    for c in changes:
        if not c.breaking:
            continue
        if cmap.get(_change_key(c)):
            return True
    return False


def _uncertainty_flags(inputs: EvalInputs) -> set[str]:
    flags: set[str] = set()
    if not inputs.index_present:
        flags.add(UncertaintyFlag.INDEX_MISSING.value)
    else:
        max_age = inputs.policy.index.max_age_hours
        if inputs.index_age_hours is None or inputs.index_age_hours > max_age:
            flags.add(UncertaintyFlag.INDEX_STALE.value)
    if inputs.unresolved_relevant:
        flags.add(UncertaintyFlag.UNRESOLVED_CONSUMERS.value)
    if any(f.id == "R-DDL-900" for f in inputs.findings):
        flags.add(UncertaintyFlag.MIGRATION_UNPARSEABLE.value)
    for fl in inputs.tool_flags:
        flags.add(fl)
    return flags


def _required_reviewers(policy: Policy, tier_name: str, inputs: EvalInputs) -> RequiredReviewers:
    routing = policy.routing.get(tier_name) or policy.routing["LOW"]
    rr = RequiredReviewers(
        min_approvals=routing.min_approvals,
        require_owners=routing.require_owners,
        require_consumer_owners=routing.require_consumer_owners,
    )
    if routing.require_owners:
        owner_union: set[str] = set()
        paths_with_owners: list[str] = []
        for p in sorted(set(inputs.changed_paths)):
            owners = inputs.ownership.owners_by_path.get(p, [])
            if owners:
                paths_with_owners.append(p)
                owner_union.update(o.lstrip("@") for o in owners)
        rr.owner_paths = sorted(set(paths_with_owners))
        rr.owner_users = sorted(owner_union)
    rr.teams = sorted({t.lstrip("@").split("/")[-1] for t in routing.require_teams})
    if routing.require_consumer_owners:
        teams: set[str] = set()
        for svc in sorted(inputs.consumer_owners):
            for o in inputs.consumer_owners[svc]:
                teams.add(str(o).lstrip("@"))
        rr.consumer_owner_teams = sorted(teams)
    return rr


def _reasons(
    weighted: list[Finding],
    hard_fired: list[str],
    flags: set[str],
    consumer_details: list[str],
    score: int,
    tier: Tier,
) -> list[str]:
    reasons: list[tuple[int, str]] = []
    contributing = [f for f in weighted if f.weight > 0]
    for f in contributing:
        loc = f"{f.location.path}:{f.location.line_start}" if f.location.path else ""
        prefix = f"[{loc}] " if loc else ""
        reasons.append((f.weight, f"{prefix}{f.id} {f.title} (+{f.weight})"))
    for line in consumer_details:
        reasons.append((0, line))
    for h in hard_fired:
        reasons.append((1000, f"hard rule matched: {h}"))
    for fl in sorted(flags):
        reasons.append((500, f"uncertainty: {fl}"))
    reasons.sort(key=lambda r: (-r[0], r[1]))
    out = [r[1] for r in reasons]
    out.append(f"score {score} -> tier {tier.value}")
    return out


def apply_override(verdict: Verdict, override_target: str, policy: Policy) -> tuple[Verdict, bool, str]:
    try:
        target = Tier(override_target)
    except ValueError:
        return verdict, False, f"unknown tier '{override_target}'"
    current = verdict.tier
    if target.rank >= current.rank:
        return verdict, False, "override must downgrade the tier"
    downgrade = current.rank - target.rank
    if downgrade > policy.overrides.max_downgrade:
        return (
            verdict,
            False,
            f"override exceeds max_downgrade={policy.overrides.max_downgrade}",
        )
    updated = verdict.model_copy(
        update={
            "tier": target,
            "required_reviewers": _routing_for(policy, target),
        }
    )
    return updated, True, ""


def _routing_for(policy: Policy, tier: Tier) -> RequiredReviewers:
    routing = policy.routing.get(tier.value) or policy.routing["LOW"]
    return RequiredReviewers(
        min_approvals=routing.min_approvals,
        require_owners=routing.require_owners,
        require_consumer_owners=routing.require_consumer_owners,
        teams=sorted({t.lstrip("@").split("/")[-1] for t in routing.require_teams}),
    )
