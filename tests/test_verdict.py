from __future__ import annotations

import copy

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from risco.models import (
    Category,
    Confidence,
    Consumer,
    ContractChange,
    Finding,
    Location,
    OperationRef,
    Severity,
)
from risco.policy.loader import load_policy_text
from risco.verdict.engine import EvalInputs, OwnershipInput, apply_override, evaluate

BASE_POLICY = load_policy_text("version: 1\n").policy


def mk_finding(id="R-DDL-005", sev=Severity.HIGH, path="m.sql", line=1):
    return Finding(
        id=id,
        category=Category.DDL,
        severity=sev,
        title=id,
        location=Location(repo="r", path=path, line_start=line),
    )


def breaking_change(op_path="/v2/x/{id}", method="GET"):
    return ContractChange(
        source="OPENAPI",
        operation=OperationRef(method=method, path_template=op_path),
        change_id="OAS-test-removed",
        breaking=True,
        description="removed",
    )


def consumer(service="web", conf=Confidence.HIGH, path="a.ts", line=1):
    return Consumer(
        service=service,
        repo=f"acme/{service}",
        path=path,
        line=line,
        strategy="S2_LITERAL_WITH_METHOD",
        confidence=conf,
    )


def base_inputs(**kw):
    inputs = EvalInputs(
        changed_paths=["src/a.py"],
        findings=[],
        contract_changes=[],
        consumers_by_change={},
        unresolved_relevant=[],
        ownership=OwnershipInput(owners_by_path={"src/a.py": ["@team"]}),
        policy_hash="abc",
        policy=BASE_POLICY,
        index_present=True,
        index_age_hours=1.0,
    )
    for k, v in kw.items():
        setattr(inputs, k, v)
    return inputs


def test_empty_is_low():
    v = evaluate(base_inputs())
    assert v.tier.value == "LOW"
    assert v.score == 0


def test_score_sums_weights():
    v = evaluate(base_inputs(findings=[mk_finding(sev=Severity.HIGH), mk_finding(sev=Severity.MEDIUM)]))
    assert v.score == 14


def test_consumer_multiplier_and_cap():
    ch = breaking_change()
    cmap = {ch.operation.key(): [consumer(f"svc{i}") for i in range(10)]}
    v = evaluate(base_inputs(contract_changes=[ch], consumers_by_change=cmap))
    assert v.score == 30
    assert v.tier.value == "HIGH"


def test_incident_weight_capped():
    f = Finding(
        id="R-INC-001",
        category=Category.INCIDENT,
        severity=Severity.INFO,
        title="x",
        details={"incidents": [{"id": str(i)} for i in range(10)]},
    )
    v = evaluate(base_inputs(findings=[f]))
    assert v.score == 20


def test_hard_rule_dominance_low_score():
    p = load_policy_text("version: 1\nhard_rules:\n  - {finding: R-DDL-001, tier: HIGH}\n").policy
    v = evaluate(base_inputs(findings=[mk_finding("R-DDL-001")], policy=p))
    assert v.tier.value == "HIGH"
    assert "finding:R-DDL-001" in v.hard_rules_fired


def test_paths_min_tier_floor():
    p = load_policy_text("version: 1\nhard_rules:\n  - {paths: ['src/auth/**'], min_tier: MEDIUM}\n").policy
    v = evaluate(base_inputs(changed_paths=["src/auth/login.py"], policy=p))
    assert v.tier.value == "MEDIUM"
    assert any("paths:" in h for h in v.hard_rules_fired)


def test_breaking_with_consumers_hard_rule():
    p = load_policy_text("version: 1\nhard_rules:\n  - {any_breaking_contract_with_consumers: true, tier: HIGH}\n").policy
    ch = breaking_change()
    cmap = {ch.operation.key(): [consumer()]}
    v = evaluate(base_inputs(contract_changes=[ch], consumers_by_change=cmap, policy=p))
    assert v.tier.value == "HIGH"
    assert "any_breaking_contract_with_consumers:True" in v.hard_rules_fired


def test_breaking_without_consumers_not_high_by_default():
    ch = breaking_change()
    v = evaluate(base_inputs(contract_changes=[ch], consumers_by_change={ch.operation.key(): []}))
    assert v.tier.value == "LOW"


@pytest.mark.parametrize(
    "flag_kwargs,expect_tier",
    [
        ({"index_present": False}, "MEDIUM"),
        ({"index_age_hours": 99.0}, "MEDIUM"),
        ({"unresolved_relevant": [{"file": "a"}]}, "MEDIUM"),
    ],
)
def test_uncertainty_floors(flag_kwargs, expect_tier):
    v = evaluate(base_inputs(**flag_kwargs))
    assert v.tier.value == expect_tier


def test_migration_unparseable_flag_from_findings():
    f = mk_finding("R-DDL-900", Severity.MEDIUM)
    v = evaluate(base_inputs(findings=[f]))
    assert "MIGRATION_UNPARSEABLE" in v.uncertainty_flags
    assert v.tier.value == "MEDIUM"


def test_custom_stale_threshold():
    p = load_policy_text("version: 1\nindex:\n  max_age_hours: 2\n").policy
    v = evaluate(base_inputs(index_age_hours=3.0, policy=p))
    assert "INDEX_STALE" in v.uncertainty_flags


def test_required_reviewers_high_defaults():
    p = load_policy_text("version: 1\nhard_rules:\n  - {any_breaking_contract_with_consumers: true, tier: HIGH}\n").policy
    ch = breaking_change()
    cmap = {ch.operation.key(): [consumer()]}
    inp = base_inputs(
        contract_changes=[ch],
        consumers_by_change=cmap,
        ownership=OwnershipInput(
            owners_by_path={"db/m.sql": ["@acme/orders-owners"]},
        ),
        changed_paths=["db/m.sql"],
        consumer_owners={"web": ["@acme/web-owners"]},
        policy=p,
    )
    v = evaluate(inp)
    rr = v.required_reviewers
    assert rr.min_approvals == 2
    assert rr.teams == ["platform-leads"]
    assert rr.require_owners and rr.require_consumer_owners
    assert rr.consumer_owner_teams == ["acme/web-owners"]
    assert rr.owner_users == ["acme/orders-owners"]


def test_reasons_ordered_by_contribution():
    v = evaluate(
        base_inputs(
            findings=[
                mk_finding("R-A", Severity.LOW),
                mk_finding("R-B", Severity.HIGH),
            ]
        )
    )
    reasons = [r for r in v.reasons if r.startswith("[")]
    assert reasons[0].startswith("[") and "R-B" in reasons[0]


DETERMINISM_INPUT = base_inputs(
    findings=[
        mk_finding("R-DDL-005"),
        mk_finding("R-DDL-007", Severity.MEDIUM, path="m2.sql", line=9),
    ],
)


def test_determinism_same_inputs_same_verdict():
    v1 = evaluate(copy.deepcopy(DETERMINISM_INPUT))
    v2 = evaluate(copy.deepcopy(DETERMINISM_INPUT))
    shuffled = copy.deepcopy(DETERMINISM_INPUT)
    shuffled.findings.reverse()
    v3 = evaluate(shuffled)
    import json

    a = json.loads(v1.model_dump_json())
    b = json.loads(v2.model_dump_json())
    c = json.loads(v3.model_dump_json())
    assert a == b == c


@given(
    n=st.integers(min_value=0, max_value=6),
)
@settings(max_examples=25, deadline=None)
def test_monotonic_add_findings_never_lowers_tier(n):
    base_v = evaluate(base_inputs(findings=[]))
    more = base_inputs(findings=[mk_finding(sev=Severity.LOW) for _ in range(n)])
    v = evaluate(more)
    assert v.tier.rank >= base_v.tier.rank
    assert v.score >= base_v.score


def test_removing_flag_never_raises_tier():
    stale = evaluate(base_inputs(index_age_hours=99.0))
    fresh = evaluate(base_inputs(index_age_hours=1.0))
    assert stale.tier.rank >= fresh.tier.rank


def test_apply_override_limits_downgrade():
    p = load_policy_text("version: 1\nhard_rules:\n  - {any_breaking_contract_with_consumers: true, tier: HIGH}\n").policy
    ch = breaking_change()
    cmap = {ch.operation.key(): [consumer()]}
    high = evaluate(base_inputs(contract_changes=[ch], consumers_by_change=cmap, policy=p))
    ok, allowed, msg = False, False, ""
    new, allowed, msg = apply_override(high, "MEDIUM", BASE_POLICY)
    assert allowed and new.tier.value == "MEDIUM"
    over, allowed2, msg2 = apply_override(high, "LOW", BASE_POLICY)
    assert not allowed2 and "max_downgrade" in msg2
    same, allowed3, _ = apply_override(high, "HIGH", BASE_POLICY)
    assert not allowed3


def test_routing_low_single_approval():
    v = evaluate(base_inputs())
    assert v.required_reviewers.min_approvals == 1
    assert not v.required_reviewers.require_owners
