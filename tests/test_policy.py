from __future__ import annotations

import pytest

from risco.errors import PolicyError
from risco.policy.loader import DEFAULT_ROUTING, DEFAULT_SEVERITY_WEIGHTS, load_policy_text


def test_defaults_equivalent_to_spec():
    p = load_policy_text("version: 1\n").policy
    assert p.mode == "advisory"
    assert p.weights.severity == DEFAULT_SEVERITY_WEIGHTS
    assert p.tiers["LOW"].max_score == 5
    assert p.tiers["MEDIUM"].max_score == 19
    assert p.tiers["HIGH"].min_score == 20
    assert p.routing["HIGH"].require_consumer_owners is True
    assert p.routing["HIGH"].min_approvals == 2
    assert p.uncertainty.index_missing == "MEDIUM"
    assert p.overrides.max_downgrade == 1
    assert p.index.max_age_hours == 36
    assert DEFAULT_ROUTING["MEDIUM"]["require_owners"] is True


def test_tier_boundaries():
    p = load_policy_text("version: 1\n").policy
    assert p.tier_for_score(0) == "LOW"
    assert p.tier_for_score(5) == "LOW"
    assert p.tier_for_score(6) == "MEDIUM"
    assert p.tier_for_score(19) == "MEDIUM"
    assert p.tier_for_score(20) == "HIGH"


CUSTOM_TIERS = """
version: 1
tiers:
  LOW: {max_score: 9}
  MEDIUM: {max_score: 15}
  HIGH: {min_score: 16}
"""


def test_custom_tiers():
    p = load_policy_text(CUSTOM_TIERS).policy
    assert p.tier_for_score(9) == "LOW"
    assert p.tier_for_score(10) == "MEDIUM"
    assert p.tier_for_score(15) == "MEDIUM"
    assert p.tier_for_score(16) == "HIGH"


def test_unknown_key_rejected():
    with pytest.raises(PolicyError):
        load_policy_text("version: 1\nmodee: advisory\n")


def test_bad_version_rejected():
    with pytest.raises(PolicyError):
        load_policy_text("version: 99\n")


def test_hard_rule_multi_trigger_rejected():
    with pytest.raises(PolicyError):
        load_policy_text(
            "version: 1\nhard_rules:\n  - {finding: X, paths: ['a'], tier: HIGH}\n"
        )


def test_hard_rule_no_effect_rejected():
    with pytest.raises(PolicyError):
        load_policy_text("version: 1\nhard_rules:\n  - {finding: X}\n")


def test_service_aliases():
    p = load_policy_text(
        """
version: 1
service:
  name: orders-api
  contracts:
    openapi: [openapi/orders.yaml]
    protobuf: [proto/]
  migrations:
    paths: [db/migrations/**/*.sql]
  base_url_env: [ORDERS_SERVICE_URL]
"""
    ).policy
    svc = p.service.resolved()
    assert svc.is_contract("openapi/orders.yaml") == "openapi"
    assert svc.is_migration("db/migrations/1.sql")
    assert not svc.is_migration("src/x.py")
    assert svc.base_url_env == ["ORDERS_SERVICE_URL"]


def test_policy_hash_changes_with_content():
    a = load_policy_text("version: 1\nmode: advisory\n")
    b = load_policy_text("version: 1\nmode: enforce\n")
    c = load_policy_text("mode: advisory\nversion: 1\n")
    assert a.policy_hash != b.policy_hash
    assert a.policy_hash == c.policy_hash
