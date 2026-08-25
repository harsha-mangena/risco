from __future__ import annotations

from risco.models import Approval, RequiredReviewers, Tier, Verdict
from risco.verdict.enforcement import evaluate_enforcement


def verdict(**kw):
    rr = RequiredReviewers(
        min_approvals=kw.pop("min_approvals", 1),
        require_owners=kw.pop("require_owners", False),
        require_consumer_owners=kw.pop("require_consumer_owners", False),
        teams=kw.pop("teams", []),
        owner_paths=kw.pop("owner_paths", []),
        consumer_owner_teams=kw.pop("consumer_owner_teams", []),
    )
    return Verdict(tier=Tier.HIGH, score=30, required_reviewers=rr)


def appr(user, sha="HEAD", state="APPROVED", teams=()):
    return Approval(user=user, state=state, sha=sha, team_memberships=list(teams))


def test_min_approvals_basic():
    v = verdict(min_approvals=2)
    res = evaluate_enforcement(v, [appr("a"), appr("b")], "HEAD", [], {}, {}, {})
    assert res.satisfied
    res2 = evaluate_enforcement(v, [appr("a")], "HEAD", [], {}, {}, {})
    assert not res2.satisfied
    assert "have 1" in res2.missing[0]


def test_stale_sha_ignored():
    v = verdict(min_approvals=1)
    res = evaluate_enforcement(v, [appr("a", sha="oldsha")], "newsha", [], {}, {}, {})
    assert not res.satisfied


def test_owner_required_per_path():
    v = verdict(min_approvals=1, require_owners=True)
    owners = {"db/m.sql": ["@carla"], "src/x.py": ["@diego"]}
    ok = evaluate_enforcement(v, [appr("carla"), appr("diego")], "HEAD", ["db/m.sql", "src/x.py"], owners, {}, {})
    assert ok.satisfied
    partial = evaluate_enforcement(v, [appr("carla")], "HEAD", ["db/m.sql", "src/x.py"], owners, {}, {})
    assert not partial.satisfied
    assert any("src/x.py" in m for m in partial.missing)


def test_team_requirement():
    v = verdict(min_approvals=1, teams=["platform-leads"])
    members = {"platform-leads": ["ana", "bruno"]}
    ok = evaluate_enforcement(v, [appr("ana", teams=["platform-leads"])], "HEAD", [], {}, {}, members)
    assert ok.satisfied
    bad = evaluate_enforcement(v, [appr("zed")], "HEAD", [], {}, {}, members)
    assert not bad.satisfied
    assert any("@platform-leads" in m for m in bad.missing)


def test_consumer_owner_requirement():
    v = verdict(min_approvals=1, require_consumer_owners=True)
    cons = {"web": ["@web-owners"], "ops-console": ["@ops-owners"]}
    members = {"web-owners": ["farid"], "ops-owners": ["hana"]}
    ok = evaluate_enforcement(v, [appr("farid"), appr("hana")], "HEAD", [], {}, cons, members)
    assert ok.satisfied
    missing_one = evaluate_enforcement(v, [appr("farid")], "HEAD", [], {}, cons, members)
    assert not missing_one.satisfied
    assert any("ops-console" in m for m in missing_one.missing)


def test_non_approved_state_not_counted():
    v = verdict(min_approvals=1)
    res = evaluate_enforcement(v, [appr("a", state="COMMENTED"), appr("b", state="CHANGES_REQUESTED")], "HEAD", [], {}, {}, {})
    assert not res.satisfied


def test_dismissed_then_reapproved_on_new_head():
    v = verdict(min_approvals=1)
    approvals = [appr("a", sha="s1", state="CHANGES_REQUESTED"), appr("a", sha="s2")]
    res = evaluate_enforcement(v, approvals, "s2", [], {}, {}, {})
    assert res.satisfied and res.approvals_count == 1
