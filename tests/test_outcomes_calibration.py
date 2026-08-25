from __future__ import annotations

import json

import pytest

from risco.models import Outcome, OutcomeLabel, Tier
from risco.outcomes.calibration import (
    confusion_table,
    load_outcomes_json,
    low_share_negative,
    never_fired_rules,
    precision_recall_high,
    render_calibration_report,
    suggested_weights_block,
)
def _o(tier, labels, pr=1):
    return Outcome(
        repo="acme/orders-api",
        pr_number=pr,
        merge_sha=f"sha{pr}",
        tier_at_merge=Tier(tier) if tier else None,
        labels=[OutcomeLabel(l) for l in labels],
    )


SAMPLE = [
    _o("HIGH", ["REVERTED"], 1),
    _o("HIGH", ["CLEAN"], 2),
    _o("HIGH", ["INCIDENT_LINKED"], 3),
    _o("MEDIUM", ["CLEAN"], 4),
    _o("LOW", ["CLEAN"], 5),
    _o("LOW", ["REVERTED"], 6),
    _o("LOW", ["CLEAN"], 7),
]


def test_precision_recall_high():
    pr = precision_recall_high(SAMPLE)
    assert (pr["tp"], pr["fp"], pr["fn"]) == (2, 1, 1)
    assert pr["precision"] == 0.667
    assert pr["recall"] == 0.667


def test_low_share_negative():
    assert low_share_negative(SAMPLE) == round(1 / 3, 3)


def test_confusion_table_counts():
    t = confusion_table(SAMPLE)
    assert t["HIGH"]["negative"] == 2
    assert t["HIGH"]["clean"] == 1
    assert t["LOW"]["negative"] == 1
    assert t["LOW"]["clean"] == 2
    assert t["MEDIUM"]["clean"] == 1


def test_never_fired_rules():
    bundles = [
        {"findings": [{"id": "R-DDL-005", "weight": 10}, {"id": "R-DDL-013", "weight": 0}]},
        {"findings": [{"id": "R-INC-001", "weight": 5}]},
    ]
    nf = never_fired_rules(bundles)
    assert nf == ["R-DDL-013"]


def test_suggested_weights_block_reacts_to_precision():
    block = suggested_weights_block(SAMPLE)
    assert "weights:" in block
    parsed = [l for l in block.splitlines() if l.strip().startswith("severity:")]
    assert len(parsed) == 1


def test_report_contains_required_sections():
    report = render_calibration_report(
        SAMPLE,
        bundles=[{"findings": [{"id": "R-DDL-013", "weight": 0}]}],
        current_weights={"severity": {"HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}},
    )
    for section in ("Tier × outcome", "HIGH quality", "Suggested adjustment", "Risco never self-tunes"):
        assert section in report
    assert "R-DDL-013" in report


def test_load_outcomes_json(tmp_path):
    payload = {
        "outcomes": [
            {
                "repo": "r",
                "pr_number": 9,
                "merge_sha": "abc",
                "tier_at_merge": "HIGH",
                "labels": ["REVERTED"],
                "evidence_refs": ["r#10"],
                "window_days": 30,
            }
        ]
    }
    path = tmp_path / "outcomes.json"
    path.write_text(json.dumps(payload))
    outcomes = load_outcomes_json(path.read_text())
    assert len(outcomes) == 1
    o = outcomes[0]
    assert o.tier_at_merge == Tier.HIGH
    assert o.labels == [OutcomeLabel.REVERTED]
    assert o.window_days == 30

