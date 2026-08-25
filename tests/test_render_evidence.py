from __future__ import annotations

import json
from pathlib import Path

import pytest

from risco.canonical import canonical_bytes, sha256_hex
from risco.evidence.bundle import build_bundle, write_bundle
from risco.models import Finding, Location, Severity, Tier, Verdict
def _verdict(tier=Tier.MEDIUM, score=8):
    return Verdict(tier=tier, score=score, policy_hash="h", engine_version="e")


def _bundle(tmp_path, **kw):
    return build_bundle(
        repo="acme/orders-api",
        pr_number=1,
        base_sha="a",
        head_sha="b" * 40,
        index_snapshot_id="snap",
        tool_versions={"oasdiff": "v"},
        inputs={"changed_files": ["m.sql"]},
        findings=[
            Finding(
                id="R-DDL-005",
                category="DDL",
                severity=Severity.HIGH,
                title="t",
                location=Location(repo="r", path=f"f{i}.sql", line_start=i + 1),
            )
            for i in range(60)
        ],
        consumers=[],
        contract_changes=[],
        verdict=_verdict(**{k: v for k, v in kw.items() if k in ("tier", "score")}),
        generated_at="2026-08-25T12:00:00+00:00",
    )


def test_bundle_hash_is_sha256_of_canonical_payload():
    b = _bundle(None)
    raw = json.loads(b.model_dump_json())
    payload = {k: v for k, v in raw.items() if k != "bundle_hash"}
    assert sha256_hex(canonical_bytes(payload)) == raw["bundle_hash"]


def test_write_bundle_roundtrip(tmp_path):
    b = _bundle(None)
    path, h = write_bundle(b, str(tmp_path))
    assert Path(path).exists()
    loaded = json.loads(Path(path).read_text())
    assert loaded["bundle_hash"] == h == b.bundle_hash


def test_no_source_text_in_bundle():
    b = _bundle(None)
    text = b.model_dump_json()
    assert "raw_content" not in text
    for f in b.findings:
        assert set(f.details.keys()) <= set()


def test_render_summary_and_comment():
    from risco.evidence.bundle import build_bundle as bb
    from risco.render.render import (
        COMMENT_MARKER,
        build_annotations,
        render_comment,
        render_summary,
    )

    b = _bundle(None)
    summary = render_summary(b, "enforce", ["2 approvals — have 0"])
    assert "Risco / merge-risk — MEDIUM" in summary
    assert "Required to merge" in summary
    comment = render_comment(b, "enforce", ["x"], collapse_low_tier=False)
    assert COMMENT_MARKER in comment

    low = _bundle(None, tier=Tier.LOW, score=0)
    collapsed = render_comment(low, "advisory", [], collapse_low_tier=True)
    assert "<details>" in collapsed and COMMENT_MARKER in collapsed

    anns = build_annotations(b)
    assert all(len(batch) <= 50 for batch in anns)
    assert sum(len(x) for x in anns) == 60
    assert anns[0][0]["annotation_level"] == "failure"


def test_parse_override_command():
    from risco.render.render import parse_override_command

    ok, tier, reason = parse_override_command("/risco override MEDIUM reason: hotfix window")
    assert ok and tier == "MEDIUM" and reason == "hotfix window"
    ok2, _, _ = parse_override_command("looks like /risco overide typo")
    assert not ok2
