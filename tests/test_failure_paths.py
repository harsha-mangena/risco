from __future__ import annotations

import json
import os
import urllib.error

import pytest

import risco.pipeline as pipeline_mod
from conftest import NOW
BREAKING_SOURCES = None


@pytest.fixture()
def sources():
    from test_pipeline_golden import BREAKING_SOURCES as BS

    return BS


def test_analyzer_crash_yields_neutral(monkeypatch, snap, orders_policy, sources):
    def boom(*a, **k):
        raise RuntimeError("exploded")

    monkeypatch.setattr(pipeline_mod, "analyze_migrations", boom)
    from risco.pipeline import AnalysisSources

    entries = [("db/migrations/0231_new.sql", "A", None)]
    src = AnalysisSources(base_texts={}, head_texts={"db/migrations/0231_new.sql": "SELECT 1;"})
    res = pipeline_mod.Analyzer(
        orders_policy,
        snap.conn,
        snap.manifest,
        repo_full="acme/orders-api",
        pr_number=1,
        head_sha="abc",
        now_iso=NOW,
    ).run(entries, src, [])
    assert res.is_neutral
    assert "exploded" in res.neutral_reason
    assert res.error_id
    assert "NEUTRAL" in res.summary_markdown


def test_contract_tool_unavailable_when_binary_missing(monkeypatch, snap, orders_policy):
    monkeypatch.delenv("RISCO_OASDIFF_BIN", raising=False)
    monkeypatch.setattr(
        pipeline_mod, "find_oasdiff", lambda: None, raising=False
    ) if hasattr(pipeline_mod, "find_oasdiff") else None
    from risco.contract import oasdiff as oas_mod

    monkeypatch.setattr(oas_mod, "find_oasdiff", lambda: None)
    from risco.pipeline import AnalysisSources

    base = open(
        str(__import__("pathlib").Path(__file__).parents[1] / "fixtures/sample-org/orders-api/openapi/orders.yaml")
    ).read()
    block = (
        "        fulfillment_eta:\n"
        "          type: string\n"
        "          description: estimated delivery window shown at checkout\n"
    )
    head = base.replace(block, "")
    src = AnalysisSources(base_texts={"openapi/orders.yaml": base}, head_texts={"openapi/orders.yaml": head})
    res = pipeline_mod.Analyzer(
        orders_policy,
        snap.conn,
        snap.manifest,
        repo_full="acme/orders-api",
        pr_number=1,
        head_sha="abc",
        now_iso=NOW,
    ).run([("openapi/orders.yaml", "M", None)], src, [])
    ids = {f.id for f in res.bundle.findings}
    assert "R-CON-900" in ids
    assert "CONTRACT_TOOL_UNAVAILABLE" in res.bundle.verdict.uncertainty_flags
    assert res.bundle.verdict.tier.value in ("MEDIUM", "HIGH")

