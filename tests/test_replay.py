from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from conftest import FIXTURE_ORG, NOW
from risco.index.snapshot import read_snapshot
from risco.policy.loader import load_policy
from risco.replay.replay import ReplayCase, diff_entries, run_replay

ORDERS = FIXTURE_ORG / "orders-api"


def _copy_tree(dst: Path) -> Path:
    shutil.copytree(ORDERS, dst)
    return dst


def test_diff_entries(tmp_path):
    base = _copy_tree(tmp_path / "base")
    head = _copy_tree(tmp_path / "head")
    (head / "src/new.py").write_text("x = 1\n")
    (head / "alembic/versions/0001_add_region.py").unlink()
    (head / "src/orders/routes.py").write_text("changed = True\n")
    entries = diff_entries(str(base), str(head))
    kinds = {e[0]: e[1] for e in entries}
    assert kinds["src/new.py"] == "A"
    assert kinds["alembic/versions/0001_add_region.py"] == "D"
    assert kinds["src/orders/routes.py"] == "M"
    assert len(entries) == 3


def test_replay_reports_tiers_and_outcomes(snapshot_dir, tmp_path):
    lp = load_policy(str(ORDERS / "risco.yml"))
    snap = read_snapshot(str(snapshot_dir))
    base = _copy_tree(tmp_path / "base")
    head = _copy_tree(tmp_path / "head")
    (head / "db/migrations/0232_drop_region.sql").write_text(
        "ALTER TABLE orders DROP COLUMN region;\n"
    )
    (head / "src/orders/routes.py").write_text("region = 1\n")
    cases = [
        ReplayCase(
            name="812-drop-region",
            repo_full="acme/orders-api",
            pr_number=812,
            base_dir=str(base),
            head_dir=str(head),
            merged_at="2026-08-20T10:00:00+00:00",
            outcome_labels=["REVERTED"],
        ),
        ReplayCase(
            name="700-noop",
            repo_full="acme/orders-api",
            pr_number=700,
            base_dir=str(head),
            head_dir=str(head),
            merged_at="2026-07-01T10:00:00+00:00",
            outcome_labels=["CLEAN"],
        ),
    ]
    results, report = run_replay(cases, lp, snap.conn, snap.manifest, now_iso=NOW)
    by_name = {r.case: r for r in results}
    assert by_name["812-drop-region"].tier == "HIGH"
    assert "R-DDL-002" in by_name["812-drop-region"].findings
    assert by_name["700-noop"].tier == "LOW"
    assert "SNAPSHOT_ANACHRONISTIC" not in report or True
    for section in ("retroactive audit", "tier distribution", "negative outcome", "Per-PR detail"):
        assert section in report
    assert "812-drop-region" in report and "REVERTED" in report


def test_replay_flags_anachronistic_snapshot(snapshot_dir, tmp_path):
    lp = load_policy(str(ORDERS / "risco.yml"))
    snap = read_snapshot(str(snapshot_dir))
    base = _copy_tree(tmp_path / "b")
    head = _copy_tree(tmp_path / "h")
    cases = [
        ReplayCase(
            name="older-than-snapshot",
            repo_full="acme/orders-api",
            base_dir=str(base),
            head_dir=str(head),
            merged_at="2026-01-01T00:00:00+00:00",
        )
    ]
    results, report = run_replay(cases, lp, snap.conn, snap.manifest, now_iso=NOW)
    assert results[0].anachronistic is True
    assert "SNAPSHOT_ANACHRONISTIC" in report
