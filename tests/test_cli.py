from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import FIXTURE_ORG, HAS_OASDIFF, NOW

REPO_ROOT = Path(__file__).resolve().parents[1]
VENV_BIN = REPO_ROOT / ".venv" / "bin"
RISCO = str(VENV_BIN / "risco") if VENV_BIN.exists() else "risco"


def run_cli(*args, env_extra=None):
    env = os.environ.copy()
    if HAS_OASDIFF:
        env.setdefault("RISCO_OASDIFF_BIN", str(REPO_ROOT / ".tools" / "bin" / "oasdiff"))
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, "-m", "risco.cli", *args], capture_output=True, text=True, env=env, cwd=str(REPO_ROOT))


def test_validate_policy_ok_and_bad(tmp_path):
    good = run_cli("validate-policy", str(FIXTURE_ORG / "orders-api" / "risco.yml"))
    assert good.returncode == 0 and "OK" in good.stdout
    bad = tmp_path / "bad.yml"
    bad.write_text("version: 1\nnot_a_key: true\n")
    res = run_cli("validate-policy", str(bad))
    assert res.returncode == 2


def test_index_analyze_replay_calibrate_offline(tmp_path):
    index_dir = tmp_path / "index"
    ix = run_cli(
        "index",
        "--repos-dir", str(FIXTURE_ORG),
        "--out", str(index_dir),
        "--incidents", str(FIXTURE_ORG / "org" / "incidents.json"),
        "--teams", str(FIXTURE_ORG / "org" / "teams.json"),
        "--org-codeowners", str(FIXTURE_ORG / "org" / "CODEOWNERS"),
        "--now", NOW,
    )
    assert ix.returncode == 0, ix.stderr
    manifest = json.loads((index_dir / "manifest.json").read_text())
    assert manifest["counts"]["consumers"] >= 3

    base = tmp_path / "base"
    head = tmp_path / "head"
    shutil.copytree(FIXTURE_ORG / "orders-api", base)
    shutil.copytree(FIXTURE_ORG / "orders-api", head)
    sql = "ALTER TABLE orders DROP COLUMN region;\n"
    (head / "db/migrations/0232_drop.sql").write_text(sql)
    out_dir = tmp_path / "evidence"

    policy_path = str(head / "risco.yml")
    an = run_cli(
        "analyze",
        "--repo", "acme/orders-api",
        "--pr", "9001",
        "--base-sha", "b" * 7,
        "--head-sha", "c" * 7,
        "--base-dir", str(base),
        "--head-dir", str(head),
        "--policy", str(FIXTURE_ORG / "orders-api" / "risco.yml"),
        "--index", str(index_dir),
        "--mode", "enforce",
        "--out", str(out_dir),
        "--json-out", str(tmp_path / "res.json"),
        "--summary-out", str(tmp_path / "summary.md"),
        "--now", NOW,
    )
    assert an.returncode == 0, an.stderr
    payload = json.loads(an.stdout.strip().splitlines()[-1])
    assert payload["tier"] == "HIGH"
    assert payload["bundle_hash"]
    evidence_file = Path(payload["evidence_path"])
    bundle = json.loads(evidence_file.read_text())
    assert any(f["id"] == "R-DDL-002" for f in bundle["findings"])

    cases = [
        {
            "name": "9001-drop",
            "repo_full": "acme/orders-api",
            "pr_number": 9001,
            "base_dir": str(base),
            "head_dir": str(head),
            "merged_at": NOW,
            "outcome_labels": ["INCIDENT_LINKED"],
        }
    ]
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(json.dumps(cases))
    rp = run_cli(
        "replay",
        "--cases", str(cases_path),
        "--policy", policy_path,
        "--index", str(index_dir),
        "--report-out", str(tmp_path / "report.md"),
        "--now", NOW,
    )
    assert rp.returncode == 0
    report = (tmp_path / "report.md").read_text()
    assert "retroactive audit" in report

    outcomes = [
        {"repo": "acme/orders-api", "pr_number": 9001, "merge_sha": "x", "tier_at_merge": "HIGH", "labels": ["INCIDENT_LINKED"]},
        {"repo": "acme/orders-api", "pr_number": 8000, "merge_sha": "y", "tier_at_merge": "LOW", "labels": ["CLEAN"]},
    ]
    oc_path = tmp_path / "outcomes.json"
    oc_path.write_text(json.dumps({"outcomes": outcomes}))
    cal = run_cli("calibrate", "--outcomes", str(oc_path), "--report-out", str(tmp_path / "cal.md"))
    assert cal.returncode == 0
    assert "calibration report" in (tmp_path / "cal.md").read_text()


def test_analyze_requires_inputs(tmp_path):
    res = run_cli("analyze", "--policy", str(FIXTURE_ORG / "orders-api" / "risco.yml"))
    assert res.returncode != 0
