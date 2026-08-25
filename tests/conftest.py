from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CORE = REPO_ROOT / "packages" / "risco-core"
for p in (str(CORE), str(REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

FIXTURE_ORG = REPO_ROOT / "fixtures" / "sample-org"
TEST_FIXTURES = Path(__file__).parent / "fixtures"

OASDIFF_BIN = os.environ.get(
    "RISCO_OASDIFF_BIN",
    str(REPO_ROOT / ".tools" / "bin" / "oasdiff"),
)
HAS_OASDIFF = os.path.isfile(OASDIFF_BIN)
if HAS_OASDIFF:
    os.environ.setdefault("RISCO_OASDIFF_BIN", OASDIFF_BIN)

NOW = "2026-08-25T12:00:00+00:00"


@pytest.fixture(scope="session")
def fixture_org() -> Path:
    return FIXTURE_ORG


@pytest.fixture(scope="session")
def snapshot_dir() -> Path:
    from risco.consumers.index_builder import build_index_data, dedupe_rows
    from risco.index.snapshot import write_snapshot_dir

    repos = {}
    org_prefix = "acme/"
    for child in sorted(FIXTURE_ORG.iterdir()):
        if child.is_dir() and child.name != "org":
            repos[org_prefix + child.name] = str(child)
    incidents_text = (FIXTURE_ORG / "org" / "incidents.json").read_text()
    teams_text = (FIXTURE_ORG / "org" / "teams.json").read_text()
    org_co = (FIXTURE_ORG / "org" / "CODEOWNERS").read_text()
    data, warnings = build_index_data(repos, incidents_text, teams_text, org_co)
    data = dedupe_rows(data)
    out = Path(tempfile.mkdtemp(prefix="risco-test-index-"))
    manifest = write_snapshot_dir(data, str(out), generated_at=NOW)
    assert not [w for w in warnings if "invalid" in w], warnings
    out.joinpath("manifest.json").write_text(json.dumps(manifest, indent=2))
    return out


@pytest.fixture(scope="session")
def snap(snapshot_dir):
    from risco.index.snapshot import read_snapshot

    return read_snapshot(str(snapshot_dir))


@pytest.fixture(scope="session")
def orders_policy():
    from risco.policy.loader import load_policy

    return load_policy(str(FIXTURE_ORG / "orders-api" / "risco.yml"))


def load_recorded(name: str):
    return json.loads((TEST_FIXTURES / f"{name}.json").read_text())
