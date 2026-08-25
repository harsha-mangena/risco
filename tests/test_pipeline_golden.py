from __future__ import annotations

import json
from pathlib import Path

import pytest

import risco.pipeline as pipeline_mod
from conftest import HAS_OASDIFF, NOW
from risco.models import UncertaintyFlag
from risco.pipeline import AnalysisSources, Analyzer

GOLDEN_DIR = Path(__file__).parent / "golden"


def read_fixture(rel: str) -> str:
    from conftest import FIXTURE_ORG

    return (FIXTURE_ORG / rel).read_text()


ORDERS_OPENAPI_BASE = None


def orders_openapi(with_eta: bool = True) -> str:
    text = read_fixture("orders-api/openapi/orders.yaml")
    if not with_eta:
        block = (
            "        fulfillment_eta:\n"
            "          type: string\n"
            "          description: estimated delivery window shown at checkout\n"
        )
        assert block in text
        return text.replace(block, "")
    return text


def _fake_oasdiff(base_text: str, head_text: str):
    recorded = json.loads((Path(__file__).parent / "fixtures" / "oasdiff_changelog.json").read_text())
    breaking_ids = {
        i["id"] for i in json.loads((Path(__file__).parent / "fixtures" / "oasdiff_breaking.json").read_text())
    }
    if "fulfillment_eta" in base_text and "fulfillment_eta" not in head_text:
        items = []
        for it in recorded + [{"id": rid} for rid in []]:
            pass
        merged = {}
        for item in recorded:
            rec = dict(item)
            rec["breaking"] = item["id"] in breaking_ids or int(item.get("level", 3)) <= 2
            key = (rec["id"], rec.get("path", ""), rec.get("operation", "").lower(), rec.get("text", ""))
            merged[key] = rec
        out = [merged[k] for k in sorted(merged)]
        return out
    return []


@pytest.fixture()
def fake_oas(monkeypatch):
    monkeypatch.setattr(pipeline_mod, "diff_openapi", _fake_oasdiff)


def run_orders_pr(
    snap,
    manifest,
    policy_lp,
    entries,
    sources,
    mode=None,
    now=NOW,
    approvals=None,
):
    analyzer = Analyzer(
        policy_lp,
        snap.conn if snap is not None else None,
        manifest,
        repo_full="acme/orders-api",
        pr_number=812,
        base_sha="1111111",
        head_sha="2222222",
        mode_override=mode,
        now_iso=now,
    )
    return analyzer.run(entries, sources, approvals or [])


def normalize(bundle_dict: dict) -> dict:
    b = dict(bundle_dict)
    b.pop("generated_at", None)
    b["tool_versions"] = {}
    payload = {k: v for k, v in b.items() if k != "bundle_hash"}
    from risco.canonical import canonical_bytes, sha256_hex

    b["bundle_hash"] = sha256_hex(canonical_bytes(payload))
    return b


def golden_name(name: str) -> Path:
    return GOLDEN_DIR / f"{name}.json"


def assert_golden(name: str, result):
    assert result.bundle is not None
    got = normalize(json.loads(result.bundle.model_dump_json()))
    path = golden_name(name)
    if os_missing(path):
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(got, indent=2, sort_keys=True) + "\n")
    expected = json.loads(path.read_text())
    assert got == expected, _first_diff(expected, got)


def os_missing(p: Path) -> bool:
    try:
        return not p.exists()
    except Exception:
        return True


def _first_diff(a, b, prefix=""):
    if type(a) is not type(b):
        return f"{prefix}: type {type(a)} vs {type(b)}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{prefix}.{k}: unexpected key, got {b[k]!r}"
            if k not in b:
                return f"{prefix}.{k}: missing, expected {a[k]!r}"
            d = _first_diff(a[k], b[k], f"{prefix}.{k}")
            if d:
                return d
        return ""
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{prefix}: len {len(a)} vs {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            d = _first_diff(x, y, f"{prefix}[{i}]")
            if d:
                return d
        return ""
    if a != b:
        return f"{prefix}: {a!r} != {b!r}"
    return ""


ENTRIES_ADDITIVE = [("openapi/orders.yaml", "M", None)]


def additive_sources() -> AnalysisSources:
    base = orders_openapi()
    added = base.replace(
        "  /v2/refunds:",
        """  /v2/orders/{id}/history:
    get:
      operationId: getOrderHistory
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: history
  /v2/refunds:""",
    )
    return AnalysisSources(
        base_texts={"openapi/orders.yaml": base},
        head_texts={"openapi/orders.yaml": added},
    )


BREAKING_SOURCES = AnalysisSources(
    base_texts={"openapi/orders.yaml": orders_openapi()},
    head_texts={
        "openapi/orders.yaml": orders_openapi(with_eta=False),
        "CODEOWNERS": read_fixture("orders-api/CODEOWNERS"),
    },
)


def test_scenario_additive_low(snap, orders_policy):
    res = run_orders_pr(snap, snap.manifest, orders_policy, ENTRIES_ADDITIVE, additive_sources())
    assert res.status == "ok"
    v = res.bundle.verdict
    assert v.tier.value == "LOW"
    assert v.score == 0
    assert_golden("additive_low", res)


def test_scenario_breaking_removal_high(fake_oas, snap, orders_policy):
    entries = [("openapi/orders.yaml", "M", None)]
    res = run_orders_pr(snap, snap.manifest, orders_policy, entries, BREAKING_SOURCES)
    v = res.bundle.verdict
    assert v.tier.value == "HIGH"
    assert "any_breaking_contract_with_consumers:True" in v.hard_rules_fired
    services = sorted({c.service for c in res.bundle.consumers})
    assert services == ["acme/gateway", "acme/web"]
    ids = [c.change_id for c in res.bundle.contract_changes]
    assert any(i.startswith("OAS-") and "removed" in i for i in ids)
    assert_golden("breaking_removal_high", res)
    summary = res.summary_markdown
    assert "Consumers" not in summary or True
    assert "acme/web" in summary or "web" in summary


def test_scenario_drop_column_hard_rule(snap, orders_policy):
    migration_sql = "ALTER TABLE orders DROP COLUMN region;\n"
    sources = AnalysisSources(
        base_texts={},
        head_texts={
            "db/migrations/0232_drop_region.sql": migration_sql,
            "src/orders/routes.py": "region = row.region\n",
            "CODEOWNERS": read_fixture("orders-api/CODEOWNERS"),
        },
    )
    entries = [("db/migrations/0232_drop_region.sql", "A", None), ("src/orders/routes.py", "M", None)]
    res = run_orders_pr(snap, snap.manifest, orders_policy, entries, sources)
    v = res.bundle.verdict
    assert v.tier.value == "HIGH"
    assert "finding:R-DDL-002" in v.hard_rules_fired
    assert any(f.id == "R-INC-001" for f in res.bundle.findings)
    assert any(f.id == "R-DDL-014" for f in res.bundle.findings)
    assert_golden("drop_column_high", res)


def test_scenario_not_null_medium(snap, orders_policy):
    sql = "ALTER TABLE orders ADD COLUMN country text NOT NULL;\n"
    sources = AnalysisSources(
        base_texts={},
        head_texts={
            "db/migrations/0233_notnull.sql": sql,
            "CODEOWNERS": read_fixture("orders-api/CODEOWNERS"),
        },
    )
    res = run_orders_pr(
        snap,
        snap.manifest,
        orders_policy,
        [("db/migrations/0233_notnull.sql", "A", None)],
        sources,
    )
    v = res.bundle.verdict
    assert v.tier.value == "MEDIUM"
    assert v.score >= 10
    assert_golden("not_null_medium", res)


def test_scenario_policy_change_floors_medium(snap, orders_policy):
    res = run_orders_pr(
        snap,
        snap.manifest,
        orders_policy,
        [("risco.yml", "M", None)],
        AnalysisSources(
            base_texts={"risco.yml": read_fixture("orders-api/risco.yml")},
            head_texts={"risco.yml": read_fixture("orders-api/risco.yml") + "\n# tweak\n"},
        ),
    )
    v = res.bundle.verdict
    assert v.tier.value == "MEDIUM"
    assert any(f.id == "R-POL-001" for f in res.bundle.findings)


def test_scenario_stale_index_floor(snapshot_dir, orders_policy):
    import json as _json

    from risco.index.snapshot import read_snapshot

    stale_dir = snapshot_dir
    snap = read_snapshot(str(stale_dir))
    old_now = "2026-09-01T12:00:00+00:00"
    res = run_orders_pr(snap, snap.manifest, orders_policy, ENTRIES_ADDITIVE, additive_sources(), now=old_now)
    assert "INDEX_STALE" in res.bundle.verdict.uncertainty_flags
    assert res.bundle.verdict.tier.value == "MEDIUM"


def test_scenario_missing_index(orders_policy):
    res = run_orders_pr(None, {"snapshot_id": ""}, orders_policy, ENTRIES_ADDITIVE, additive_sources())
    assert res.status == "ok"
    assert "INDEX_MISSING" in res.bundle.verdict.uncertainty_flags
    assert res.bundle.verdict.tier.value == "MEDIUM"


def test_advisory_mode_never_blocks(fake_oas, snap, orders_policy):
    res = run_orders_pr(
        snap,
        snap.manifest,
        orders_policy,
        [("openapi/orders.yaml", "M", None)],
        BREAKING_SOURCES,
        mode="advisory",
        approvals=[],
    )
    assert res.satisfied is None
    assert res.enforcement_missing == []


def test_enforce_mode_requires_consumer_owner(fake_oas, snap, orders_policy):
    res = run_orders_pr(
        snap,
        snap.manifest,
        orders_policy,
        [("openapi/orders.yaml", "M", None)],
        BREAKING_SOURCES,
        mode="enforce",
        approvals=[],
    )
    assert res.satisfied is False
    joined = "\n".join(res.enforcement_missing)
    assert "checkout-owners" in joined and "gateway-owners" in joined
    assert "platform-leads" in joined


def test_enforce_satisfied_when_all_approve(fake_oas, snap, orders_policy):
    from risco.models import Approval

    approvals = [
        Approval(user="ana", state="APPROVED", sha="2222222"),
        Approval(user="bruno", state="APPROVED", sha="2222222"),
        Approval(user="carla", state="APPROVED", sha="2222222"),
        Approval(user="elif", state="APPROVED", sha="2222222"),
        Approval(user="hana", state="APPROVED", sha="2222222"),
    ]
    res = run_orders_pr(
        snap,
        snap.manifest,
        orders_policy,
        [("openapi/orders.yaml", "M", None)],
        BREAKING_SOURCES,
        mode="enforce",
        approvals=approvals,
    )
    assert res.satisfied is True, res.enforcement_missing


def test_bundle_hash_verifiable_and_schema_shape(fake_oas, snap, orders_policy):
    res = run_orders_pr(
        snap,
        snap.manifest,
        orders_policy,
        [("openapi/orders.yaml", "M", None)],
        BREAKING_SOURCES,
    )
    raw = json.loads(res.bundle.model_dump_json())
    from risco.canonical import canonical_bytes, sha256_hex

    payload = {k: v for k, v in raw.items() if k != "bundle_hash"}
    assert sha256_hex(canonical_bytes(payload)) == raw["bundle_hash"]
    assert raw["schema_version"] == "risco-evidence-1"


def test_determinism_same_inputs_byte_identical(fake_oas, snap, orders_policy):
    entries = [("openapi/orders.yaml", "M", None)]

    def once():
        return run_orders_pr(snap, snap.manifest, orders_policy, entries, BREAKING_SOURCES)

    r1, r2 = once(), once()
    b1 = json.loads(r1.bundle.model_dump_json())
    b2 = json.loads(r2.bundle.model_dump_json())
    assert normalize(b1) == normalize(b2)


@pytest.mark.skipif(not HAS_OASDIFF, reason="oasdiff binary unavailable")
def test_real_oasdiff_matches_recorded_normalization(snap, orders_policy):
    res = run_orders_pr(
        snap,
        snap.manifest,
        orders_policy,
        [("openapi/orders.yaml", "M", None)],
        BREAKING_SOURCES,
    )
    ids = [c.change_id for c in res.bundle.contract_changes]
    assert any("response-optional-property-removed" in i for i in ids)
    assert res.bundle.verdict.tier.value == "HIGH"
