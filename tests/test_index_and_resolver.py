from __future__ import annotations

from risco.index.snapshot import IndexData, read_snapshot, write_snapshot_dir
from risco.models import OperationRef
from risco.consumers.resolver import resolve_consumers


def _mk_snapshot(tmp_path, generated_at="2026-08-25T12:00:00+00:00"):
    data = IndexData(
        repos=[
            {"name": "acme/orders-api", "manifested": True, "service": "orders-api", "codeowners": "* @acme/orders-team", "last_indexed_sha": "sha-orders"},
            {"name": "acme/web", "codeowners": "/src/api/ @acme/checkout-owners\n* @acme/web-owners", "last_indexed_sha": "sha-web"},
        ],
        services=[{"name": "orders-api", "repo": "acme/orders-api", "base_url_env": ["ORDERS_SERVICE_URL"]}],
        registry=[
            {"service": "orders-api", "method": "GET", "path_template": "/v2/orders/{id}", "path_regex": "", "specificity": 3, "operation_id": "getOrder", "source_repo": "acme/orders-api", "source_file": "o.yaml"},
            {"service": "orders-api", "method": "POST", "path_template": "/v2/refunds", "path_regex": "", "specificity": 3, "operation_id": "createRefund", "source_repo": "acme/orders-api", "source_file": "o.yaml"},
        ],
        consumers=[
            {"consumer_repo": "acme/web", "file": "src/api/orders.ts", "line": 4, "strategy": "S2_LITERAL_WITH_METHOD", "confidence": "HIGH", "method": "GET", "operation_id": "getOrder", "path_template": "/v2/orders/{id}", "target_service": "orders-api"},
            {"consumer_repo": "acme/ops-console", "file": "app/o.py", "line": 9, "strategy": "S3_LITERAL_PATH", "confidence": "MEDIUM", "method": "", "operation_id": "", "path_template": "/v2/orders/{id}", "target_service": "orders-api"},
            {"consumer_repo": "acme/web", "file": "src/api/r.ts", "line": 8, "strategy": "S2_LITERAL_WITH_METHOD", "confidence": "HIGH", "method": "POST", "operation_id": "createRefund", "path_template": "/v2/refunds", "target_service": "orders-api"},
        ],
        unresolved=[
            {"consumer_repo": "acme/billing", "file": "b.py", "line": 3, "hint_service": "orders-api", "reason": "dynamic_url"},
            {"consumer_repo": "acme/web", "file": "u.ts", "line": 5, "hint_service": "", "reason": "dynamic_url"},
        ],
    )
    return write_snapshot_dir(data, str(tmp_path / "snap"), generated_at=generated_at), tmp_path / "snap"


def test_roundtrip_and_manifest(tmp_path):
    manifest, d = _mk_snapshot(tmp_path)
    snap = read_snapshot(str(d))
    assert snap.manifest["snapshot_id"] == manifest["snapshot_id"]
    assert snap.manifest["counts"]["consumers"] == 3
    assert snap.manifest["repos"]["acme/web"] != ""


def test_hash_mismatch_detected(tmp_path):
    manifest, d = _mk_snapshot(tmp_path)
    db = d / "snapshot.sqlite"
    raw = bytearray(db.read_bytes())
    raw[-1] ^= 0xFF
    db.write_bytes(bytes(raw))
    import pytest

    from risco.index.snapshot import SnapshotHashMismatch

    with pytest.raises(SnapshotHashMismatch):
        read_snapshot(str(d))


def test_resolver_highest_per_service(tmp_path):
    _, d = _mk_snapshot(tmp_path)
    snap = read_snapshot(str(d))
    res = resolve_consumers(
        snap.conn,
        "orders-api",
        [OperationRef(method="GET", path_template="/v2/orders/{id}", operation_id="getOrder")],
    )
    key = "get|/v2/orders/{id}|getOrder|"
    top = {c.service: c for c in res.highest_per_service(key)}
    assert set(top) == {"acme/web", "acme/ops-console"}
    assert top["acme/web"].confidence.value == "HIGH"
    assert top["acme/ops-console"].confidence.value == "MEDIUM"
    assert len(res.unresolved_matching) == 1
    assert res.unresolved_matching[0]["consumer_repo"] == "acme/billing"


def test_resolver_method_filter(tmp_path):
    _, d = _mk_snapshot(tmp_path)
    snap = read_snapshot(str(d))
    res = resolve_consumers(snap.conn, "orders-api", [OperationRef(method="DELETE", path_template="/v2/refunds")])
    key = "delete|/v2/refunds||"
    assert res.consumers_for(key) == []
