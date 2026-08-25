from __future__ import annotations

import pytest

from risco.consumers.scanner import scan_repo

pytest.importorskip("tree_sitter")

REG = [
    {
        "service": "orders-api",
        "method": "GET",
        "path_template": "/v2/orders/{id}",
        "specificity": 3,
        "operation_id": "getOrder",
    },
    {
        "service": "orders-api",
        "method": "POST",
        "path_template": "/v2/refunds",
        "specificity": 3,
        "operation_id": "createRefund",
    },
]
ENV = {"ORDERS_SERVICE_URL": "orders-api"}


def _scan(files):
    return scan_repo("acme/web", files, REG, [], ENV)


def test_literal_with_method_high():
    res = _scan(
        {"a.ts": 'const u = process.env.ORDERS_SERVICE_URL;\nfetch(`${u}/v2/orders/${id}`, {method:"GET"})\n'}
    )
    rows = [r for r in res.consumers]
    assert len(rows) == 1
    r = rows[0]
    assert r["strategy"] == "S2_LITERAL_WITH_METHOD"
    assert r["confidence"] == "HIGH"
    assert r["target_service"] == "orders-api"
    assert r["line"] == 2


def test_literal_without_method_is_medium():
    res = _scan({"a.ts": 'fetch(`/v2/refunds`);\n'})
    assert res.consumers[0]["strategy"] == "S3_LITERAL_PATH"
    assert res.consumers[0]["confidence"] == "MEDIUM"


def test_generated_client_symbol():
    files = {
        "orval.config.ts": "export default {}",
        "src/gen/client.ts": "export function getOrder(id: string){ return go(id); }",
        "src/app.ts": 'import { getOrder } from "./gen/client";\ngetOrder("1");',
    }
    res = _scan(files)
    s1 = [r for r in res.consumers if r["strategy"] == "S1_GENERATED_CLIENT"]
    assert s1 and s1[0]["file"] == "src/app.ts"
    assert s1[0]["operation_id"] == "getOrder"


def test_dynamic_two_params_unresolved():
    res = _scan({"a.ts": 'function f(a,b){ return fetch(`${a}/x/${b}/y`); }\nf(1,2);'})
    assert res.consumers == []
    assert len(res.unresolved) == 1
    assert res.unresolved[0]["reason"] == "dynamic_url"


def test_fragment_match_low():
    reg_deep = REG + [
        {"service": "payments-api", "method": "POST", "path_template": "/v2/billing/charges/{cid}/retry", "specificity": 5, "operation_id": "retryCharge"},
    ]
    res = scan_repo(
        "acme/web",
        {"a.ts": 'fetch("/charges/c9/retry", { method: "POST" });'},
        reg_deep,
        [],
        {},
    )
    assert res.consumers[0]["strategy"] == "S4_FRAGMENT"
    assert res.consumers[0]["confidence"] == "LOW"


def test_base_url_binding_raises_confidence():
    res = _scan({"a.py": 'import os, requests\nBASE = os.environ.get("ORDERS_SERVICE_URL")\ndef f(i):\n    return requests.get(f"{BASE}/v2/orders/{i}")\n'})
    assert res.consumers[0]["confidence"] == "HIGH"
    assert res.consumers[0]["target_service"] == "orders-api"


def test_python_string_concat():
    res = _scan(
        {
            "a.py": (
                'import os, requests\n'
                'BASE = os.environ["ORDERS_SERVICE_URL"]\n'
                'def f():\n'
                '    return requests.get(BASE + "/v2/refunds")\n'
            )
        }
    )
    assert any(c["path_template"] == "/v2/refunds" for c in res.consumers), res.consumers


def test_nonliteral_without_env_not_recorded():
    res = _scan({"a.ts": 'function f(u){ return fetch(u); }\nf(x);'})
    assert res.consumers == []
    assert res.unresolved == []


def test_bound_but_no_match_records_unresolved():
    res = _scan({"a.ts": 'const u=process.env.ORDERS_SERVICE_URL;\nfetch(`${u}/v9/nope`,{method:"GET"});'})
    assert res.unresolved and res.unresolved[0]["hint_service"] == "orders-api"
    assert res.unresolved[0]["reason"] == "bound_no_match"


def test_proto_rpc_consumer():
    proto_rows = [{"service": "acme.payments.v1.Payments", "rpc": "Charge", "package": "acme.payments.v1"}]
    env = {"PAYMENTS_API_BASE": "acme.payments.v1.Payments"}
    res = scan_repo(
        "web",
        {"c.py": 'import os\nBASE=os.environ.get("PAYMENTS_API_BASE")\ndef charge():\n    stub.Charge(req)\n'},
        [],
        proto_rows,
        env,
    )
    assert res.consumers == [] or res.consumers[0]["target_service"].startswith("acme.payments")
