from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from risco.canonical import canonical_bytes, sha256_hex
from risco.models import Approval, Consumer, ContractChange, EvidenceBundle, Finding, Override, Verdict

SCHEMA_VERSION = "risco-evidence-1"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_bundle(
    repo: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    index_snapshot_id: str,
    tool_versions: dict[str, str],
    inputs: dict[str, Any],
    findings: list[Finding],
    consumers: list[Consumer],
    contract_changes: list[ContractChange],
    verdict: Optional[Verdict],
    approvals_at_evaluation: Optional[list[Approval]] = None,
    overrides: Optional[list[Override]] = None,
    generated_at: str = "",
) -> EvidenceBundle:
    bundle = EvidenceBundle(
        schema_version=SCHEMA_VERSION,
        repo=repo,
        pr_number=int(pr_number),
        base_sha=base_sha,
        head_sha=head_sha,
        index_snapshot_id=index_snapshot_id,
        tool_versions=dict(tool_versions),
        inputs=_sanitize_inputs(inputs),
        findings=findings,
        consumers=consumers,
        contract_changes=contract_changes,
        verdict=verdict,
        approvals_at_evaluation=approvals_at_evaluation or [],
        overrides=overrides or [],
        generated_at=generated_at or now_iso(),
    )
    payload = bundle.model_dump(mode="json")
    payload.pop("bundle_hash", None)
    bundle.bundle_hash = sha256_hex(canonical_bytes(payload))
    return bundle


def _sanitize_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    cleaned = {}
    for k, v in inputs.items():
        if k in ("source_text", "file_texts", "contents"):
            continue
        cleaned[k] = v
    return cleaned


def bundle_bytes(bundle: EvidenceBundle) -> bytes:
    return canonical_bytes(bundle.model_dump(mode="json"))


def write_bundle(bundle: EvidenceBundle, out_dir: str) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    name = f"evidence-{bundle.head_sha or 'unknown'}.json"
    path = os.path.join(out_dir, name)
    with open(path, "wb") as f:
        f.write(json.dumps(json.loads(bundle_bytes(bundle)), indent=2, sort_keys=True).encode() + b"\n")
    return path, bundle.bundle_hash
