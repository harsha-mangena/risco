# Evidence bundle schema

Every evaluation writes one bundle per PR head SHA:
`evidence-<head_sha>.json`, uploaded as artifact `risco-evidence-<pr>-<head7>`
and optionally committed to `evidence.commit_to_branch` under
`pr-<n>/<head_sha>.json`.

Formal JSON Schema: [`schemas/evidence-bundle.schema.json`](../schemas/evidence-bundle.schema.json).
The authoritative serializer is `risco.evidence.bundle` (Pydantic, strict).

## Canonicalization and hashing

`bundle_hash` = sha256 over the canonical JSON of the entire bundle **excluding
the `bundle_hash` field itself**:

```python
canonical_bytes(obj)  # json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)
```

Same inputs + policy + snapshot ⇒ byte-identical bundles. Reviewers can verify
an uploaded artifact against the hash printed in the check-run summary.

## Contents

| Field | Notes |
|---|---|
| `schema_version` | `risco-evidence-1` |
| `repo`, `pr_number`, `base_sha`, `head_sha` | identity |
| `index_snapshot_id` | sha256 of the SQLite snapshot used |
| `tool_versions` | oasdiff / buf / pglast / engine versions |
| `inputs` | changed/contract/migration file lists, policy hash, mode, index age, unresolved examples, counts |
| `findings[]` | rule id, category, severity, location (repo/path/lines), structured details, resolved weight |
| `consumers[]` | service, repo, path:line, strategy S1–S5/U, confidence, operation ref |
| `contract_changes[]` | source, operation ref, namespaced change id (`OAS-*`, `BUF-*`), breaking flag |
| `verdict` | tier, score, hard rules fired, reasons (ordered by contribution), required reviewers, uncertainty flags, policy hash, engine version |
| `approvals_at_evaluation` | user, team memberships, state, SHA — the exact approval set the enforcement math saw |
| `overrides[]` | user, reason, timestamp, from_tier → to_tier |
| `generated_at` | ISO 8601 |

## Redaction guarantees

- No source lines are included unless `evidence.include_line_context: true`.
- Statement text in DDL findings is stored as a truncated sha256, not raw text.
- No token material, no environment values.
- A structural guard strips any `source_text`-like keys before serialization.

## Compliance positioning

The bundle is the artifact SOC 2 CC8.1 auditors sample for change management:
authorization (policy as code, CODEOWNERS), review (approvals at evaluation),
segregation of duties (owner routing) — all captured mechanically at merge
decision time on the evidence branch. Risco does not claim an AI-specific audit
mandate exists; when your auditor asks about AI-generated code, the evidence
branch is the export surface.
