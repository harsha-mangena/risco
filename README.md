# Risco

**A deterministic merge-risk router for pull requests in multi-service organizations.**

Risco runs entirely inside your GitHub Actions. It computes each PR's cross-service
blast radius (OpenAPI/protobuf contract changes resolved against a consumer index of
your whole org), database-migration risk (PostgreSQL DDL + Alembic), incident-history
exposure and ownership routing — then records an auditable evidence bundle.

No LLM in the verdict path. No hosted service. Your source code never leaves your org.

```
Same inputs + same policy + same index snapshot = same tier, byte-for-byte.
```

## How it works

Two execution contexts, both plain GitHub Actions:

| Context | Where | What it does |
|---|---|---|
| **Org Indexer** (`risco/index`) | one central repo on a schedule | Clones every in-scope repo, builds endpoint registry + consumer index (tree-sitter TS/JS/Python) + team cache + incident map, publishes a hash-pinned SQLite snapshot as a Release asset. |
| **PR Analyzer** (`risco/check`) | every service repo, per PR | Downloads the snapshot, diffs contracts (oasdiff / Buf), analyzes migrations (pglast / Alembic AST), resolves consumers for changed operations, evaluates `risco.yml`, writes the check run + sticky comment + evidence bundle. |

Verdicts are `LOW / MEDIUM / HIGH` with reasons, required reviewers and
uncertainty flags. Enforcement is a required check that passes only when the
tier's reviewer requirements are satisfied.

```yaml
# .github/workflows/risco.yml
name: Risco
on:
  pull_request:
  pull_request_review:
jobs:
  merge-risk:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: risco-dev/risco/actions/check@v1
        with:
          index-token: ${{ secrets.RISCO_INDEX_READ_TOKEN }}
```

## Quickstart (local, no GitHub needed)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e "packages/risco-core[sql,scan,dev]" -e packages/risco-cli
# optional but recommended: oasdiff binary on PATH (or RISCO_OASDIFF_BIN)

# build the index from a directory of repos
risco index --repos-dir fixtures/sample-org --out .risco/index \
    --incidents fixtures/sample-org/org/incidents.json \
    --teams fixtures/sample-org/org/teams.json --now 2026-08-25T12:00:00+00:00

# validate a policy
risco validate-policy fixtures/sample-org/orders-api/risco.yml
```

## Design principles

1. **Deterministic verdict path.** No model, no randomness; canonical-JSON hashed evidence bundles.
2. **Agent-agnostic.** The diff is analyzed, not the author.
3. **Local-first.** Runs on your runners; there is no Risco infrastructure.
4. **Evidence before opinion.** Every finding cites a rule ID, file:line and inputs.
5. **Unknown is not safe.** Unresolved consumers and stale indexes raise the tier floor instead of reporting absence.
6. **Fail neutral, never fail closed on Risco's own bugs.**
7. **Policy is code.** All behavior lives in CODEOWNERS-protected `risco.yml`.

Docs: [install](docs/install.md) · [policy reference](docs/policy-reference.md) ·
[rule catalog](docs/rules/README.md) · [evidence schema](docs/evidence-schema.md) ·
[security model](docs/security.md) · [licensing](docs/licensing.md).

## Development

```bash
pip install -e "packages/risco-core[sql,scan,dev]" -e packages/risco-cli
pytest tests -q            # 155+ tests: unit, property, corpus, golden, failure-path, CLI e2e
```

License: Apache-2.0 for the analyzers/schemas; commercial for org-scale indexing,
enforcement and calibration. See [licensing](docs/licensing.md).
