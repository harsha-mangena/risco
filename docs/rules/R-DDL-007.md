# R-DDL-007 — CREATE INDEX without CONCURRENTLY

- Category: `DDL`
- Severity: `MEDIUM`

## Trigger

CREATE INDEX without CONCURRENTLY.

## Rationale

Blocks writes for the duration of the build.

## Safe alternative

CREATE INDEX CONCURRENTLY outside a transaction; keep migrations transaction-free for this step.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
