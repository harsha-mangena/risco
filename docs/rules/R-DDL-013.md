# R-DDL-013 — DROP INDEX without CONCURRENTLY

- Category: `DDL`
- Severity: `LOW`

## Trigger

DROP INDEX without CONCURRENTLY.

## Rationale

Brief exclusive lock; usually cheap but can stall hot paths.

## Safe alternative

DROP INDEX CONCURRENTLY where supported.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
