# R-DDL-901 — Unmapped Alembic operation

- Category: `DDL`
- Severity: `LOW`

## Trigger

Unmapped Alembic operation.

## Rationale

op.* call has no rule mapping yet; its risk is unassessed.

## Safe alternative

Prefer mapped operations, or request the mapping — unmapped ops should become fixtures.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
