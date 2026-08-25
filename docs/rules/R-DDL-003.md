# R-DDL-003 — RENAME TABLE / RENAME COLUMN

- Category: `DDL`
- Severity: `HIGH`

## Trigger

RENAME TABLE / RENAME COLUMN.

## Rationale

Breaks all consumers simultaneously.

## Safe alternative

Expand/contract: add the new name, dual-write and migrate readers, then remove the old name.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
