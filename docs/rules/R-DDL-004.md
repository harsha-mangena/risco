# R-DDL-004 — ALTER COLUMN TYPE (non-widening)

- Category: `DDL`
- Severity: `HIGH`

## Trigger

ALTER COLUMN TYPE (non-widening).

## Rationale

Full table rewrite under ACCESS EXCLUSIVE lock; may truncate values.

## Safe alternative

Add a new column with the desired type, backfill in batches, swap reads/writes, drop the old column.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
