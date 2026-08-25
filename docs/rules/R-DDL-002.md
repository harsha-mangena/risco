# R-DDL-002 — DROP COLUMN

- Category: `DDL`
- Severity: `HIGH (hard)`

## Trigger

DROP COLUMN.

## Rationale

Data loss; breaks every reader of the column.

## Safe alternative

Stop writing the column, backfill a replacement, remove reads, then drop in a later release.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
