# R-DDL-005 — ADD COLUMN ... NOT NULL without DEFAULT

- Category: `DDL`
- Severity: `HIGH`

## Trigger

ADD COLUMN ... NOT NULL without DEFAULT.

## Rationale

Fails on any non-empty table.

## Safe alternative

Add the column nullable, backfill in batches, then SET NOT NULL (validated by a CHECK first if possible).

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
