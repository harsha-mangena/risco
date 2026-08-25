# R-DDL-009 — ALTER COLUMN SET NOT NULL

- Category: `DDL`
- Severity: `MEDIUM`

## Trigger

ALTER COLUMN SET NOT NULL.

## Rationale

Full scan under lock unless a validated CHECK NOT NULL exists.

## Safe alternative

Add CHECK (col IS NOT NULL) NOT VALID, VALIDATE it, then SET NOT NULL and drop the CHECK.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
