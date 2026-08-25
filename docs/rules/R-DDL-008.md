# R-DDL-008 — ADD FOREIGN KEY without NOT VALID

- Category: `DDL`
- Severity: `MEDIUM`

## Trigger

ADD FOREIGN KEY without NOT VALID.

## Rationale

Takes SHARE ROW EXCLUSIVE locks on both tables while validating every row.

## Safe alternative

ADD CONSTRAINT ... NOT VALID, then VALIDATE CONSTRAINT separately.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
