# R-DDL-010 — ADD CONSTRAINT CHECK/UNIQUE without NOT VALID

- Category: `DDL`
- Severity: `MEDIUM`

## Trigger

ADD CONSTRAINT CHECK/UNIQUE without NOT VALID.

## Rationale

Full scan under lock while validating existing rows.

## Safe alternative

Create the constraint NOT VALID and VALIDATE CONSTRAINT afterwards.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
