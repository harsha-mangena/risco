# R-DDL-012 — DDL and DML mixed in one migration file

- Category: `DDL`
- Severity: `MEDIUM`

## Trigger

DDL and DML mixed in one migration file.

## Rationale

Long transactions hold DDL locks while rows are processed.

## Safe alternative

Split into separate migrations: DDL first, data backfill second (batched).

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
