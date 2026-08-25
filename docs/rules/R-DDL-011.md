# R-DDL-011 — Destructive DML in migration (TRUNCATE / DELETE / UPDATE without WHERE)

- Category: `DDL`
- Severity: `HIGH (hard)`

## Trigger

Destructive DML in migration (TRUNCATE / DELETE / UPDATE without WHERE).

## Rationale

Unbounded data change disguised as schema management.

## Safe alternative

Keep data surgery out of migrations; if unavoidable, scope it with an explicit key list reviewed by owners.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
