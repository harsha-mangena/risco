# R-DDL-001 — DROP TABLE

- Category: `DDL`
- Severity: `HIGH (hard)`

## Trigger

DROP TABLE.

## Rationale

Irreversible data loss.

## Safe alternative

Archive the table instead: rename to <table>_deprecated_<date> inside an expand phase, drop in a later contracted migration.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
