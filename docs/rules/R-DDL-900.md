# R-DDL-900 — Migration file unparseable

- Category: `UNCERTAINTY`
- Severity: `MEDIUM`

## Trigger

Migration file unparseable.

## Rationale

Unknown is not safe: rules could not be evaluated.

## Safe alternative

Fix SQL/Alembic syntax or open an issue with a reduced example so the parser corpus grows.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
