# R-DDL-004a — ALTER COLUMN TYPE (widening)

- Category: `DDL`
- Severity: `MEDIUM`

## Trigger

ALTER COLUMN TYPE (widening).

## Rationale

May still rewrite the table and can break consumer type expectations (e.g. int → string in clients).

## Safe alternative

Coordinate the type change with consumers; verify client deserialization tolerates the wider domain.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
