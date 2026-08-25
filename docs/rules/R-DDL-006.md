# R-DDL-006 — ADD COLUMN with volatile DEFAULT

- Category: `DDL`
- Severity: `MEDIUM`

## Trigger

ADD COLUMN with volatile DEFAULT.

## Rationale

Forces a full table rewrite at ADD time on PostgreSQL < 11 semantics and produces surprising historical values.

## Safe alternative

Use a stable constant default; compute volatile values lazily in code or via batched backfill.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
