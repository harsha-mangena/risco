# R-POL-001 — Merge-risk policy changed in this PR

- Category: `UNCERTAINTY`
- Severity: `MEDIUM`

## Trigger

Merge-risk policy changed in this PR.

## Rationale

The gate's own configuration is part of the diff.

## Safe alternative

Require platform/policy owners to approve risco.yml changes (CODEOWNERS).

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
