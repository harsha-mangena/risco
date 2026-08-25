# R-OWN-900 — No CODEOWNERS found

- Category: `OWNERSHIP`
- Severity: `INFO`

## Trigger

No CODEOWNERS found.

## Rationale

Ownership routing falls back to tier defaults only.

## Safe alternative

Add CODEOWNERS so path-level routing has signal.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
