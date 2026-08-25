# R-CON-900 — Contract diff unavailable / failed / unparseable

- Category: `UNCERTAINTY`
- Severity: `MEDIUM`

## Trigger

Contract diff unavailable / failed / unparseable.

## Rationale

Breaking-change detection silently skipped would understate risk.

## Safe alternative

Install oasdiff/Buf (bundled in the action image) or fix the contract file syntax.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
