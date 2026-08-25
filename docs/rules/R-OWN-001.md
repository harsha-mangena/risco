# R-OWN-001 — Sensitive path touched

- Category: `OWNERSHIP`
- Severity: `INFO`

## Trigger

Sensitive path touched.

## Rationale

Policy hard_rules.paths matched; these paths carry org-specific blast radius.

## Safe alternative

Ensure the routed owners actually review this PR.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
