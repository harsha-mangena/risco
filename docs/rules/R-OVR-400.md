# R-OVR-400 — Override rejected

- Category: `UNCERTAINTY`
- Severity: `MEDIUM`

## Trigger

Override rejected.

## Rationale

Override attempt failed validation (team, reason, or max downgrade).

## Safe alternative

Ask an allowed team member to re-issue with a valid reason within policy limits.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
