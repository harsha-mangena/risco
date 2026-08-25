# R-DDL-014 — Migration touches a table/column also referenced by changed source in this PR

- Category: `DDL`
- Severity: `INFO`

## Trigger

Migration touches a table/column also referenced by changed source in this PR.

## Rationale

Schema and code changing together deserve one reviewer who owns both sides.

## Safe alternative

No action required — reviewer context flag.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
