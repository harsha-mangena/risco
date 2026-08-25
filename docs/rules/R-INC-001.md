# R-INC-001 — Path/service implicated in prior incident

- Category: `INCIDENT`
- Severity: `INFO`

## Trigger

Path/service implicated in prior incident.

## Rationale

History repeats: this area produced incidents within the lookback window.

## Safe alternative

Have someone who remembers the incident look at this change.

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
