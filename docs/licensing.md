# Licensing

Boundary rule (normative):

> Anything a single-repo user needs to obtain a correct advisory verdict is open.
> Anything that requires org-wide state or produces enforcement is commercial.

## Apache-2.0

- `risco-core` analyzers: DDL rules, contract-diff normalization, CODEOWNERS
  parsing, consumer scanner primitives, verdict engine, evidence canonicalization.
- Policy and evidence JSON schemas.
- Rule pages (docs/rules) and fixture org.

Reasons: distribution, trust ("no model — read the rules"), community rule
contributions, free single-repo advisory mode as habit formation.

## Commercial

- Org indexer at scale: incremental multi-repo indexing, team cache, snapshot
  publishing pipeline.
- Routing enforcement (enforce mode check semantics + reviewer requests).
- Incident exposure, outcomes/calibration, evidence-branch tooling.
- Any future hosted control plane.

## Never open

Partner-derived labeled datasets and cross-customer calibration priors.
