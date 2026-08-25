# Policy reference (`risco.yml`)

One file at repository root. Validated strictly on every run: any key not in
[`schemas/risco-policy.schema.json`](../schemas/risco-policy.schema.json) fails
validation. Unknown is not safe — defaults are conservative.

Full example (all keys shown; most are optional):

```yaml
version: 1

service:
  name: orders-api                      # stable service identity across repos
  contracts:
    openapi: [openapi/orders.yaml]
    protobuf: [proto/]                  # buf.yaml respected
  migrations:
    paths: [db/migrations/**/*.sql, prisma/migrations/**/migration.sql, alembic/versions/*.py]
  base_url_env: [ORDERS_SERVICE_URL]    # helps other repos' consumer resolution

index:
  source: release                       # release | artifact | path
  repo: acme/risco-index
  max_age_hours: 36                     # older → INDEX_STALE, tier floor MEDIUM

mode: enforce                           # advisory never blocks

weights:
  severity: { HIGH: 10, MEDIUM: 4, LOW: 1, INFO: 0 }
  consumer_multiplier:
    HIGH_confidence_service: 6          # per breaking change × distinct consuming service
    MEDIUM_confidence_service: 3
    LOW_confidence_service: 1
    cap: 30
  incident_exposure:
    lookback_days: 180
    per_incident: 5                     # counted once per unique incident
    cap: 20

tiers:
  LOW:    { max_score: 5 }
  MEDIUM: { max_score: 19 }
  HIGH:   { min_score: 20 }

hard_rules:                             # force tier regardless of score, evaluated in order
  - { finding: R-DDL-001, tier: HIGH }
  - { finding: R-DDL-002, tier: HIGH }
  - { finding: R-DDL-011, tier: HIGH }
  - { any_breaking_contract_with_consumers: true, tier: HIGH }
  - { paths: ["src/billing/**", "src/auth/**"], min_tier: MEDIUM }

uncertainty:                            # floors applied after hard rules
  index_missing: MEDIUM
  index_stale: MEDIUM
  unresolved_consumers: MEDIUM
  migration_unparseable: MEDIUM
  contract_tool_unavailable: MEDIUM

routing:
  LOW:    { min_approvals: 1 }
  MEDIUM: { min_approvals: 1, require_owners: true }
  HIGH:
    min_approvals: 2
    require_owners: true                # ≥1 approving owner of every changed path
    require_teams: [platform-leads]
    require_consumer_owners: true       # owners of each HIGH-confidence consuming service

overrides:
  allowed_teams: [platform-leads]
  require_reason: true
  max_downgrade: 1                      # HIGH→MEDIUM ok; HIGH→LOW not ok

evidence:
  upload_artifact: true
  commit_to_branch: ""                  # e.g. risco-evidence to also commit bundles
  include_line_context: false           # never include source lines by default

comment:
  enabled: true
  collapse_low_tier: true
```

## Semantics

### Scoring order (see `risco/verdict/engine.py`)

1. Every finding contributes its severity weight.
2. Each breaking contract change adds the confidence multiplier per distinct
   consuming service (highest confidence wins), capped by `consumer_multiplier.cap`.
3. Incident exposure adds `per_incident` per unique matched incident within the
   lookback window, capped.
4. Base tier comes from `tiers`.
5. `hard_rules` are applied **in listed order**: `tier:` sets it absolutely;
   `min_tier:` only raises.
6. Uncertainty flags apply their floors (never lower).
7. `routing.<tier>` produces the reviewer requirements.

Monotonicity guarantees (property-tested): adding a finding never lowers the
tier; removing an uncertainty flag never raises it.

### Consumer strategies

| Strategy | Detection | Confidence |
|---|---|---|
| S1 generated client | call sites of exported symbols of generated modules (orval/openapi-typescript/openapi-generator configs detected) | HIGH |
| S2 literal path + method | fetch/axios/ky/got · requests/httpx/aiohttp/client-style calls, template literals normalized (`${x}` → `{*}`), env-bound base URLs resolved | HIGH |
| S3 literal path, method unknown | same normalization, no adjacent method | MEDIUM |
| S4 fragment | last two segments match a registry template | LOW |
| S5 base-URL binding | env var in `base_url_env` resolves → raises S3 to HIGH | modifier |
| U unresolved | URL built from ≥2 dynamic parts, or bound-but-unmatched | recorded as uncertainty |

Dynamically built URLs, string concat through unknown variables, GraphQL, queues
and reflection are **not** resolvable statically. They surface as
`UNRESOLVED_CONSUMERS`, never as absence. Dial conservatism via
`uncertainty.unresolved_consumers`.

### Overrides

Members of `overrides.allowed_teams` comment `/risco override MEDIUM reason: …`.
Membership is validated against the index's team cache (never trusted from
comment text). Overrides are recorded in the evidence bundle with user, reason,
timestamp and tiers. `max_downgrade` limits how far a single override may drop
the tier. Rejected attempts produce `R-OVR-400` and are visible.

### Enforcement

On `pull_request_review` events Risco re-fetches reviews for the current head
SHA (older-SHA approvals are stale and ignored, matching GitHub's dismiss-stale
semantics) and re-evaluates routing satisfaction. In enforce mode the check run
concludes `failure` until satisfied. Risco never edits approval counts; branch
protection does the blocking.
