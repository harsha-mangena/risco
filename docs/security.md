# Security model

## Execution topology

Risco V1 runs entirely inside the customer's GitHub Actions runners. There is no
Risco-hosted infrastructure and no LLM anywhere in the verdict path — therefore
no prompt-injection surface in the gate.

Outbound network calls from the PR analyzer are limited to:

1. GitHub REST for the current repository (check run, comments, reviews,
   reviewer requests), using the workflow token or the provided PAT;
2. download of the index snapshot Release asset from `<org>/risco-index`.

## Tokens

| Token | Scope |
|---|---|
| `RISCO_ORG_READ_TOKEN` | fine-grained: contents read on in-scope repos, members read |
| `RISCO_INDEX_READ_TOKEN` | fine-grained: contents read on `<org>/risco-index` only |
| workflow `github.token` | checks write, pull-requests write (default) |

All read-only with respect to source code. Rotation runbook in
[install.md](install.md#1-tokens).

## Supply chain

Analyzer image pinned by digest, multi-arch, signed with cosign (keyless), SBOM
attached, dependencies pinned with hashes, Dependabot enabled on the Risco repo.
Release pipeline runs the fixture-org golden suite before anything publishes; a
failing gate blocks the release.

## Threat model

### Malicious PR modifies `risco.yml`

Mitigations: require CODEOWNERS on `risco.yml`; every evidence bundle records
`policy_hash`; a changed policy produces finding `R-POL-001` (MEDIUM, floors
tier). Policy changes route like any other risky change.

### Malicious PR modifies the workflow file

GitHub's own protections apply (forks cannot touch workflows without approval).
Documented posture: fork PRs should run Risco in advisory mode only; enforce-mode
repos should restrict workflow-trigger approvals to members.

### Poisoned index

Snapshot id is verified against the manifest's sha256 before use. The indexer
runs only from the protected default branch of `<org>/risco-index`; its token is
read-only everywhere else. A tampered snapshot fails verification and the
analyzer degrades to `INDEX_MISSING` (tier floor), never silently proceeds.

### Comment spoofing of `/risco override`

The comment author is taken from the event payload, never from comment text.
Team membership is validated against the org team cache. Rejected overrides
leave a visible `R-OVR-400` finding.

## Data leaving the boundary

Nothing does, by construction: analysis is local, telemetry is opt-in and
limited to `{engine_version, tier, duration_ms, flags}` — never repo names,
paths or findings. Design-partner labeling stores labels in the partner's own
repo; only aggregates leave.
