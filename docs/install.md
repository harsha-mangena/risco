# Installing Risco

Target: an afternoon, no founder involvement. Two tokens, one central repo,
one workflow per service repo.

## 0. Prerequisites

- GitHub.com cloud or GitHub Enterprise Cloud.
- Ability to create org-level fine-grained PATs and org secrets.
- One new repository: `<org>/risco-index` (protected default branch).

## 1. Tokens

| Secret (org level) | Fine-grained scopes | Used by |
|---|---|---|
| `RISCO_ORG_READ_TOKEN` | `contents: read` on in-scope repos, `members: read` | `risco/index` in `<org>/risco-index` |
| `RISCO_INDEX_READ_TOKEN` | `contents: read` on `<org>/risco-index` only | `risco/check` in every service repo |

Both are read-only. Rotation: create the successor token, update the secret,
delete the predecessor after one full index cycle. Documented rotation cadence:
90 days or on offboarding of the creating admin.

Post-V1 note: a GitHub App replaces both tokens with installation tokens.

## 2. The index repo

`.github/workflows/index.yml` in `<org>/risco-index`:

```yaml
name: risco-index
on:
  schedule: [{ cron: "0 */6 * * *" }]
  workflow_dispatch:
permissions: { contents: write }
jobs:
  index:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: risco-dev/risco/actions/index@v1
        with:
          org-token: ${{ secrets.RISCO_ORG_READ_TOKEN }}
          repos: "acme/*"
          exclude: "acme/archive-*"
          incidents: "incidents.json"
```

Each run publishes a Release whose assets are `snapshot.sqlite`,
`manifest.json` and a calibration report. The manifest contains the snapshot
id (sha256 of the SQLite file), per-repo SHAs and counts; the PR analyzer
verifies the hash before use.

Add `incidents.json` following [`schemas/incidents.schema.json`](../schemas/incidents.schema.json).
Every incident mapped by paths/services/PRs sharpens exposure findings.

## 3. Service repositories

`.github/workflows/risco.yml`:

```yaml
name: Risco
on:
  pull_request: { types: [opened, synchronize, reopened] }
  pull_request_review: { types: [submitted, dismissed] }
  issue_comment: { types: [created] }
permissions:
  contents: read
  pull-requests: write
  checks: write
jobs:
  merge-risk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: risco-dev/risco/actions/check@v1
        with:
          policy: risco.yml
          index-token: ${{ secrets.RISCO_INDEX_READ_TOKEN }}
          incidents: .risco/incidents.json   # optional per-repo additions
```

Then add `risco.yml` (see the [policy reference](policy-reference.md)) and a
`CODEOWNERS`. Protect `risco.yml` itself with CODEOWNERS.

The image is pinned by digest and signed with cosign; pin the major tag `v1`
and dependabot will propose bumps.

## 4. Branch protection

1. Add **Risco / merge-risk** as a required status check on the default branch ruleset.
2. Keep existing CODEOWNERS requirements — Risco supplements them.
3. Enable **dismiss stale approvals** so SHA semantics match Risco's.
4. Start in `mode: advisory`. Switch to `enforce` when:
   - resolver labels show trustworthy precision,
   - ≥ 2 HIGH verdicts were judged correct by your team,
   - zero CI failures were caused by Risco,
   - a named policy owner owns `risco.yml`.

## 5. Verify

Open a scratch PR that removes a field from an OpenAPI spec consumed by
another service. Expect a HIGH check run listing the consuming services at
file:line, the required reviewers, a bundle hash and an uploaded
`risco-evidence-*` artifact.

## Troubleshooting / degraded modes

| Symptom | Meaning | Action |
|---|---|---|
| Check is NEUTRAL | Risco hit an internal error and refused to block | Fix cause from error id in summary |
| `INDEX_MISSING` flag | Snapshot could not be downloaded | Check `RISCO_INDEX_READ_TOKEN` scope + latest release exists |
| `INDEX_STALE` flag | Snapshot older than `index.max_age_hours` (default 36) | Check the scheduled workflow ran |
| `CONTRACT_TOOL_UNAVAILABLE` flag | oasdiff/Buf missing or contract unparseable | Use the action image (tools vendored) or fix file syntax |
