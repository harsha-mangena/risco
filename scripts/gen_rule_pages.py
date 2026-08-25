from __future__ import annotations

import sys
from pathlib import Path

RULES = [
    ("R-DDL-001", "DDL", "HIGH (hard)", "DROP TABLE", "Irreversible data loss.", "Archive the table instead: rename to <table>_deprecated_<date> inside an expand phase, drop in a later contracted migration."),
    ("R-DDL-002", "DDL", "HIGH (hard)", "DROP COLUMN", "Data loss; breaks every reader of the column.", "Stop writing the column, backfill a replacement, remove reads, then drop in a later release."),
    ("R-DDL-003", "DDL", "HIGH", "RENAME TABLE / RENAME COLUMN", "Breaks all consumers simultaneously.", "Expand/contract: add the new name, dual-write and migrate readers, then remove the old name."),
    ("R-DDL-004", "DDL", "HIGH", "ALTER COLUMN TYPE (non-widening)", "Full table rewrite under ACCESS EXCLUSIVE lock; may truncate values.", "Add a new column with the desired type, backfill in batches, swap reads/writes, drop the old column."),
    ("R-DDL-004a", "DDL", "MEDIUM", "ALTER COLUMN TYPE (widening)", "May still rewrite the table and can break consumer type expectations (e.g. int → string in clients).", "Coordinate the type change with consumers; verify client deserialization tolerates the wider domain."),
    ("R-DDL-005", "DDL", "HIGH", "ADD COLUMN ... NOT NULL without DEFAULT", "Fails on any non-empty table.", "Add the column nullable, backfill in batches, then SET NOT NULL (validated by a CHECK first if possible)."),
    ("R-DDL-006", "DDL", "MEDIUM", "ADD COLUMN with volatile DEFAULT", "Forces a full table rewrite at ADD time on PostgreSQL < 11 semantics and produces surprising historical values.", "Use a stable constant default; compute volatile values lazily in code or via batched backfill."),
    ("R-DDL-007", "DDL", "MEDIUM", "CREATE INDEX without CONCURRENTLY", "Blocks writes for the duration of the build.", "CREATE INDEX CONCURRENTLY outside a transaction; keep migrations transaction-free for this step."),
    ("R-DDL-008", "DDL", "MEDIUM", "ADD FOREIGN KEY without NOT VALID", "Takes SHARE ROW EXCLUSIVE locks on both tables while validating every row.", "ADD CONSTRAINT ... NOT VALID, then VALIDATE CONSTRAINT separately."),
    ("R-DDL-009", "DDL", "MEDIUM", "ALTER COLUMN SET NOT NULL", "Full scan under lock unless a validated CHECK NOT NULL exists.", "Add CHECK (col IS NOT NULL) NOT VALID, VALIDATE it, then SET NOT NULL and drop the CHECK."),
    ("R-DDL-010", "DDL", "MEDIUM", "ADD CONSTRAINT CHECK/UNIQUE without NOT VALID", "Full scan under lock while validating existing rows.", "Create the constraint NOT VALID and VALIDATE CONSTRAINT afterwards."),
    ("R-DDL-011", "DDL", "HIGH (hard)", "Destructive DML in migration (TRUNCATE / DELETE / UPDATE without WHERE)", "Unbounded data change disguised as schema management.", "Keep data surgery out of migrations; if unavoidable, scope it with an explicit key list reviewed by owners."),
    ("R-DDL-012", "DDL", "MEDIUM", "DDL and DML mixed in one migration file", "Long transactions hold DDL locks while rows are processed.", "Split into separate migrations: DDL first, data backfill second (batched)."),
    ("R-DDL-013", "DDL", "LOW", "DROP INDEX without CONCURRENTLY", "Brief exclusive lock; usually cheap but can stall hot paths.", "DROP INDEX CONCURRENTLY where supported."),
    ("R-DDL-014", "DDL", "INFO", "Migration touches a table/column also referenced by changed source in this PR", "Schema and code changing together deserve one reviewer who owns both sides.", "No action required — reviewer context flag."),
    ("R-DDL-900", "UNCERTAINTY", "MEDIUM", "Migration file unparseable", "Unknown is not safe: rules could not be evaluated.", "Fix SQL/Alembic syntax or open an issue with a reduced example so the parser corpus grows."),
    ("R-DDL-901", "DDL", "LOW", "Unmapped Alembic operation", "op.* call has no rule mapping yet; its risk is unassessed.", "Prefer mapped operations, or request the mapping — unmapped ops should become fixtures."),
    ("R-CON-900", "UNCERTAINTY", "MEDIUM", "Contract diff unavailable / failed / unparseable", "Breaking-change detection silently skipped would understate risk.", "Install oasdiff/Buf (bundled in the action image) or fix the contract file syntax."),
    ("R-OWN-001", "OWNERSHIP", "INFO", "Sensitive path touched", "Policy hard_rules.paths matched; these paths carry org-specific blast radius.", "Ensure the routed owners actually review this PR."),
    ("R-OWN-900", "OWNERSHIP", "INFO", "No CODEOWNERS found", "Ownership routing falls back to tier defaults only.", "Add CODEOWNERS so path-level routing has signal."),
    ("R-INC-001", "INCIDENT", "INFO", "Path/service implicated in prior incident", "History repeats: this area produced incidents within the lookback window.", "Have someone who remembers the incident look at this change."),
    ("R-POL-001", "UNCERTAINTY", "MEDIUM", "Merge-risk policy changed in this PR", "The gate's own configuration is part of the diff.", "Require platform/policy owners to approve risco.yml changes (CODEOWNERS)."),
    ("R-OVR-400", "UNCERTAINTY", "MEDIUM", "Override rejected", "Override attempt failed validation (team, reason, or max downgrade).", "Ask an allowed team member to re-issue with a valid reason within policy limits."),
]


def render(rule_id: str, category: str, severity: str, title: str, rationale: str, alternative: str) -> str:
    return f"""# {rule_id} — {title}

- Category: `{category}`
- Severity: `{severity}`

## Trigger

{title}.

## Rationale

{rationale}

## Safe alternative

{alternative}

## Determinism

This finding is computed statically from the PR diff against the declared
migration/contract paths in `risco.yml`. The same inputs, policy file and index
snapshot always produce the same verdict; see `docs/evidence-schema.md` for how
the inputs are recorded in the evidence bundle.
"""


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/rules")
    out_dir.mkdir(parents=True, exist_ok=True)
    for rule_id, cat, sev, title, why, alt in RULES:
        page = render(rule_id, cat, sev, title, why, alt)
        (out_dir / f"{rule_id}.md").write_text(page)
        print(f"wrote {rule_id}.md")
    index_lines = ["# Rule catalog", ""]
    index_lines += [f"- [`{rid}`]({rid}.md) — {title}" for rid, _, _, title, _, _ in RULES]
    (out_dir / "README.md").write_text("\n".join(index_lines) + "\n")
    print(f"wrote index ({len(RULES)} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
