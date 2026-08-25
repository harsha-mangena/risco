from __future__ import annotations

import pytest

from risco.ddl.analyzer import analyze_migrations
from risco.models import Severity

pytest.importorskip("pglast")

SQL_CASES = {
    "R-DDL-001": ("DROP TABLE old_orders;", Severity.HIGH),
    "R-DDL-002": ("ALTER TABLE orders DROP COLUMN region;", Severity.HIGH),
    "R-DDL-003": ("ALTER TABLE orders RENAME COLUMN total TO amount;", Severity.HIGH),
    "R-DDL-004": ("ALTER TABLE orders ALTER COLUMN total TYPE varchar(10);", Severity.HIGH),
    "R-DDL-005": ("ALTER TABLE orders ADD COLUMN country text NOT NULL;", Severity.HIGH),
    "R-DDL-006": (
        "ALTER TABLE orders ADD COLUMN created timestamptz DEFAULT now();",
        Severity.MEDIUM,
    ),
    "R-DDL-007": ("CREATE INDEX idx_orders_region ON orders(region);", Severity.MEDIUM),
    "R-DDL-008": (
        "ALTER TABLE refunds ADD CONSTRAINT fk_ref FOREIGN KEY (order_id) REFERENCES orders(id);",
        Severity.MEDIUM,
    ),
    "R-DDL-009": ("ALTER TABLE orders ALTER COLUMN region SET NOT NULL;", Severity.MEDIUM),
    "R-DDL-010": ("ALTER TABLE orders ADD CONSTRAINT ck CHECK (total > 0);", Severity.MEDIUM),
    "R-DDL-011": ("TRUNCATE audit_log;", Severity.HIGH),
    "R-DDL-013": ("DROP INDEX idx_old;", Severity.LOW),
}


@pytest.mark.parametrize("rule_id", sorted(SQL_CASES.keys()))
def test_sql_rule_fires(rule_id):
    sql, severity = SQL_CASES[rule_id]
    res = analyze_migrations("r", {"m.sql": sql})
    ids = [f.id for f in res.findings]
    assert rule_id in ids, (rule_id, ids)
    f = next(x for x in res.findings if x.id == rule_id)
    assert f.severity == severity
    assert f.location.path == "m.sql"
    assert f.location.line_start >= 1


def test_delete_update_without_where():
    res = analyze_migrations("r", {"m.sql": "DELETE FROM logs;\nUPDATE t SET a=1;"})
    hits = [f for f in res.findings if f.id == "R-DDL-011"]
    assert len(hits) == 2
    statements = {f.details["statement"] for f in hits}
    assert statements == {"delete", "update"}


def test_delete_with_where_is_clean():
    res = analyze_migrations("r", {"m.sql": "DELETE FROM logs WHERE id < 100;"})
    assert all(f.id != "R-DDL-011" for f in res.findings)


def test_mixed_ddl_dml_flags_012():
    sql = "CREATE INDEX i ON orders(r);\nDELETE FROM logs;"
    res = analyze_migrations("r", {"m.sql": sql})
    assert any(f.id == "R-DDL-012" for f in res.findings)


def test_widening_type_downgrades_to_004a_alembic():
    src = """
import sqlalchemy as sa
from alembic import op
def upgrade():
    op.alter_column("orders", "n", existing_type=sa.Integer(), type_=sa.BigInteger())
"""
    res = analyze_migrations("r", {"v.py": src})
    assert any(f.id == "R-DDL-004a" and f.severity == Severity.MEDIUM for f in res.findings)


def test_narrowing_type_stays_high():
    src = """
import sqlalchemy as sa
from alembic import op
def upgrade():
    op.alter_column("t", "c", existing_type=sa.Text(), type_=sa.String(length=10))
"""
    res = analyze_migrations("r", {"v.py": src})
    assert any(f.id == "R-DDL-004" for f in res.findings)


ALEMBIC_MATRIX = {
    "drop_table": ('op.drop_table("legacy")', "R-DDL-001"),
    "drop_column": ('op.drop_column("orders", "region")', "R-DDL-002"),
    "rename": ('op.rename_table("a", "b")', "R-DDL-003"),
    "notnull_add": (
        'op.add_column("o", sa.Column("x", sa.Integer(), nullable=False))',
        "R-DDL-005",
    ),
    "volatile_default": (
        'op.add_column("o", sa.Column("c", sa.DateTime(), server_default=sa.text("now()")))',
        "R-DDL-006",
    ),
    "index": ('op.create_index("ix", "orders", ["a"])', "R-DDL-007"),
    "concurrent_index_suppressed": (
        'op.create_index("ix", "orders", ["a"], postgresql_concurrently=True)',
        None,
    ),
    "fk": (
        'op.create_foreign_key("fk", "refunds", "orders", ["order_id"], ["id"])',
        "R-DDL-008",
    ),
    "set_not_null": (
        'op.alter_column("orders", "region", nullable=False)',
        "R-DDL-009",
    ),
    "drop_index": ('op.drop_index("ix_old")', "R-DDL-013"),
}


@pytest.mark.parametrize("case", sorted(ALEMBIC_MATRIX.keys()))
def test_alembic_mapping(case):
    expr, expected = ALEMBIC_MATRIX[case]
    src = f"import sqlalchemy as sa\nfrom alembic import op\ndef upgrade():\n    {expr}\n"
    res = analyze_migrations("r", {"v.py": src})
    ids = [f.id for f in res.findings]
    if expected is None:
        hard_ids = [i for i in ids if i.startswith("R-DDL-") and i not in ("R-DDL-900", "R-DDL-901")]
        assert hard_ids == [], (case, ids)
    else:
        assert expected in ids, (case, ids)


def test_op_execute_sql_parsed():
    src = 'from alembic import op\ndef upgrade():\n    op.execute("DROP TABLE legacy;")\n'
    res = analyze_migrations("r", {"v.py": src})
    assert any(f.id == "R-DDL-001" for f in res.findings)


def test_unmapped_op_flagged_low():
    src = "from alembic import op\ndef upgrade():\n    op.custom_magic(1)\n"
    res = analyze_migrations("r", {"v.py": src})
    assert any(f.id == "R-DDL-901" for f in res.findings)


def test_unparseable_sets_flag():
    res = analyze_migrations("r", {"m.sql": "NOT VALID SQL ((("})
    assert any(f.id == "R-DDL-900" for f in res.findings)
    assert res.unparseable is True


def test_coupled_source_info():
    res = analyze_migrations(
        "r",
        {"m.sql": "ALTER TABLE orders DROP COLUMN region;"},
        changed_source_texts={"src/routes.py": "query orders set region"},
    )
    hit = [f for f in res.findings if f.id == "R-DDL-014"]
    assert hit and hit[0].details["tables"] == ["orders"]


def test_statement_hash_present_and_line_numbers():
    res = analyze_migrations("r", {"m.sql": "SELECT 1;\nDROP TABLE a;"})
    drop = next(f for f in res.findings if f.id == "R-DDL-001")
    sha = drop.details.get("statement_sha")
    assert isinstance(sha, str) and len(sha) == 16
    assert drop.location.line_start == 2
