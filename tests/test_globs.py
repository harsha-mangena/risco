from __future__ import annotations

import pytest

from risco.globs import glob_to_regex, match_first, match_path


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("db/migrations/**/*.sql", "db/migrations/a/b/c.sql", True),
        ("db/migrations/**/*.sql", "db/migrations/a.sql", True),
        ("db/migrations/*.sql", "db/migrations/a.sql", True),
        ("db/migrations/*.sql", "db/migrations/sub/a.sql", False),
        ("prisma/migrations/**/migration.sql", "prisma/migrations/20260101_x/migration.sql", True),
        ("alembic/versions/*.py", "alembic/versions/0001_a.py", True),
        ("openapi/*.yaml", "openapi/orders.yaml", True),
        ("proto/**", "proto/payments/v1/payments.proto", True),
        ("src/billing/**", "src/billing/sync.py", True),
        ("src/billing/**", "src/order/sync.py", False),
        ("*.md", "README.md", True),
        ("*.md", "docs/README.md", False),
        ("**/*.md", "docs/deep/README.md", True),
        ("openapi.{yaml,yml}", "openapi.yml", True),
        ("openapi.{yaml,yml}", "openapi.json", False),
        ("file?.sql", "file1.sql", True),
        ("[abc].py", "b.py", True),
        ("risco.yml", "risco.yml", True),
    ],
)
def test_glob_matching(pattern, path, expected):
    assert match_path(path, [pattern]) is expected


def test_match_first_returns_pattern():
    pats = ["db/migrations/**/*.sql", "alembic/versions/*.py"]
    assert match_first("alembic/versions/0001_a.py", pats) == "alembic/versions/*.py"
    assert match_first("nope.txt", pats) is None


def test_regex_is_anchored():
    rx = glob_to_regex("a/*")
    assert not rx.match("x/a/b")
