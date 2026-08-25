from __future__ import annotations

from risco.ownership.codeowners import parse_codeowners, resolve_ownership


TEXT = """
# comment
* @platform-leads
/docs/** @docs-team lead@example.com
*.md @writers
/src/billing/ @security @billing-oncall
/src/**/*.ts @frontend
"""


def test_last_match_wins():
    rules = parse_codeowners(TEXT)
    res = resolve_ownership(
        ["README.md", "src/main.py", "docs/a/b.md", "docs/guide.md", "src/billing/x.py", "src/app/util.ts"],
        [TEXT],
    )
    assert res.owners_for("README.md") == ["@writers"]
    assert res.owners_for("src/main.py") == ["@platform-leads"]
    assert res.owners_for("docs/a/b.md") == ["@writers"]
    assert set(res.owners_for("docs/guide.md")) == {"@writers"}
    assert "@security" in res.owners_for("src/billing/x.py")
    assert res.owners_for("src/app/util.ts") == ["@frontend"]


def test_anchored_vs_unanchored():
    text = """
data/*.json @d
main.py @root
"""
    res = resolve_ownership(["conf/data/a.json", "data/a.json", "deep/nested/main.py"], [text])
    assert res.owners_for("data/a.json") == ["@d"]
    assert res.owners_for("conf/data/a.json") == []
    assert res.owners_for("deep/nested/main.py") == ["@root"]


def test_dir_pattern_matches_contents():
    text = "/db/migrations/ @orders-owners\n"
    res = resolve_ownership(["db/migrations/0001.sql", "db/migrations/sub/0002.sql", "db/other.sql"], [text])
    assert res.owners_for("db/migrations/0001.sql") == ["@orders-owners"]
    assert res.owners_for("db/migrations/sub/0002.sql") == ["@orders-owners"]
    assert res.owners_for("db/other.sql") == []


def test_no_codeowners():
    res = resolve_ownership(["a.py"], [])
    assert res.rules_found is False
    assert res.owners_for("a.py") == []


def test_union_and_patterns():
    res = resolve_ownership(["README.md", "src/main.py"], [TEXT])
    assert set(res.union_owners) >= {"@writers", "@platform-leads"}
    assert res.matched_patterns["README.md"] == "*.md"


def test_precedence_across_files_root_then_github():
    root = "* @team-a\n"
    github = "/src/** @team-b\n"
    res = resolve_ownership(["src/x.ts"], [root, github])
    assert res.owners_for("src/x.ts") == ["@team-b"]


def test_parse_skips_invalid_lines():
    rules = parse_codeowners("# only comment\n\npattern_without_owners\n")
    assert rules == []
