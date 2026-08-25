from __future__ import annotations

import re
from dataclasses import dataclass

from risco.globs import glob_to_regex


@dataclass(frozen=True)
class CodeownersRule:
    pattern: str
    owners: tuple[str, ...]
    order: int
    regex: re.Pattern[str]


_OWNER_TOKEN = re.compile(r"^@[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?$|^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _compile_pattern(pattern: str) -> re.Pattern[str] | None:
    p = pattern.strip()
    if not p or p.startswith("#") or p.startswith("!"):
        return None
    anchored = "/" in p.rstrip("/")
    dir_only = p.endswith("/")
    core = p.rstrip("/")
    rx = glob_to_regex(core.lstrip("/") if anchored else core).pattern
    rx = rx.removeprefix("^").removesuffix("$")
    if anchored:
        body = "^" + rx + ("/(?:.*)?$" if dir_only else "(?:/.*)?$")
    else:
        body = "^(?:.*/)?" + rx + ("/(?:.*)?$" if dir_only else "(?:/.*)?$")
    return re.compile(body)


def parse_codeowners(text: str) -> list[CodeownersRule]:
    rules: list[CodeownersRule] = []
    for i, raw in enumerate(text.splitlines()):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        if len(tokens) < 2:
            continue
        pattern, owner_tokens = tokens[0], tokens[1:]
        owners = tuple(t for t in owner_tokens if _OWNER_TOKEN.match(t))
        rx = _compile_pattern(pattern)
        if rx is None or not owners:
            continue
        rules.append(CodeownersRule(pattern=pattern, owners=owners, order=i, regex=rx))
    rules.sort(key=lambda r: r.order)
    return rules


@dataclass
class OwnershipResult:
    rules_found: bool
    owners_by_path: dict[str, list[str]]
    union_owners: list[str]
    matched_patterns: dict[str, str]

    def owners_for(self, path: str) -> list[str]:
        return self.owners_by_path.get(path, [])


def resolve_ownership(paths: list[str], codeowners_texts: list[str]) -> OwnershipResult:
    rules: list[CodeownersRule] = []
    for text in codeowners_texts:
        rules.extend(parse_codeowners(text))
    owners_by_path: dict[str, list[str]] = {}
    matched: dict[str, str] = {}
    union: set[str] = set()
    for path in sorted(set(paths)):
        best: CodeownersRule | None = None
        for r in rules:
            if r.regex.match(path):
                best = r
        owners = list(best.owners) if best else []
        owners_by_path[path] = owners
        if best:
            matched[path] = best.pattern
        union.update(owners)
    return OwnershipResult(
        rules_found=bool(rules),
        owners_by_path=owners_by_path,
        union_owners=sorted(union),
        matched_patterns=matched,
    )


def find_codeowners_files(root: str) -> list[str]:
    import os

    found = []
    for rel in CODEOWNERS_PATHS:
        p = os.path.join(root, rel)
        if os.path.isfile(p):
            found.append(p)
    return found
