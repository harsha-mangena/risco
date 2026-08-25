from __future__ import annotations

import re


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    pat = pattern.strip().lstrip("/")
    i = 0
    out = ["^"]
    n = len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            if i + 1 < n and pat[i + 1] == "*":
                j = i + 2
                seg_star = True
                while j < n and pat[j] == "*":
                    j += 1
                if j < n and pat[j] == "/":
                    out.append("(?:[^/]+/)*")
                    i = j + 1
                else:
                    out.append(".*")
                    i = j
                del seg_star
                continue
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                inner = pat[i + 1 : j]
                if inner.startswith("!"):
                    inner = "^" + inner[1:]
                out.append("[" + inner + "]")
                i = j + 1
        elif c == "{":
            j = pat.find("}", i + 1)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                alts = pat[i + 1 : j].split(",")
                out.append("(?:" + "|".join(re.escape(a) for a in alts) + ")")
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def match_path(path: str, patterns: list[str]) -> bool:
    return any(glob_to_regex(p).match(path.lstrip("./")) for p in patterns)


def match_first(path: str, patterns: list[str]) -> str | None:
    for p in patterns:
        if glob_to_regex(p).match(path.lstrip("./")):
            return p
    return None
