from __future__ import annotations

from risco.models import EvidenceBundle, Finding, Verdict

CHECK_NAME = "Risco / merge-risk"
COMMENT_MARKER = "<!-- risco:sticky-comment:v1 -->"
MAX_ANNOTATIONS_PER_REQUEST = 50

SEVERITY_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🔵"}


def _short(sha: str) -> str:
    return sha[:7] if sha else ""


def render_summary(bundle: EvidenceBundle, mode: str, enforcement_lines: list[str]) -> str:
    v = bundle.verdict
    assert v is not None
    lines: list[str] = []
    snapshot_age = bundle.inputs.get("index_age_hours")
    age_txt = f" (age {snapshot_age:g}h)" if isinstance(snapshot_age, (int, float)) else ""
    lines.append(
        f"**{CHECK_NAME} — {v.tier.value}** (score {v.score}) · bundle `{bundle.bundle_hash[:12]}` · "
        f"snapshot `{bundle.index_snapshot_id[:8] or 'none'}`{age_txt}"
    )
    why = [f for f in bundle.findings if f.id not in ("R-OWN-900",)]
    if why:
        lines.append("\n### Why\n")
        for f in why[:25]:
            loc = f"{f.location.path}:{f.location.line_start}" if f.location.path else ""
            sev = SEVERITY_EMOJI.get(f.severity.value, "•")
            head = f"- {sev} **{f.id}**: {f.title}"
            if loc:
                head += f"  `{loc}`"
            lines.append(head)
            det = f.details or {}
            consumers = det.get("consumers") if isinstance(det, dict) else None
            del consumers
    else:
        lines.append("\nNo findings contributed to this verdict.")

    breaking = [c for c in bundle.contract_changes if c.breaking]
    if breaking:
        lines.append("\n### Breaking contract changes\n")
        by_op: dict[str, list] = {}
        for c in breaking:
            op = c.operation.method and f"{c.operation.method} {c.operation.path_template}" or (
                c.operation.rpc or c.change_id
            )
            by_op.setdefault(op or "(schema-level)", []).append(c)
        for op in sorted(by_op):
            lines.append(f"- `{op}`")
            for c in sorted(by_op[op], key=lambda x: x.change_id)[:5]:
                cons = _consumers_for(bundle, c)
                suffix = f"  → consumers: {cons}" if cons else ""
                lines.append(f"  - {c.change_id}{'  `[breaking]`' if c.breaking else ''}{suffix}")

    if v.uncertainty_flags:
        lines.append("\n### Uncertainty\n")
        for fl in v.uncertainty_flags:
            detail = ""
            if fl == "UNRESOLVED_CONSUMERS" and bundle.inputs.get("unresolved_examples"):
                ex = bundle.inputs["unresolved_examples"][:3]
                detail = " — " + "; ".join(f"{e.get('file')}:{e.get('line')}" for e in ex)
            lines.append(f"- {fl}{detail}")

    if mode == "enforce":
        lines.append("\n### Required to merge\n")
        rr = v.required_reviewers
        if enforcement_lines:
            lines.extend(f"- {m}" for m in enforcement_lines)
        elif rr.min_approvals:
            lines.append(f"- All routing requirements satisfied ({rr.min_approvals} approval(s) on {_short(bundle.head_sha)})")

    if v.tier.value == "HIGH":
        lines.append(
            "\n> Override: members of an allowed team may comment `/risco override MEDIUM reason: …`"
        )
    return "\n".join(lines)


def _consumers_for(bundle: EvidenceBundle, change) -> str:
    matches = [
        c
        for c in bundle.consumers
        if (change.operation.path_template and c.operation.path_template == change.operation.path_template)
        or (change.operation.rpc and change.operation.rpc == c.operation.rpc)
    ]
    if not matches:
        return ""
    best: dict[str, tuple] = {}
    rank = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
    for c in matches:
        cur = best.get(c.service)
        if cur is None or rank[c.confidence.value] > rank[cur[0]]:
            best[c.service] = (c.confidence.value, f"{c.path}:{c.line}")
    parts = []
    for svc in sorted(best):
        conf, where = best[svc]
        parts.append(f"{svc} ({conf.lower()}: `{where}`)")
    return ", ".join(parts)


def render_comment(bundle: EvidenceBundle, mode: str, enforcement_lines: list[str], collapse_low_tier: bool = True) -> str:
    v = bundle.verdict
    assert v is not None
    body = render_summary(bundle, mode, enforcement_lines)
    header = f"{COMMENT_MARKER}\n"
    if v.tier.value == "LOW" and collapse_low_tier:
        collapsed = [
            COMMENT_MARKER,
            f"<details>\n<summary>{CHECK_NAME} — LOW (score {v.score}) · bundle <code>{bundle.bundle_hash[:12]}</code></summary>",
            "",
            body,
            "</details>",
        ]
        return header + "\n".join(collapsed) + "\n"
    return header + body + "\n"


def build_annotations(bundle: EvidenceBundle) -> list[dict]:
    anns: list[dict] = []
    level_map = {"HIGH": "failure", "MEDIUM": "warning", "LOW": "notice", "INFO": "notice"}
    seen: set[tuple] = set()
    for f in bundle.findings:
        key = (f.id, f.location.path, f.location.line_start)
        if key in seen:
            continue
        seen.add(key)
        if not f.location.path:
            continue
        anns.append(
            {
                "path": f.location.path,
                "start_line": max(1, f.location.line_start or 1),
                "end_line": max(1, f.location.line_end or f.location.line_start or 1),
                "annotation_level": level_map.get(f.severity.value, "notice"),
                "message": f"{f.id}: {f.title}",
                "title": f.id,
            }
        )
    batches = []
    for i in range(0, len(anns), MAX_ANNOTATIONS_PER_REQUEST):
        batches.append(anns[i : i + MAX_ANNOTATIONS_PER_REQUEST])
    return batches


def neutral_summary(reason: str, error_id: str) -> str:
    return (
        f"**{CHECK_NAME} — NEUTRAL**\n\n"
        f"Risco could not complete analysis, so it is not blocking this PR.\n\n"
        f"- reason: {reason}\n- error id: `{error_id}`"
    )


def parse_override_command(body: str) -> tuple[bool, str, str]:
    import re

    m = re.search(r"/risco\s+override\s+(LOW|MEDIUM|HIGH)(?:\s+reason:\s*(.+))?", body, flags=re.IGNORECASE | re.MULTILINE)
    if not m:
        return False, "", ""
    tier = m.group(1).upper()
    reason = (m.group(2) or "").strip()
    return True, tier, reason
