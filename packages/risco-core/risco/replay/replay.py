from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from risco.models import OutcomeLabel
from risco.pipeline import AnalysisSources, Analyzer


@dataclass
class ReplayCase:
    name: str
    repo_full: str
    pr_number: int = 0
    base_dir: str = ""
    head_dir: str = ""
    merged_at: str = ""
    outcome_labels: list[str] = field(default_factory=list)


@dataclass
class ReplayResult:
    case: str
    tier: str
    score: int
    status: str
    neutral_reason: str = ""
    hard_rules_fired: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    consumer_services: list[str] = field(default_factory=list)
    outcome_labels: list[str] = field(default_factory=list)
    anachronistic: bool = False


def diff_entries(base_dir: str, head_dir: str) -> list[tuple[str, str, Optional[str]]]:
    base_files = _list_files(base_dir)
    head_files = _list_files(head_dir)
    entries: list[tuple[str, str, Optional[str]]] = []
    for p in sorted(set(base_files) | set(head_files)):
        if p not in head_files:
            entries.append((p, "D", None))
        elif p not in base_files:
            entries.append((p, "A", None))
        elif base_files[p] != head_files[p]:
            entries.append((p, "M", None))
    return entries


def _list_files(root: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "__pycache__")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    out[rel] = f.read()
            except OSError:
                continue
    return out


def run_replay(
    cases: list[ReplayCase],
    loaded_policy,
    index_conn,
    index_manifest: dict,
    repo_full: str = "",
    mode: str | None = None,
    now_iso: str = "",
    proto_base_dir_fn=None,
) -> tuple[list[ReplayResult], str]:
    results: list[ReplayResult] = []
    generated_at = str(index_manifest.get("generated_at", ""))
    sources_cache: dict[str, dict[str, str]] = {}
    for case in cases:
        if case.base_dir not in sources_cache:
            sources_cache[case.base_dir] = _list_files(case.base_dir) if case.base_dir else {}
        if case.head_dir not in sources_cache:
            sources_cache[case.head_dir] = _list_files(case.head_dir) if case.head_dir else {}
        base_texts = sources_cache[case.base_dir]
        head_texts = sources_cache[case.head_dir]
        entries = diff_entries(case.base_dir, case.head_dir)
        anachronistic = bool(
            case.merged_at and generated_at and str(generated_at) > str(case.merged_at)
        )
        analyzer = Analyzer(
            loaded_policy,
            index_conn,
            index_manifest,
            repo_full=case.repo_full or repo_full,
            pr_number=case.pr_number,
            base_sha="base",
            head_sha=f"replay-{case.name}",
            mode_override=mode or loaded_policy.policy.mode,
            now_iso=case.merged_at or now_iso,
            proto_base_dir=(proto_base_dir_fn(case) if proto_base_dir_fn else ""),
            proto_head_dir=(proto_base_dir_fn(case) if proto_base_dir_fn else ""),
        )
        res = analyzer.run(entries, AnalysisSources(base_texts=base_texts, head_texts=head_texts))
        if res.is_neutral or res.bundle is None:
            results.append(
                ReplayResult(
                    case=case.name,
                    tier="NEUTRAL",
                    score=0,
                    status="neutral",
                    neutral_reason=res.neutral_reason[:200],
                    outcome_labels=case.outcome_labels,
                    anachronistic=anachronistic,
                )
            )
            continue
        b = res.bundle
        results.append(
            ReplayResult(
                case=case.name,
                tier=b.verdict.tier.value,
                score=b.verdict.score,
                status="ok",
                hard_rules_fired=list(b.verdict.hard_rules_fired),
                findings=sorted({f.id for f in b.findings}),
                consumer_services=sorted({c.service for c in b.consumers}),
                outcome_labels=case.outcome_labels,
                anachronistic=anachronistic,
            )
        )

    report = render_report(results, len(cases))
    return results, report


def render_report(results: list[ReplayResult], total: int) -> str:
    tiers: dict[str, int] = {}
    for r in results:
        tiers[r.tier] = tiers.get(r.tier, 0) + 1
    lines: list[str] = []
    lines.append("# Risco retroactive audit (replay)")
    lines.append("")
    lines.append(f"- PRs replayed: **{total}**")
    lines.append(
        "- tier distribution: "
        + ", ".join(f"{k}={v}" for k, v in sorted(tiers.items()))
    )
    lows = sum(1 for r in results if r.tier == "LOW")
    if total:
        lines.append(f"- LOW-tier share (single-approval merges): **{lows / total:.0%}**")
    negatives = {OutcomeLabel.REVERTED.value, OutcomeLabel.INCIDENT_LINKED.value}
    high_negative = [
        r for r in results if r.tier == "HIGH" and (set(r.outcome_labels) & negatives)
    ]
    low_negative = [
        r for r in results if r.tier == "LOW" and (set(r.outcome_labels) & negatives)
    ]
    lines.append("")
    lines.append("## HIGH-tier PRs that had a real negative outcome")
    lines.append("")
    if high_negative:
        for r in high_negative:
            lines.append(f"- **{r.case}** — labels {r.outcome_labels}, rules {r.findings}")
    else:
        lines.append("- none in this sample")
    lines.append("")
    lines.append("## LOW-tier PRs with a negative outcome (misses)")
    lines.append("")
    if low_negative:
        for r in low_negative:
            lines.append(f"- {r.case} — labels {r.outcome_labels}")
    else:
        lines.append("- none in this sample")
    lines.append("")
    lines.append("## Per-PR detail")
    lines.append("")
    lines.append("| PR | tier | score | rules fired | consumers | outcome | notes |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in sorted(results, key=lambda x: (-{"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x.tier, 0), x.case)):
        notes = []
        if r.status == "neutral":
            notes.append("neutral: " + r.neutral_reason)
        if r.anachronistic:
            notes.append("SNAPSHOT_ANACHRONISTIC")
        lines.append(
            "| {name} | {tier} | {score} | {rules} | {cons} | {outcome} | {notes} |".format(
                name=r.case,
                tier=r.tier,
                score=r.score,
                rules=", ".join(r.hard_rules_fired[:2]) or ", ".join(r.findings[:3]),
                cons=", ".join(r.consumer_services[:3]),
                outcome=", ".join(r.outcome_labels) or "—",
                notes="; ".join(notes),
            )
        )
    lines.append("")
    lines.append(
        "_Snapshot caveat: where the current snapshot postdates the merged PR, rows are marked "
        "SNAPSHOT_ANACHRONISTIC; treat their consumer resolution as approximate._"
    )
    return "\n".join(lines) + "\n"
