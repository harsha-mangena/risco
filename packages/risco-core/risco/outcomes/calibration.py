from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any, Optional

from risco.models import Outcome, OutcomeLabel, Tier

NEGATIVE = {OutcomeLabel.REVERTED.value, OutcomeLabel.INCIDENT_LINKED.value}


def collect_labels(outcomes: list[Outcome]) -> Counter:
    c: Counter = Counter()
    for o in outcomes:
        for l in o.labels:
            c[l.value] += 1
    return c


def confusion_table(outcomes: list[Outcome]) -> dict[str, dict[str, int]]:
    table: dict[str, dict[str, int]] = {
        t.value: defaultdict(int) for t in Tier
    }
    for o in outcomes:
        tier = o.tier_at_merge.value if o.tier_at_merge else "NONE"
        row = table.setdefault(tier, defaultdict(int))
        negative = bool(set(o.labels) & NEGATIVE)
        row["negative" if negative else "clean"] += 1
    return table


def precision_recall_high(outcomes: list[Outcome]) -> dict[str, float]:
    tp = sum(1 for o in outcomes if o.tier_at_merge == Tier.HIGH and (set(o.labels) & NEGATIVE))
    fp = sum(1 for o in outcomes if o.tier_at_merge == Tier.HIGH and not (set(o.labels) & NEGATIVE))
    fn = sum(1 for o in outcomes if o.tier_at_merge != Tier.HIGH and (set(o.labels) & NEGATIVE))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {"precision": round(precision, 3), "recall": round(recall, 3), "tp": tp, "fp": fp, "fn": fn}


def low_share_negative(outcomes: list[Outcome]) -> float:
    lows = [o for o in outcomes if o.tier_at_merge == Tier.LOW]
    if not lows:
        return 0.0
    neg = sum(1 for o in lows if set(o.labels) & NEGATIVE)
    return round(neg / len(lows), 3)


def never_fired_rules(bundles: list[dict]) -> list[str]:
    fired: set[str] = set()
    known: set[str] = set()
    for b in bundles:
        for f in b.get("findings", []):
            known.add(str(f.get("id", "")))
            if float(f.get("weight", 0) or 0) > 0:
                fired.add(str(f.get("id", "")))
    return sorted(k for k in known if k not in fired and k.startswith("R-"))


def suggested_weights_block(outcomes: list[Outcome], current: Optional[dict] = None) -> str:
    pr = precision_recall_high(outcomes)
    low_neg = low_share_negative(outcomes)
    lines = ["# Proposed weights block (heuristic — human must review and commit via policy PR)", "weights:"]
    sev = dict(current or {}).get("severity") or {"HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    high_w = int(sev.get("HIGH", 10))
    medium_w = int(sev.get("MEDIUM", 4))
    if pr["precision"] < 0.6 and pr["fp"] > 0:
        high_w = max(6, high_w - 2)
        lines.append(f"  # HIGH precision {pr['precision']} below 0.6 — reducing HIGH weight")
    if low_neg >= 0.05:
        medium_w = medium_w + 2
        lines.append(f"  # LOW-tier negatives at {low_neg:.0%} — raising MEDIUM weight")
    lines.append(f"  severity: {{HIGH: {high_w}, MEDIUM: {medium_w}, LOW: {int(sev.get('LOW', 1))}, INFO: {int(sev.get('INFO', 0))}}}")
    return "\n".join(lines)


def render_calibration_report(
    outcomes: list[Outcome],
    bundles: Optional[list[dict]] = None,
    current_weights: Optional[dict] = None,
) -> str:
    table = confusion_table(outcomes)
    pr = precision_recall_high(outcomes)
    low_neg = low_share_negative(outcomes)
    counts = collect_labels(outcomes)
    lines: list[str] = []
    lines.append("# Risco calibration report")
    lines.append("")
    lines.append(f"- outcomes analyzed: **{len(outcomes)}**")
    lines.append(
        "- labels: " + ", ".join(f"`{k}`×{v}" for k, v in sorted(counts.items())) or "(none)"
    )
    lines.append("")
    lines.append("## Tier × outcome")
    lines.append("")
    lines.append("| tier | negative (REVERTED/INCIDENT_LINKED) | clean |")
    lines.append("|---|---|---|")
    for tier_name in ("HIGH", "MEDIUM", "LOW", "NONE"):
        row = table.get(tier_name)
        if row is None:
            continue
        lines.append(f"| {tier_name} | {row.get('negative', 0)} | {row.get('clean', 0)} |")
    lines.append("")
    lines.append("## HIGH quality against real outcomes")
    lines.append("")
    lines.append(
        f"- precision **{pr['precision']}** ({pr['tp']} TP / {pr['fp']} FP), recall **{pr['recall']}** ({pr['fn']} FN missed)"
    )
    lines.append(f"- LOW-tier share with any negative outcome: **{low_neg:.1%}**")
    if bundles is not None:
        nf = never_fired_rules(bundles)
        lines.append("")
        lines.append("## Rules seen but never weighted (>0)")
        lines.append("")
        if nf:
            lines.extend(f"- `{r}`" for r in nf)
        else:
            lines.append("- none")
    lines.append("")
    lines.append("## Suggested adjustment")
    lines.append("")
    lines.append("```yaml")
    lines.append(suggested_weights_block(outcomes, current_weights))
    lines.append("```")
    lines.append("")
    lines.append("Risco never self-tunes. Commit changes through a policy PR protected by CODEOWNERS.")
    return "\n".join(lines) + "\n"


def load_outcomes_json(text: str) -> list[Outcome]:
    data = json.loads(text)
    items = data.get("outcomes", data) if isinstance(data, dict) else data
    from risco.outcomes.detect import outcome_from_dict

    return [outcome_from_dict(x) for x in items]
