from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from risco.contract.bufdiff import diff_proto, find_buf
from risco.contract.normalize import normalize_buf, normalize_oasdiff
from risco.contract.oasdiff import diff_openapi
from risco.ddl.analyzer import analyze_migrations
from risco.diff import ChangedFileSet, classify_all, git_diff_name_status
from risco.errors import ToolUnavailable
from risco.evidence.bundle import build_bundle, write_bundle
from risco.incidents import exposure as inc_exposure
from risco.models import (
    Approval,
    Category,
    Consumer,
    FileCategory,
    ContractChange,
    Finding,
    Location,
    Override,
    Severity,
    UncertaintyFlag,
)
from risco.ownership.codeowners import resolve_ownership
from risco.policy.loader import LoadedPolicy
from risco.render.render import (
    CHECK_NAME,
    build_annotations,
    neutral_summary,
    render_comment,
    render_summary,
)
from risco.verdict.enforcement import evaluate_enforcement
from risco.verdict.engine import EvalInputs, OwnershipInput, apply_override, evaluate

R_POL_001 = "R-POL-001"
R_CON_900 = "R-CON-900"
R_OWN_001 = "R-OWN-001"
R_OWN_900 = "R-OWN-900"


@dataclass
class AnalysisSources:
    base_texts: dict[str, str] = field(default_factory=dict)
    head_texts: dict[str, str] = field(default_factory=dict)


@dataclass
class PipelineResult:
    status: str = "ok"
    neutral_reason: str = ""
    error_id: str = ""
    tier: str = "LOW"
    score: int = 0
    bundle: Any = None
    summary_markdown: str = ""
    comment_markdown: str = ""
    annotation_batches: list[list[dict]] = field(default_factory=list)
    enforcement_missing: list[str] = field(default_factory=list)
    satisfied: Optional[bool] = None
    flags: list[str] = field(default_factory=list)
    requested_reviewers_users: list[str] = field(default_factory=list)
    requested_reviewers_teams: list[str] = field(default_factory=list)

    @property
    def is_neutral(self) -> bool:
        return self.status == "neutral"


def _load_texts_from_dir(root: str) -> dict[str, str]:
    texts: dict[str, str] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    texts[rel] = f.read()
            except OSError:
                continue
    return texts


def sources_from_dirs(base_dir: Optional[str], head_dir: Optional[str]) -> AnalysisSources:
    src = AnalysisSources()
    if base_dir:
        src.base_texts = _load_texts_from_dir(base_dir)
    if head_dir:
        src.head_texts = _load_texts_from_dir(head_dir)
    return src


def changed_entries_from_repo(repo_dir: str, base: str, head: str):
    return git_diff_name_status(repo_dir, base, head)


class Analyzer:
    def __init__(
        self,
        loaded_policy: LoadedPolicy,
        index_conn=None,
        index_manifest: Optional[dict] = None,
        repo_full: str = "",
        pr_number: int = 0,
        base_sha: str = "",
        head_sha: str = "",
        mode_override: Optional[str] = None,
        tool_versions: Optional[dict[str, str]] = None,
        now_iso: str = "",
        proto_base_dir: str = "",
        proto_head_dir: str = "",
    ):
        self.proto_base_dir = proto_base_dir
        self.proto_head_dir = proto_head_dir
        self.lp = loaded_policy
        self.policy = loaded_policy.policy
        self.svc = self.policy.service.resolved()
        self.index_conn = index_conn
        self.index_manifest = index_manifest or {}
        self.repo_full = repo_full
        self.pr_number = pr_number
        self.base_sha = base_sha
        self.head_sha = head_sha
        self.mode = mode_override or self.policy.mode
        self.tool_versions = tool_versions or {}
        self.now_iso = now_iso

    def run(
        self,
        entries: list[tuple[str, str, Optional[str]]],
        sources: AnalysisSources,
        approvals: Optional[list[Approval]] = None,
        override_request: Optional[tuple[str, str, str]] = None,
    ) -> PipelineResult:
        try:
            return self._run_inner(entries, sources, approvals or [], override_request)
        except Exception as e:
            eid = uuid.uuid4().hex[:12]
            res = PipelineResult(status="neutral", neutral_reason=f"{type(e).__name__}: {e}", error_id=eid)
            res.summary_markdown = neutral_summary(res.neutral_reason[:300], eid)
            return res

    def _run_inner(self, entries, sources, approvals, override_request=None) -> PipelineResult:
        from risco.index.snapshot import Snapshot

        file_set: ChangedFileSet = classify_all(entries, self.svc, policy_path="risco.yml")
        changed_paths = [f.path for f in file_set.files if f.status.value != "D"]
        findings: list[Finding] = []
        flags: set[str] = set()
        contract_changes: list[ContractChange] = []
        consumers_flat: list[Consumer] = []
        consumers_by_change: dict[str, list[Consumer]] = {}
        unresolved_relevant: list[dict] = []

        migration_texts = {
            f.path: sources.head_texts[f.path]
            for f in file_set.of(FileCategory.MIGRATION)
            if f.status.value != "D" and f.path in sources.head_texts
        }
        old_migration_texts = {
            (f.old_path or f.path): sources.base_texts.get(f.old_path or f.path, "")
            for f in file_set.of(FileCategory.MIGRATION)
            if f.status.value == "D"
        }
        del old_migration_texts

        if migration_texts:
            source_texts = {
                f.path: sources.head_texts.get(f.path, "")
                for f in file_set.source_files()
                if f.status.value != "D" and f.path in sources.head_texts
            }
            ddl = analyze_migrations(self.repo_full, migration_texts, source_texts)
            findings.extend(ddl.findings)
            if ddl.unparseable:
                flags.add(UncertaintyFlag.MIGRATION_UNPARSEABLE.value)

        openapi_changed = [
            f
            for f in file_set.files
            if (f.old_path or f.path) and self.svc.is_contract(f.old_path or f.path) == "openapi"
        ]
        head_doc = None
        if openapi_changed:
            primary = openapi_changed[0]
            base_key = primary.old_path or primary.path
            base_text = sources.base_texts.get(base_key, "")
            head_text = sources.head_texts.get(primary.path, "")
            if not base_text or not head_text:
                findings.append(
                    Finding(
                        id=R_CON_900,
                        category=Category.UNCERTAINTY,
                        severity=Severity.MEDIUM,
                        title="Contract unparseable (missing base or head revision)",
                        location=Location(repo=self.repo_full, path=primary.path),
                    )
                )
            else:
                from risco.contract.openapi_doc import load_openapi_text

                try:
                    items = diff_openapi(base_text, head_text)
                    try:
                        head_doc = load_openapi_text(head_text, primary.path)
                    except Exception:
                        head_doc = None
                    contract_changes.extend(normalize_oasdiff(items, head_doc))
                except ToolUnavailable as e:
                    flags.add(UncertaintyFlag.CONTRACT_TOOL_UNAVAILABLE.value)
                    findings.append(
                        Finding(
                            id=R_CON_900,
                            category=Category.UNCERTAINTY,
                            severity=Severity.MEDIUM,
                            title=f"Contract diff unavailable ({e.tool} not found)",
                            location=Location(repo=self.repo_full, path=primary.path),
                        )
                    )
                except Exception as e:
                    findings.append(
                        Finding(
                            id=R_CON_900,
                            category=Category.UNCERTAINTY,
                            severity=Severity.MEDIUM,
                            title="Contract diff failed",
                            location=Location(repo=self.repo_full, path=primary.path),
                            details={"reason": str(e)[:200]},
                        )
                    )

        proto_changed = [
            f
            for f in file_set.files
            if (f.old_path or f.path) and self.svc.is_contract(f.old_path or f.path) == "protobuf"
        ]
        if proto_changed:
            buf = find_buf()
            if buf is None:
                flags.add(UncertaintyFlag.CONTRACT_TOOL_UNAVAILABLE.value)
                findings.append(
                    Finding(
                        id=R_CON_900,
                        category=Category.UNCERTAINTY,
                        severity=Severity.MEDIUM,
                        title="Contract diff unavailable (buf not found)",
                        location=Location(repo=self.repo_full, path=proto_changed[0].path),
                    )
                )
            else:
                items = []
                try:
                    if self.proto_base_dir and self.proto_head_dir:
                        items = diff_proto(self.proto_base_dir, self.proto_head_dir, binary=buf)
                    else:
                        items = []
                except Exception as e:
                    if isinstance(e, ToolUnavailable):
                        flags.add(UncertaintyFlag.CONTRACT_TOOL_UNAVAILABLE.value)
                    else:
                        findings.append(
                            Finding(
                                id=R_CON_900,
                                category=Category.UNCERTAINTY,
                                severity=Severity.MEDIUM,
                                title="Protobuf breaking check failed",
                                location=Location(repo=self.repo_full, path=proto_changed[0].path),
                                details={"reason": str(e)[:200]},
                            )
                        )
                if items:
                    contract_changes.extend(normalize_buf(items))

        own_service = self.svc.name or (self.repo_full.split("/", 1)[-1] if "/" in self.repo_full else self.repo_full)
        breaking_changes = [c for c in contract_changes if c.breaking]

        index_present = self.index_conn is not None
        index_age: Optional[float] = None
        if index_present:
            from risco.consumers.resolver import (
                base_url_env_index,
                index_age_hours,
                resolve_consumers,
            )

            index_age = index_age_hours(self.index_manifest, self.now_iso)
            for change in breaking_changes:
                res = resolve_consumers(self.index_conn, own_service, [change.operation])
                per_op = res.highest_per_service(change.operation.key())
                consumers_by_change[change.operation.key()] = per_op
                consumers_flat.extend(per_op)
                unresolved_relevant.extend(res.unresolved_matching)
            _ = base_url_env_index

        codeowners_texts = [
            sources.head_texts[p]
            for p in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")
            if p in sources.head_texts
        ]
        ownership = resolve_ownership(changed_paths, codeowners_texts)
        if not ownership.rules_found:
            findings.append(
                Finding(
                    id=R_OWN_900,
                    category=Category.OWNERSHIP,
                    severity=Severity.INFO,
                    title="No CODEOWNERS file found",
                    location=Location(repo=self.repo_full),
                )
            )

        sensitive_fired: list[tuple[str, list[str]]] = []
        for rule in self.policy.hard_rules:
            if rule.trigger != "paths":
                continue
            hit_paths = sorted({p for p in changed_paths if rule.applies_to_path(p)})
            if hit_paths:
                sensitive_fired.append((str(rule.value), hit_paths))
        for pattern, paths in sensitive_fired:
            findings.append(
                Finding(
                    id=R_OWN_001,
                    category=Category.OWNERSHIP,
                    severity=Severity.INFO,
                    title=f"Sensitive path touched ({pattern})",
                    location=Location(repo=self.repo_full, path=paths[0]),
                    details={"pattern": pattern, "paths": paths},
                )
            )

        if file_set.policy_changed:
            findings.append(
                Finding(
                    id=R_POL_001,
                    category=Category.UNCERTAINTY,
                    severity=Severity.MEDIUM,
                    title="Merge-risk policy changed in this PR",
                    location=Location(repo=self.repo_full, path="risco.yml"),
                    details={"policy_hash": self.lp.policy_hash},
                )
            )

        incident_findings: list[Finding] = []
        if index_present:
            touched_services = {own_service}
            for clist in consumers_by_change.values():
                for c in clist:
                    if c.confidence.value == "HIGH":
                        touched_services.add(c.service)
            incident_findings = inc_exposure.evaluate_exposure(
                self.index_conn,
                self.repo_full,
                changed_paths,
                sorted(touched_services),
                self.policy.weights.incident_exposure.get("lookback_days", 180),
                self.now_iso,
            )
            findings.extend(incident_findings)

        all_findings = findings
        consumer_owner_map: dict[str, list[str]] = {}
        if index_present:
            from risco.ownership.codeowners import parse_codeowners

            repos_needed = sorted({c.repo for c in consumers_flat})
            for crepo in repos_needed:
                row = self.index_conn.execute(
                    "SELECT codeowners FROM repos WHERE name=?", (crepo,)
                ).fetchone()
                text = row[0] if row and row[0] else ""
                if not text:
                    continue
                rules = parse_codeowners(text)
                for c in consumers_flat:
                    if c.repo != crepo:
                        continue
                    owners = set(consumer_owner_map.get(c.service, []))
                    best = None
                    for r in rules:
                        if r.regex.match(c.path):
                            best = r
                    if best:
                        owners.update(best.owners)
                    if owners:
                        consumer_owner_map[c.service] = sorted(owners)

        eval_inputs = EvalInputs(
            repo=self.repo_full,
            changed_paths=[f.path for f in file_set.files if f.status.value != "D"],
            findings=all_findings,
            contract_changes=contract_changes,
            consumers_by_change=consumers_by_change,
            unresolved_relevant=unresolved_relevant,
            ownership=OwnershipInput(
                owners_by_path={p: ownership.owners_for(p) for p in ownership.owners_by_path},
                sensitive_paths_fired=sensitive_fired,
            ),
            consumer_owners=consumer_owner_map,
            policy_hash=self.lp.policy_hash,
            policy=self.policy,
            index_present=index_present,
            index_age_hours=index_age,
            tool_flags=sorted(flags),
        )
        verdict = evaluate(eval_inputs)

        applied_overrides: list[Override] = []
        extra_findings: list[Finding] = []
        if override_request is not None:
            user, target_tier, reason = override_request
            reason_ok = bool(reason.strip()) or not self.policy.overrides.require_reason
            member_teams: dict[str, list[str]] = {}
            if index_present:
                from risco.consumers.resolver import teams_table as _tt

                member_teams = _tt(self.index_conn)
            allowed_slugs = {t.lstrip("@").split("/")[-1] for t in self.policy.overrides.allowed_teams}
            allowed_members = {
                m.lstrip("@")
                for slug in allowed_slugs
                for m in member_teams.get(slug, [])
            }
            is_allowed = user.lstrip("@") in allowed_members
            from_tier = verdict.tier
            new_verdict, ok, msg = apply_override(verdict, target_tier, self.policy)
            if is_allowed and ok and reason_ok:
                verdict = new_verdict
                applied_overrides.append(
                    Override(
                        user=user,
                        reason=reason,
                        timestamp=self.now_iso,
                        from_tier=from_tier,
                        to_tier=verdict.tier,
                    )
                )
            else:
                why = msg or ("user not in allowed_teams" if not is_allowed else "reason required")
                extra_findings.append(
                    Finding(
                        id="R-OVR-400",
                        category=Category.UNCERTAINTY,
                        severity=Severity.MEDIUM,
                        title=f"Override rejected ({why})",
                        location=Location(repo=self.repo_full),
                    )
                )

        enforcement_missing: list[str] = []
        satisfied: Optional[bool] = None
        if self.mode == "enforce":
            team_members: dict[str, list[str]] = {}
            if index_present:
                from risco.consumers.resolver import teams_table

                team_members = teams_table(self.index_conn)
            er = evaluate_enforcement(
                verdict,
                approvals,
                self.head_sha,
                eval_inputs.changed_paths,
                eval_inputs.ownership.owners_by_path,
                consumer_owner_map,
                team_members,
            )
            satisfied = er.satisfied
            enforcement_missing = er.missing

        inputs_bundle = {
            "changed_files": [f.path for f in file_set.files],
            "contract_files": [f.path for f in file_set.files if f.category == FileCategory.CONTRACT],
            "migration_files": [f.path for f in file_set.files if f.category == FileCategory.MIGRATION],
            "policy_hash": self.lp.policy_hash,
            "mode": self.mode,
            "index_age_hours": index_age,
            "unresolved_examples": unresolved_relevant[:5],
            "unresolved_count": len(unresolved_relevant),
            "breaking_change_count": len(breaking_changes),
            "consumer_services": sorted({c.service for c in consumers_flat}),
        }
        bundle = build_bundle(
            repo=self.repo_full,
            pr_number=self.pr_number,
            base_sha=self.base_sha,
            head_sha=self.head_sha,
            index_snapshot_id=str(self.index_manifest.get("snapshot_id", "")),
            tool_versions=self.tool_versions,
            inputs=inputs_bundle,
            findings=all_findings + extra_findings,
            consumers=consumers_flat,
            contract_changes=contract_changes,
            verdict=verdict,
            approvals_at_evaluation=approvals,
            overrides=applied_overrides,
            generated_at=self.now_iso,
        )

        summary = render_summary(bundle, self.mode, enforcement_missing)
        comment = render_comment(bundle, self.mode, enforcement_missing, self.policy.comment.collapse_low_tier)
        anns = build_annotations(bundle)

        return PipelineResult(
            status="ok",
            tier=verdict.tier.value,
            score=verdict.score,
            bundle=bundle,
            summary_markdown=summary,
            comment_markdown=comment,
            annotation_batches=anns,
            enforcement_missing=enforcement_missing,
            satisfied=satisfied,
            flags=verdict.uncertainty_flags,
        )


def write_evidence(result: PipelineResult, out_dir: str) -> tuple[str, str]:
    assert result.bundle is not None
    return write_bundle(result.bundle, out_dir)


CHECK_RUN_TITLE = CHECK_NAME
