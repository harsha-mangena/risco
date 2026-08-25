from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Tier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2}[self.value]


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    CONTRACT = "CONTRACT"
    DDL = "DDL"
    CONSUMER = "CONSUMER"
    OWNERSHIP = "OWNERSHIP"
    INCIDENT = "INCIDENT"
    UNCERTAINTY = "UNCERTAINTY"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Strategy(str, Enum):
    S1_GENERATED_CLIENT = "S1_GENERATED_CLIENT"
    S2_LITERAL_WITH_METHOD = "S2_LITERAL_WITH_METHOD"
    S3_LITERAL_PATH = "S3_LITERAL_PATH"
    S4_FRAGMENT = "S4_FRAGMENT"
    S5_BASE_URL = "S5_BASE_URL"
    U_UNRESOLVED = "U_UNRESOLVED"


class ChangeStatus(str, Enum):
    ADDED = "A"
    MODIFIED = "M"
    DELETED = "D"
    RENAMED = "R"


class FileCategory(str, Enum):
    MIGRATION = "migration"
    CONTRACT = "contract"
    POLICY = "policy"
    CODEOWNERS = "codeowners"
    SOURCE = "source"
    OTHER = "other"


class UncertaintyFlag(str, Enum):
    INDEX_STALE = "INDEX_STALE"
    INDEX_MISSING = "INDEX_MISSING"
    UNRESOLVED_CONSUMERS = "UNRESOLVED_CONSUMERS"
    MIGRATION_UNPARSEABLE = "MIGRATION_UNPARSEABLE"
    CONTRACT_TOOL_UNAVAILABLE = "CONTRACT_TOOL_UNAVAILABLE"
    SNAPSHOT_ANACHRONISTIC = "SNAPSHOT_ANACHRONISTIC"


class Location(Strict):
    repo: str = ""
    path: str = ""
    line_start: int = 0
    line_end: int = 0


class OperationRef(Strict):
    method: Optional[str] = None
    path_template: Optional[str] = None
    operation_id: Optional[str] = None
    rpc: Optional[str] = None

    def key(self) -> str:
        parts = [
            (self.method or "").lower(),
            self.path_template or "",
            self.operation_id or "",
            self.rpc or "",
        ]
        return "|".join(parts)


class Finding(Strict):
    id: str
    category: Category
    severity: Severity
    title: str
    location: Location = Field(default_factory=Location)
    details: dict[str, Any] = Field(default_factory=dict)
    weight: int = 0


class Consumer(Strict):
    service: str
    repo: str
    path: str
    line: int
    strategy: Strategy
    confidence: Confidence
    operation: OperationRef = Field(default_factory=OperationRef)


class ContractChange(Strict):
    source: str
    operation: OperationRef = Field(default_factory=OperationRef)
    change_id: str
    breaking: bool
    description: str


class Approval(Strict):
    user: str
    team_memberships: list[str] = []
    state: str = "APPROVED"
    sha: str = ""


class RequiredReviewers(Strict):
    min_approvals: int = 1
    users: list[str] = []
    teams: list[str] = []
    owner_paths: list[str] = []
    owner_users: list[str] = []
    consumer_owner_teams: list[str] = []
    require_owners: bool = False
    require_consumer_owners: bool = False


class Override(Strict):
    user: str
    reason: str
    timestamp: str
    from_tier: Tier
    to_tier: Tier


class Verdict(Strict):
    tier: Tier
    score: int
    hard_rules_fired: list[str] = []
    reasons: list[str] = []
    required_reviewers: RequiredReviewers = Field(default_factory=RequiredReviewers)
    uncertainty_flags: list[str] = []
    policy_hash: str = ""
    engine_version: str = ""

    def with_tier(self, tier: Tier) -> "Verdict":
        data = self.model_dump()
        data["tier"] = tier
        return Verdict(**data)


class EvidenceBundle(Strict):
    schema_version: str
    repo: str
    pr_number: int = 0
    base_sha: str = ""
    head_sha: str = ""
    index_snapshot_id: str = ""
    tool_versions: dict[str, str] = Field(default_factory=dict)
    inputs: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    consumers: list[Consumer] = Field(default_factory=list)
    contract_changes: list[ContractChange] = Field(default_factory=list)
    verdict: Optional[Verdict] = None
    approvals_at_evaluation: list[Approval] = Field(default_factory=list)
    overrides: list[Override] = Field(default_factory=list)
    generated_at: str = ""
    bundle_hash: str = ""


class OutcomeLabel(str, Enum):
    REVERTED = "REVERTED"
    HOTFIX_FOLLOWED = "HOTFIX_FOLLOWED"
    INCIDENT_LINKED = "INCIDENT_LINKED"
    MAIN_CI_FAILED = "MAIN_CI_FAILED"
    CLEAN = "CLEAN"


class Outcome(Strict):
    repo: str
    pr_number: int
    merge_sha: str = ""
    tier_at_merge: Optional[Tier] = None
    labels: list[OutcomeLabel] = []
    evidence_refs: list[str] = []
    window_days: int = 14


class IndexManifest(Strict):
    snapshot_id: str = ""
    generated_at: str = ""
    indexer_version: str = ""
    repos: dict[str, str] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)
