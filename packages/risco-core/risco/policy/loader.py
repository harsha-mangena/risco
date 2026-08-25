from __future__ import annotations

import re
from typing import Any, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from risco.canonical import canonical_json, stable_hash
from risco.errors import PolicyError
from risco.globs import match_path

POLICY_VERSION = 1
ENGINE_VERSION = "risco-engine-0.1.0"

DEFAULT_SEVERITY_WEIGHTS = {"HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}
DEFAULT_CONSUMER_MULTIPLIER = {
    "HIGH_confidence_service": 6,
    "MEDIUM_confidence_service": 3,
    "LOW_confidence_service": 1,
    "cap": 30,
}
DEFAULT_INCIDENT_EXPOSURE = {"lookback_days": 180, "per_incident": 5, "cap": 20}
DEFAULT_TIERS = {"LOW": {"max_score": 5}, "MEDIUM": {"max_score": 19}, "HIGH": {"min_score": 20}}
DEFAULT_UNCERTAINTY = {
    "index_missing": "MEDIUM",
    "index_stale": "MEDIUM",
    "unresolved_consumers": "MEDIUM",
    "migration_unparseable": "MEDIUM",
    "contract_tool_unavailable": "MEDIUM",
}
DEFAULT_ROUTING = {
    "LOW": {"min_approvals": 1},
    "MEDIUM": {"min_approvals": 1, "require_owners": True},
    "HIGH": {
        "min_approvals": 2,
        "require_owners": True,
        "require_teams": ["platform-leads"],
        "require_consumer_owners": True,
    },
}
DEFAULT_CONTRACT_PATHS = [
    "openapi.yaml",
    "openapi.yml",
    "openapi.json",
    "openapi/*.yaml",
    "openapi/**/*.yaml",
    "api/openapi*",
]
DEFAULT_PROTO_PATHS = ["proto/**", "**/*.proto"]
DEFAULT_MIGRATION_PATHS = [
    "db/migrations/**/*.sql",
    "db/migrations/*.sql",
    "prisma/migrations/**/migration.sql",
    "alembic/versions/*.py",
]

TRIGGER_KEYS = ("finding", "any_breaking_contract_with_consumers", "paths")


class ServiceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = ""
    contracts_openapi: list[str] = []
    contracts_protobuf: list[str] = []
    migrations_paths: list[str] = DEFAULT_MIGRATION_PATHS
    base_url_env: list[str] = []

    @model_validator(mode="before")
    @classmethod
    def _alias(cls, data: Any) -> Any:
        if isinstance(data, dict):
            d = dict(data)
            contracts = d.pop("contracts", None)
            if isinstance(contracts, dict):
                d.setdefault("contracts_openapi", contracts.get("openapi", []))
                d.setdefault("contracts_protobuf", contracts.get("protobuf", []))
            m = d.pop("migrations", None)
            if isinstance(m, dict):
                d.setdefault("migrations_paths", m.get("paths", []))
            return d
        return data

    def resolved(self) -> "ServiceConfig":
        return ServiceConfig(
            name=self.name,
            contracts_openapi=self.contracts_openapi or DEFAULT_CONTRACT_PATHS,
            contracts_protobuf=self.contracts_protobuf or [],
            migrations_paths=self.migrations_paths or DEFAULT_MIGRATION_PATHS,
            base_url_env=self.base_url_env,
        )

    def is_migration(self, path: str) -> bool:
        return match_path(path, self.migrations_paths)

    def is_contract(self, path: str) -> bool | None:
        if match_path(path, self.contracts_openapi):
            return "openapi"
        if match_path(path, self.contracts_protobuf):
            return "protobuf"
        return None


class IndexConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["release", "artifact", "path"] = "release"
    repo: str = ""
    max_age_hours: int = 36


class Weights(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    severity: dict[str, int] = DEFAULT_SEVERITY_WEIGHTS.copy()
    consumer_multiplier: dict[str, int] = DEFAULT_CONSUMER_MULTIPLIER.copy()
    incident_exposure: dict[str, int] = DEFAULT_INCIDENT_EXPOSURE.copy()

    @field_validator("severity")
    @classmethod
    def _sev(cls, v: dict[str, int]) -> dict[str, int]:
        out = DEFAULT_SEVERITY_WEIGHTS.copy()
        for k, val in v.items():
            if k not in out:
                raise ValueError(f"unknown severity weight key: {k}")
            out[k] = int(val)
        return out

    @field_validator("consumer_multiplier")
    @classmethod
    def _mult(cls, v: dict[str, int]) -> dict[str, int]:
        out = DEFAULT_CONSUMER_MULTIPLIER.copy()
        for k, val in v.items():
            if k not in out:
                raise ValueError(f"unknown consumer_multiplier key: {k}")
            out[k] = int(val)
        return out

    @field_validator("incident_exposure")
    @classmethod
    def _inc(cls, v: dict[str, int]) -> dict[str, int]:
        out = DEFAULT_INCIDENT_EXPOSURE.copy()
        for k, val in v.items():
            if k not in out:
                raise ValueError(f"unknown incident_exposure key: {k}")
            out[k] = int(val)
        return out


class TierRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_score: Optional[int] = None
    min_score: Optional[int] = None


class HardRule(BaseModel):
    trigger: str
    value: Any
    tier: Optional[str] = None
    min_tier: Optional[str] = None
    raw_index: int = 0

    @property
    def kind(self) -> str:
        return self.trigger

    def applies_to_path(self, path: str) -> bool:
        if self.trigger != "paths" or not isinstance(self.value, list):
            return False
        return match_path(path, [str(p) for p in self.value])


class UncertaintyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    index_missing: str = "MEDIUM"
    index_stale: str = "MEDIUM"
    unresolved_consumers: str = "MEDIUM"
    migration_unparseable: str = "MEDIUM"
    contract_tool_unavailable: str = "MEDIUM"

    @model_validator(mode="before")
    @classmethod
    def _fill(cls, data: Any) -> Any:
        merged = dict(DEFAULT_UNCERTAINTY)
        if isinstance(data, dict):
            merged.update(data)
        return merged


class RoutingRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    min_approvals: int = 1
    require_owners: bool = False
    require_teams: list[str] = []
    require_consumer_owners: bool = False


class OverridesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_teams: list[str] = []
    require_reason: bool = True
    max_downgrade: int = 1


class EvidenceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    upload_artifact: bool = True
    commit_to_branch: str = ""
    include_line_context: bool = False


class CommentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    collapse_low_tier: bool = True


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = POLICY_VERSION
    service: ServiceConfig = Field(default_factory=ServiceConfig)
    index: IndexConfig = Field(default_factory=IndexConfig)
    mode: Literal["advisory", "enforce"] = "advisory"
    weights: Weights = Field(default_factory=Weights)
    tiers: dict[str, TierRule] = Field(
        default_factory=lambda: {k: TierRule(**v) for k, v in DEFAULT_TIERS.items()}
    )
    hard_rules: list[HardRule] = []
    uncertainty: UncertaintyConfig = Field(default_factory=UncertaintyConfig)
    routing: dict[str, RoutingRule] = Field(
        default_factory=lambda: {k: RoutingRule(**v) for k, v in DEFAULT_ROUTING.items()}
    )
    overrides: OverridesConfig = Field(default_factory=OverridesConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    comment: CommentConfig = Field(default_factory=CommentConfig)

    @field_validator("version")
    @classmethod
    def _version(cls, v: int) -> int:
        if v != POLICY_VERSION:
            raise ValueError(f"unsupported policy version: {v} (expected {POLICY_VERSION})")
        return v

    @model_validator(mode="before")
    @classmethod
    def _normalize_hard_rules(cls, data: Any) -> Any:
        if isinstance(data, dict) and "hard_rules" in data:
            rules = data["hard_rules"]
            if isinstance(rules, list):
                normalized = []
                for i, r in enumerate(rules):
                    if not isinstance(r, dict):
                        raise ValueError(f"hard_rules[{i}] must be a mapping")
                    triggers = [k for k in TRIGGER_KEYS if k in r]
                    if len(triggers) != 1:
                        raise ValueError(
                            f"hard_rules[{i}] must have exactly one trigger of {TRIGGER_KEYS}"
                        )
                    nr = {
                        "trigger": triggers[0],
                        "value": r[triggers[0]],
                        "raw_index": i,
                    }
                    for out_key in ("tier", "min_tier"):
                        if out_key in r:
                            nr[out_key] = r[out_key]
                    has_effect = "tier" in nr or "min_tier" in nr
                    if not has_effect:
                        raise ValueError(f"hard_rules[{i}] needs 'tier' or 'min_tier'")
                    normalized.append(nr)
                data = dict(data)
                data["hard_rules"] = normalized
        return data

    @field_validator("tiers")
    @classmethod
    def _tiers(cls, v: dict[str, TierRule]) -> dict[str, TierRule]:
        merged: dict[str, TierRule] = {}
        for name in ("LOW", "MEDIUM", "HIGH"):
            rule = v.get(name) or TierRule(**DEFAULT_TIERS[name])
            merged[name] = rule
        extra = set(v.keys()) - {"LOW", "MEDIUM", "HIGH"}
        if extra:
            raise ValueError(f"unknown tiers: {sorted(extra)}")
        return merged

    @field_validator("routing")
    @classmethod
    def _routing(cls, v: dict[str, RoutingRule]) -> dict[str, RoutingRule]:
        merged: dict[str, RoutingRule] = {}
        for name in ("LOW", "MEDIUM", "HIGH"):
            default = RoutingRule(**DEFAULT_ROUTING[name])
            given = v.get(name)
            if given is None:
                merged[name] = default
            else:
                d = default.model_dump()
                g = given.model_dump(exclude_none=True)
                d.update(g)
                merged[name] = RoutingRule(**d)
        extra = set(v.keys()) - {"LOW", "MEDIUM", "HIGH"}
        if extra:
            raise ValueError(f"unknown routing tiers: {sorted(extra)}")
        return merged

    def tier_for_score(self, score: int) -> str:
        low_max = self.tiers["LOW"].max_score
        med_max = self.tiers["MEDIUM"].max_score
        high_min = self.tiers["HIGH"].min_score
        if high_min is not None and score >= high_min:
            return "HIGH"
        if med_max is not None and score <= med_max and (low_max is None or score > low_max):
            return "MEDIUM"
        if low_max is not None and score <= low_max:
            return "LOW"
        return "HIGH"


class LoadedPolicy(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    policy: Policy
    raw: dict[str, Any]
    policy_hash: str
    source_path: str = ""


def parse_policy_dict(raw: dict[str, Any], source_path: str = "") -> LoadedPolicy:
    try:
        policy = Policy(**raw)
    except Exception as e:
        raise PolicyError(_format_validation_error(e)) from e
    return LoadedPolicy(policy=policy, raw=raw, policy_hash=stable_hash(raw), source_path=source_path)


def load_policy_text(text: str, source_path: str = "") -> LoadedPolicy:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyError(f"invalid YAML in policy: {e}") from e
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError("policy root must be a YAML mapping")
    return parse_policy_dict(raw, source_path)


def load_policy(path: str) -> LoadedPolicy:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    return load_policy_text(text, source_path=path)


def _format_validation_error(e: Exception) -> str:
    msg = str(e)
    lines = re.findall(r"\d+\s+validation error.*?(?=\n\d+\s|$)", msg, flags=re.S)
    if lines:
        return "\n".join(l.strip() for l in lines[:10])
    return msg
