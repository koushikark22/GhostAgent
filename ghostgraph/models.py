from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: str | datetime | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    normalized = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class Environment(str, Enum):
    development = "development"
    staging = "staging"
    production = "production"


class AgentStatus(str, Enum):
    active = "active"
    retiring = "retiring"
    retired = "retired"
    decommissioned = "decommissioned"


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingSeverity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class RetirementRequest(BaseModel):
    agent_id: str = Field(min_length=3)
    owner: str | None = None
    status: Literal["retire", "verify", "decommission"] = "retire"
    reason: str = "No reason provided"
    environment: Environment | None = None
    requested_by: str = "local-user"
    requested_at: datetime = Field(default_factory=utc_now)

    @field_validator("requested_at", mode="before")
    @classmethod
    def _parse_requested_at(cls, value: Any) -> datetime:
        return parse_dt(value) or utc_now()


class AgentRecord(BaseModel):
    agent_id: str
    owner: str
    status: AgentStatus
    environment: Environment
    service_account: str | None = None
    created_at: datetime | None = None
    retired_at: datetime | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("created_at", "retired_at", mode="before")
    @classmethod
    def _parse_dates(cls, value: Any) -> datetime | None:
        return parse_dt(value)


class ToolConnection(BaseModel):
    agent_id: str
    tool: str
    connection_id: str
    status: Literal["active", "disabled", "revoked"]
    scopes: list[str] = Field(default_factory=list)
    privilege: Literal["read", "write", "admin"] = "read"
    environment: Environment
    last_verified_at: datetime | None = None

    @field_validator("last_verified_at", mode="before")
    @classmethod
    def _parse_date(cls, value: Any) -> datetime | None:
        return parse_dt(value)

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    @property
    def is_privileged(self) -> bool:
        dangerous_words = {"write", "admin", "delete", "manage", "cluster-admin", "owner"}
        return self.privilege in {"write", "admin"} or any(
            any(word in scope.lower() for word in dangerous_words) for scope in self.scopes
        )


class TokenRecord(BaseModel):
    agent_id: str
    token_id: str
    provider: str
    status: Literal["active", "revoked", "expired"]
    scopes: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    rotation_required: bool = False

    @field_validator("created_at", "expires_at", "last_used_at", mode="before")
    @classmethod
    def _parse_dates(cls, value: Any) -> datetime | None:
        return parse_dt(value)

    @property
    def is_active(self) -> bool:
        if self.status != "active":
            return False
        if self.expires_at and self.expires_at < utc_now():
            return False
        return True


class MemoryNamespace(BaseModel):
    agent_id: str
    namespace: str
    status: Literal["active", "read_only", "quarantined", "deleted"]
    writable: bool
    sensitive_records: int = 0
    last_accessed_at: datetime | None = None

    @field_validator("last_accessed_at", mode="before")
    @classmethod
    def _parse_date(cls, value: Any) -> datetime | None:
        return parse_dt(value)


class InboundInvocation(BaseModel):
    agent_id: str
    source_type: Literal["webhook", "scheduler", "queue", "api", "agent"]
    source_id: str
    status: Literal["active", "disabled"]
    last_invoked_at: datetime | None = None
    environment: Environment

    @field_validator("last_invoked_at", mode="before")
    @classmethod
    def _parse_date(cls, value: Any) -> datetime | None:
        return parse_dt(value)

    @property
    def is_active(self) -> bool:
        return self.status == "active"


class DependencyEdge(BaseModel):
    source_agent_id: str
    target_agent_id: str
    relation: Literal["calls", "delegates_to", "reads_memory", "writes_to", "uses_tool"]
    environment: Environment
    status: Literal["active", "disabled"] = "active"


class KubernetesBinding(BaseModel):
    agent_id: str
    service_account: str
    namespace: str
    binding_name: str
    role_name: str
    role_kind: Literal["Role", "ClusterRole"]
    verbs: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    status: Literal["active", "removed"] = "active"

    @property
    def is_dangerous(self) -> bool:
        role = self.role_name.lower()
        if self.role_kind == "ClusterRole" and "cluster-admin" in role:
            return True
        if "*" in self.verbs or "*" in self.resources:
            return True
        dangerous_verbs = {"create", "update", "patch", "delete", "deletecollection", "impersonate", "bind", "escalate"}
        return any(verb.lower() in dangerous_verbs for verb in self.verbs)


class Finding(BaseModel):
    finding_id: str
    severity: FindingSeverity
    category: str
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str | None = None


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    reasons: list[str] = Field(default_factory=list)
    score_breakdown: dict[str, int | float] = Field(default_factory=dict)


class RevocationAction(BaseModel):
    action_id: str
    action_type: str
    target: str
    description: str
    approval_required: bool = True
    status: Literal["planned", "approved", "rejected", "executed_mock", "blocked", "skipped"] = "planned"
    environment: Environment
    rollback: str
    evidence_file: str | None = None
    policy_decision: str | None = None
    policy_reason: str | None = None


class ApprovalDecision(BaseModel):
    approved: bool
    approver: str = "local-user"
    reason: str = "No reason provided"
    approved_at: datetime = Field(default_factory=utc_now)

    @field_validator("approved_at", mode="before")
    @classmethod
    def _parse_date(cls, value: Any) -> datetime:
        return parse_dt(value) or utc_now()


class AuditEvent(BaseModel):
    step: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)


class DecommissionCertificate(BaseModel):
    agent_id: str
    status: Literal["complete", "blocked", "requires_review"]
    evidence_hash: str
    certificate_hash: str
    signature_algorithm: str
    signature: str
    public_key: str
    issued_at: datetime = Field(default_factory=utc_now)
    summary: dict[str, Any] = Field(default_factory=dict)
