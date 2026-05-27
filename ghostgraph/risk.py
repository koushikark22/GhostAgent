from __future__ import annotations

from datetime import datetime
from typing import Any

from .models import (
    AgentRecord,
    Environment,
    Finding,
    FindingSeverity,
    InboundInvocation,
    KubernetesBinding,
    MemoryNamespace,
    RiskAssessment,
    RiskLevel,
    TokenRecord,
    ToolConnection,
)


def _level(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.critical
    if score >= 60:
        return RiskLevel.high
    if score >= 30:
        return RiskLevel.medium
    return RiskLevel.low


def _used_after_retirement(token: TokenRecord, agent: AgentRecord | None) -> bool:
    if not token.last_used_at or not agent or not agent.retired_at:
        return False
    return token.last_used_at > agent.retired_at


def _invoked_after_retirement(invocation: InboundInvocation, agent: AgentRecord | None) -> bool:
    if not invocation.last_invoked_at or not agent or not agent.retired_at:
        return False
    return invocation.last_invoked_at > agent.retired_at


def build_findings(
    agent: AgentRecord | None,
    tool_connections: list[ToolConnection],
    tokens: list[TokenRecord],
    memory_namespaces: list[MemoryNamespace],
    inbound_invocations: list[InboundInvocation],
    dependencies: dict[str, Any],
    kubernetes_bindings: list[KubernetesBinding],
) -> list[Finding]:
    findings: list[Finding] = []

    if agent is None:
        return [
            Finding(
                finding_id="GG-IDENTITY-404",
                severity=FindingSeverity.critical,
                category="identity",
                title="Agent identity not found",
                description="The requested agent is not present in the registry. Offboarding cannot be verified.",
                evidence=[],
                recommended_action="Create or import an authoritative agent identity record before decommissioning.",
            )
        ]

    if agent.status not in {"retired", "retiring", "decommissioned"}:
        findings.append(
            Finding(
                finding_id="GG-IDENTITY-001",
                severity=FindingSeverity.medium,
                category="identity",
                title="Agent is not marked as retiring or retired",
                description=f"Registry status is {agent.status.value}.",
                evidence=[f"agent_registry.status={agent.status.value}"],
                recommended_action="Mark the agent as retiring before running decommission actions.",
            )
        )

    active_privileged = [item for item in tool_connections if item.is_active and item.is_privileged]
    if active_privileged:
        findings.append(
            Finding(
                finding_id="GG-TOOLS-001",
                severity=FindingSeverity.high,
                category="tool_access",
                title="Active privileged tool connections remain",
                description="The retiring agent still has active privileged tool connections.",
                evidence=[f"{item.tool}:{item.connection_id}:{','.join(item.scopes)}" for item in active_privileged],
                recommended_action="Disable or downgrade privileged tool connections before marking the agent decommissioned.",
            )
        )

    active_tokens = [item for item in tokens if item.is_active]
    if active_tokens:
        findings.append(
            Finding(
                finding_id="GG-TOKEN-001",
                severity=FindingSeverity.high,
                category="credential",
                title="Active credentials remain",
                description="The retiring agent still has active tokens or secrets.",
                evidence=[f"{item.provider}:{item.token_id}" for item in active_tokens],
                recommended_action="Revoke or rotate all agent-owned credentials.",
            )
        )

    post_retirement_tokens = [item for item in active_tokens if _used_after_retirement(item, agent)]
    if post_retirement_tokens:
        findings.append(
            Finding(
                finding_id="GG-TOKEN-002",
                severity=FindingSeverity.critical,
                category="credential",
                title="Credential used after retirement",
                description="At least one credential was used after the agent retirement timestamp.",
                evidence=[f"{item.provider}:{item.token_id}:last_used_at={item.last_used_at}" for item in post_retirement_tokens],
                recommended_action="Investigate possible ghost execution, leaked credentials, or token reuse by another workflow.",
            )
        )

    writable_memory = [item for item in memory_namespaces if item.writable and item.status == "active"]
    if writable_memory:
        findings.append(
            Finding(
                finding_id="GG-MEMORY-001",
                severity=FindingSeverity.high,
                category="memory",
                title="Writable memory namespace remains active",
                description="The retired agent can still write to one or more memory namespaces.",
                evidence=[f"{item.namespace}:sensitive_records={item.sensitive_records}" for item in writable_memory],
                recommended_action="Quarantine memory namespaces as read-only and restrict access to approved reviewers.",
            )
        )

    active_inbound = [item for item in inbound_invocations if item.is_active]
    if active_inbound:
        findings.append(
            Finding(
                finding_id="GG-INBOUND-001",
                severity=FindingSeverity.high,
                category="inbound_invocation",
                title="Inbound invocation paths remain active",
                description="The retired agent can still be triggered by webhooks, schedulers, queues, application programming interfaces, or other agents.",
                evidence=[f"{item.source_type}:{item.source_id}" for item in active_inbound],
                recommended_action="Disable inbound triggers before retiring the agent.",
            )
        )

    post_retirement_invocations = [item for item in active_inbound if _invoked_after_retirement(item, agent)]
    if post_retirement_invocations:
        findings.append(
            Finding(
                finding_id="GG-RESURRECTION-001",
                severity=FindingSeverity.critical,
                category="resurrection",
                title="Ghost agent resurrection signal detected",
                description="The agent was invoked after its retirement timestamp.",
                evidence=[f"{item.source_type}:{item.source_id}:last_invoked_at={item.last_invoked_at}" for item in post_retirement_invocations],
                recommended_action="Block inbound traffic immediately and investigate the source of post-retirement execution.",
            )
        )

    if dependencies.get("has_blocking_dependencies"):
        findings.append(
            Finding(
                finding_id="GG-DEPS-001",
                severity=FindingSeverity.high,
                category="dependency",
                title="Production agents still depend on retiring agent",
                description="One or more production agents still call or delegate to this agent.",
                evidence=[f"called_by={item['agent_id']} relation={item.get('relation')}" for item in dependencies.get("production_callers", [])],
                recommended_action="Migrate or disable upstream dependencies before final decommission.",
            )
        )

    dangerous_bindings = [item for item in kubernetes_bindings if item.status == "active" and item.is_dangerous]
    if dangerous_bindings:
        findings.append(
            Finding(
                finding_id="GG-K8S-001",
                severity=FindingSeverity.critical,
                category="kubernetes",
                title="Dangerous Kubernetes binding remains active",
                description="The agent service account still has a dangerous Kubernetes RoleBinding or ClusterRoleBinding.",
                evidence=[f"{item.namespace}/{item.binding_name}:{item.role_kind}/{item.role_name}" for item in dangerous_bindings],
                recommended_action="Remove dangerous service account bindings or replace them with least-privilege namespace roles.",
            )
        )

    return findings


def calculate_residual_risk(
    agent: AgentRecord | None,
    tool_connections: list[ToolConnection],
    tokens: list[TokenRecord],
    memory_namespaces: list[MemoryNamespace],
    inbound_invocations: list[InboundInvocation],
    dependencies: dict[str, Any],
    kubernetes_bindings: list[KubernetesBinding],
) -> RiskAssessment:
    score = 0
    reasons: list[str] = []
    breakdown: dict[str, int | float] = {}

    active_tokens = [item for item in tokens if item.is_active]
    token_points = min(len(active_tokens) * 12, 35)
    if token_points:
        score += token_points
        breakdown["active_tokens"] = token_points
        reasons.append(f"{len(active_tokens)} active token(s) remain")

    post_retirement_tokens = [item for item in active_tokens if _used_after_retirement(item, agent)]
    if post_retirement_tokens:
        score += 20
        breakdown["post_retirement_token_use"] = 20
        reasons.append("Credential use detected after retirement")

    privileged_tools = [item for item in tool_connections if item.is_active and item.is_privileged]
    privileged_points = min(len(privileged_tools) * 8, 25)
    if privileged_points:
        score += privileged_points
        breakdown["privileged_tool_connections"] = privileged_points
        reasons.append(f"{len(privileged_tools)} active privileged tool connection(s)")

    writable_memory = [item for item in memory_namespaces if item.status == "active" and item.writable]
    if writable_memory:
        memory_points = 15 + min(sum(item.sensitive_records for item in writable_memory) // 10, 10)
        score += memory_points
        breakdown["writable_memory"] = memory_points
        reasons.append("Writable memory namespace remains active")

    active_inbound = [item for item in inbound_invocations if item.is_active]
    inbound_points = min(len(active_inbound) * 8, 20)
    if inbound_points:
        score += inbound_points
        breakdown["active_inbound_invocations"] = inbound_points
        reasons.append(f"{len(active_inbound)} active inbound invocation path(s)")

    post_retirement_invocations = [item for item in active_inbound if _invoked_after_retirement(item, agent)]
    if post_retirement_invocations:
        score += 15
        breakdown["post_retirement_invocation"] = 15
        reasons.append("Agent invocation detected after retirement")

    production_callers = dependencies.get("production_callers", [])
    if production_callers:
        score += 15
        breakdown["production_dependencies"] = 15
        reasons.append(f"{len(production_callers)} production dependency/dependencies still call the agent")

    dangerous_bindings = [item for item in kubernetes_bindings if item.status == "active" and item.is_dangerous]
    if dangerous_bindings:
        score += 20
        breakdown["dangerous_kubernetes_bindings"] = 20
        reasons.append("Dangerous Kubernetes binding remains active")

    if agent and agent.environment == Environment.production:
        before_multiplier = score
        score = int(round(score * 1.25))
        breakdown["production_multiplier"] = round(score - before_multiplier, 2)
        if before_multiplier:
            reasons.append("Production environment multiplier applied")

    score = max(0, min(100, score))
    if not reasons:
        reasons.append("No meaningful residual access detected")

    return RiskAssessment(score=score, level=_level(score), reasons=reasons, score_breakdown=breakdown)
