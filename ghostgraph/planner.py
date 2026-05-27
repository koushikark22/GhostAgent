from __future__ import annotations

from itertools import count

from .models import (
    AgentRecord,
    ApprovalDecision,
    Environment,
    InboundInvocation,
    KubernetesBinding,
    MemoryNamespace,
    RevocationAction,
    TokenRecord,
    ToolConnection,
)


def _action_id(counter: count[int]) -> str:
    return f"ACT-{next(counter):03d}"


def build_decommission_plan(
    agent: AgentRecord | None,
    tool_connections: list[ToolConnection],
    tokens: list[TokenRecord],
    memory_namespaces: list[MemoryNamespace],
    inbound_invocations: list[InboundInvocation],
    dependencies: dict,
    kubernetes_bindings: list[KubernetesBinding],
) -> list[RevocationAction]:
    actions: list[RevocationAction] = []
    seq = count(1)
    environment = agent.environment if agent else Environment.production

    for invocation in inbound_invocations:
        if invocation.is_active:
            actions.append(
                RevocationAction(
                    action_id=_action_id(seq),
                    action_type="disable_inbound_invocation",
                    target=f"{invocation.source_type}:{invocation.source_id}",
                    description=f"Disable inbound {invocation.source_type} trigger {invocation.source_id}.",
                    environment=invocation.environment,
                    rollback=f"Re-enable {invocation.source_type} trigger {invocation.source_id} for a time-boxed recovery window.",
                )
            )

    for token in tokens:
        if token.is_active:
            actions.append(
                RevocationAction(
                    action_id=_action_id(seq),
                    action_type="revoke_token",
                    target=f"{token.provider}:{token.token_id}",
                    description=f"Revoke active {token.provider} token {token.token_id}.",
                    environment=environment,
                    rollback="Issue a new least-privilege token with a short expiration after approval.",
                )
            )

    for connection in tool_connections:
        if connection.is_active and connection.is_privileged:
            actions.append(
                RevocationAction(
                    action_id=_action_id(seq),
                    action_type="disable_tool_connection",
                    target=f"{connection.tool}:{connection.connection_id}",
                    description=f"Disable or downgrade privileged {connection.tool} connection {connection.connection_id}.",
                    environment=connection.environment,
                    rollback="Restore read-only access only if a named owner approves the recovery.",
                )
            )

    for memory in memory_namespaces:
        if memory.status == "active" and memory.writable:
            actions.append(
                RevocationAction(
                    action_id=_action_id(seq),
                    action_type="quarantine_memory_namespace",
                    target=memory.namespace,
                    description=f"Move memory namespace {memory.namespace} to read-only quarantine.",
                    environment=environment,
                    rollback="Return namespace to read-only production memory only after data owner approval.",
                )
            )

    for binding in kubernetes_bindings:
        if binding.status == "active" and binding.is_dangerous:
            actions.append(
                RevocationAction(
                    action_id=_action_id(seq),
                    action_type="remove_kubernetes_binding",
                    target=f"{binding.namespace}/{binding.binding_name}",
                    description=f"Remove dangerous Kubernetes binding {binding.binding_name} for service account {binding.service_account}.",
                    environment=environment,
                    rollback="Apply a least-privilege namespace RoleBinding after review.",
                )
            )

    for caller in dependencies.get("production_callers", []):
        actions.append(
            RevocationAction(
                action_id=_action_id(seq),
                action_type="migrate_dependency",
                target=caller["agent_id"],
                description=f"Migrate production dependency from {caller['agent_id']} before final decommission.",
                environment=Environment.production,
                rollback="Restore dependency edge only if upstream owner approves rollback.",
            )
        )

    if agent is not None:
        actions.append(
            RevocationAction(
                action_id=_action_id(seq),
                action_type="mark_agent_decommissioned",
                target=agent.agent_id,
                description="Mark agent as fully decommissioned after residual access checks pass.",
                environment=agent.environment,
                rollback="Move agent back to retiring status; do not restore credentials automatically.",
            )
        )

    return actions


def apply_approval(plan: list[RevocationAction], approval: ApprovalDecision | None) -> list[RevocationAction]:
    if approval is None:
        return plan
    updated: list[RevocationAction] = []
    for action in plan:
        data = action.model_dump()
        if approval.approved:
            data["status"] = "approved"
        else:
            data["status"] = "rejected"
        updated.append(RevocationAction(**data))
    return updated
