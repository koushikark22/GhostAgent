from __future__ import annotations

from dataclasses import dataclass

from .models import Environment, RevocationAction


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEngine:
    """Deterministic policy gate for agent offboarding actions.

    This intentionally avoids LLM reasoning. The agent can propose actions, but the
    policy engine decides what is allowed to execute.
    """

    destructive_actions = {
        "revoke_token",
        "disable_tool_connection",
        "disable_inbound_invocation",
        "quarantine_memory_namespace",
        "remove_kubernetes_binding",
        "migrate_dependency",
        "mark_agent_decommissioned",
    }

    denied_actions = {
        "delete_agent_runtime",
        "delete_memory_namespace",
        "delete_audit_logs",
        "permanently_delete_secret",
    }

    def evaluate(self, action: RevocationAction, approved: bool) -> PolicyDecision:
        if action.action_type in self.denied_actions:
            return PolicyDecision(False, "Action is explicitly denied by policy.")

        if action.action_type in self.destructive_actions and not approved:
            return PolicyDecision(False, "Human approval is required before destructive or production-affecting action.")

        if action.environment == Environment.production and not approved:
            return PolicyDecision(False, "Production actions require explicit approval.")

        if action.action_type == "mark_agent_decommissioned" and action.status == "planned":
            return PolicyDecision(False, "Agent cannot be marked decommissioned before approval and revocation execution.")

        return PolicyDecision(True, "Allowed by local offboarding policy.")
