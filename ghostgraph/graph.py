from __future__ import annotations

from pathlib import Path
from typing import Any

from .engine import initial_state
from .models import ApprovalDecision, RetirementRequest, RevocationAction
from .nodes import (
    certificate_node,
    connector_inventory_node,
    decommission_planner_node,
    delegation_analyzer_node,
    identity_resolver_node,
    inbound_scanner_node,
    kubernetes_inspector_node,
    memory_inspector_node,
    report_node,
    revocation_executor_node,
    risk_scorer_node,
    token_scanner_node,
)
from .planner import apply_approval
from .state import GhostGraphState


def _approval_payload(state: dict[str, Any]) -> dict[str, Any]:
    risk = state.get("risk") or {}
    return {
        "message": "Review GhostGraph decommission plan before executing mock revocation actions.",
        "agent_id": (state.get("request") or {}).get("agent_id"),
        "risk_score": risk.get("score"),
        "risk_level": risk.get("level"),
        "finding_count": len(state.get("findings") or []),
        "planned_actions": state.get("plan") or [],
        "expected_response": {"approved": True, "approver": "name", "reason": "approval reason"},
    }


def langgraph_approval_node(state: GhostGraphState) -> dict[str, Any]:
    from langgraph.types import interrupt

    if state.get("approval") is not None:
        return {}

    response = interrupt(_approval_payload(state))
    if isinstance(response, dict):
        approved = bool(response.get("approved"))
        approver = str(response.get("approver") or "langgraph-user")
        reason = str(response.get("reason") or "No reason provided")
    else:
        normalized = str(response).strip().lower()
        approved = normalized in {"approve", "approved", "yes", "y", "true"}
        approver = "langgraph-user"
        reason = f"Resume response was {response!r}"

    decision = ApprovalDecision(approved=approved, approver=approver, reason=reason)
    plan = apply_approval([RevocationAction(**item) for item in state.get("plan", [])], decision)
    return {
        "approval": decision.model_dump(mode="json"),
        "plan": [item.model_dump(mode="json") for item in plan],
    }


def build_graph():
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import END, START, StateGraph

    builder = StateGraph(GhostGraphState)
    builder.add_node("identity_resolver", identity_resolver_node)
    builder.add_node("connector_inventory", connector_inventory_node)
    builder.add_node("token_scanner", token_scanner_node)
    builder.add_node("memory_inspector", memory_inspector_node)
    builder.add_node("inbound_scanner", inbound_scanner_node)
    builder.add_node("delegation_analyzer", delegation_analyzer_node)
    builder.add_node("kubernetes_inspector", kubernetes_inspector_node)
    builder.add_node("risk_scorer", risk_scorer_node)
    builder.add_node("decommission_planner", decommission_planner_node)
    builder.add_node("approval_gate", langgraph_approval_node)
    builder.add_node("revocation_executor", revocation_executor_node)
    builder.add_node("certificate", certificate_node)
    builder.add_node("report", report_node)

    builder.add_edge(START, "identity_resolver")
    builder.add_edge("identity_resolver", "connector_inventory")
    builder.add_edge("connector_inventory", "token_scanner")
    builder.add_edge("token_scanner", "memory_inspector")
    builder.add_edge("memory_inspector", "inbound_scanner")
    builder.add_edge("inbound_scanner", "delegation_analyzer")
    builder.add_edge("delegation_analyzer", "kubernetes_inspector")
    builder.add_edge("kubernetes_inspector", "risk_scorer")
    builder.add_edge("risk_scorer", "decommission_planner")
    builder.add_edge("decommission_planner", "approval_gate")
    builder.add_edge("approval_gate", "revocation_executor")
    builder.add_edge("revocation_executor", "certificate")
    builder.add_edge("certificate", "report")
    builder.add_edge("report", END)

    return builder.compile(checkpointer=InMemorySaver())


def run_langgraph(
    request: RetirementRequest,
    data_dir: str | Path,
    output_dir: str | Path = "outputs",
    auto_approve: bool = False,
) -> dict[str, Any]:
    from langgraph.types import Command

    graph = build_graph()
    config = {"configurable": {"thread_id": f"ghostgraph-{request.agent_id}"}}
    state = initial_state(request, data_dir, output_dir)
    first = graph.invoke(state, config=config)

    if "__interrupt__" in first:
        if not auto_approve:
            return first
        resume_payload = {
            "approved": True,
            "approver": "auto-approver",
            "reason": "Auto-approved local LangGraph demo run",
        }
        return graph.invoke(Command(resume=resume_payload), config=config)

    return first
