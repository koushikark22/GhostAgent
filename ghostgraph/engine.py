from __future__ import annotations

from pathlib import Path
from typing import Any

from .data_loader import DataStore
from .models import RetirementRequest
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
    static_approval_node,
    token_scanner_node,
)


def initial_state(request: RetirementRequest, data_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    return {
        "request": request.model_dump(mode="json"),
        "data_dir": str(data_dir),
        "output_dir": str(output_dir),
        "agent": None,
        "tool_connections": [],
        "tokens": [],
        "memory_namespaces": [],
        "inbound_invocations": [],
        "dependencies": {},
        "kubernetes_bindings": [],
        "findings": [],
        "risk": None,
        "plan": [],
        "approval": None,
        "executed_actions": [],
        "certificate": None,
        "report_markdown": None,
        "report_path": None,
        "audit_trace": [],
        "errors": [],
    }


def run_pure_python(
    request: RetirementRequest,
    data_dir: str | Path,
    output_dir: str | Path = "outputs",
    auto_approve: bool = False,
) -> dict[str, Any]:
    """Deterministic runner used by tests and by environments without LangGraph.

    The LangGraph runner uses the same node functions, so logic stays consistent.
    """
    state = initial_state(request, data_dir, output_dir)
    for node in [
        identity_resolver_node,
        connector_inventory_node,
        token_scanner_node,
        memory_inspector_node,
        inbound_scanner_node,
        delegation_analyzer_node,
        kubernetes_inspector_node,
        risk_scorer_node,
        decommission_planner_node,
    ]:
        state.update(node(state))

    state.update(static_approval_node(state, approved=auto_approve, reason="Auto-approved by pure-Python runner" if auto_approve else "No approval supplied"))
    state.update(revocation_executor_node(state))
    state.update(certificate_node(state))
    state.update(report_node(state))
    return state


def load_request_for_agent(agent_id: str, data_dir: str | Path) -> RetirementRequest:
    return DataStore(data_dir).load_request(agent_id)
