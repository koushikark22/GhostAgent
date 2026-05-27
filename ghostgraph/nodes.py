from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit import append_audit, append_error
from .certificate import issue_certificate
from .data_loader import DataStore
from .dependency_graph import analyze_dependencies
from .models import (
    AgentRecord,
    ApprovalDecision,
    InboundInvocation,
    KubernetesBinding,
    MemoryNamespace,
    RetirementRequest,
    RiskAssessment,
    TokenRecord,
    ToolConnection,
)
from .planner import apply_approval, build_decommission_plan
from .report import write_report
from .revocation import MockRevocationExecutor
from .risk import build_findings, calculate_residual_risk
from .tools.connector_inventory import scan_tool_connections
from .tools.identity import resolve_agent
from .tools.inbound_scanner import scan_inbound_invocations
from .tools.kubernetes_inspector import scan_kubernetes_bindings
from .tools.memory_inspector import inspect_memory_namespaces
from .tools.token_scanner import scan_tokens
from .tools.types import ScanContext


def _store(state: dict[str, Any]) -> DataStore:
    return DataStore(state["data_dir"])


def _request(state: dict[str, Any]) -> RetirementRequest:
    return RetirementRequest(**state["request"])


def _ctx(state: dict[str, Any]) -> ScanContext:
    request = _request(state)
    return ScanContext(agent_id=request.agent_id, store=_store(state))


def identity_resolver_node(state: dict[str, Any]) -> dict[str, Any]:
    ctx = _ctx(state)
    agent = resolve_agent(ctx)
    update: dict[str, Any] = {
        "agent": agent.model_dump(mode="json") if agent else None,
        "audit_trace": append_audit(
            state,
            "identity_resolver",
            "Resolved agent identity" if agent else "Agent identity not found",
            agent_id=ctx.agent_id,
        ),
    }
    if agent is None:
        update["errors"] = append_error(state, f"Agent {ctx.agent_id} was not found in registry")
    return update


def connector_inventory_node(state: dict[str, Any]) -> dict[str, Any]:
    ctx = _ctx(state)
    connections = scan_tool_connections(ctx)
    return {
        "tool_connections": [item.model_dump(mode="json") for item in connections],
        "audit_trace": append_audit(state, "connector_inventory", "Scanned tool connections", count=len(connections)),
    }


def token_scanner_node(state: dict[str, Any]) -> dict[str, Any]:
    ctx = _ctx(state)
    tokens = scan_tokens(ctx)
    active = [item for item in tokens if item.is_active]
    return {
        "tokens": [item.model_dump(mode="json") for item in tokens],
        "audit_trace": append_audit(state, "token_scanner", "Scanned tokens", total=len(tokens), active=len(active)),
    }


def memory_inspector_node(state: dict[str, Any]) -> dict[str, Any]:
    ctx = _ctx(state)
    namespaces = inspect_memory_namespaces(ctx)
    return {
        "memory_namespaces": [item.model_dump(mode="json") for item in namespaces],
        "audit_trace": append_audit(state, "memory_inspector", "Inspected memory namespaces", count=len(namespaces)),
    }


def inbound_scanner_node(state: dict[str, Any]) -> dict[str, Any]:
    ctx = _ctx(state)
    invocations = scan_inbound_invocations(ctx)
    active = [item for item in invocations if item.is_active]
    return {
        "inbound_invocations": [item.model_dump(mode="json") for item in invocations],
        "audit_trace": append_audit(state, "inbound_scanner", "Scanned inbound invocation paths", total=len(invocations), active=len(active)),
    }


def delegation_analyzer_node(state: dict[str, Any]) -> dict[str, Any]:
    ctx = _ctx(state)
    edges = ctx.store.get_dependency_edges()
    dependencies = analyze_dependencies(ctx.agent_id, edges)
    return {
        "dependencies": dependencies,
        "audit_trace": append_audit(
            state,
            "delegation_analyzer",
            "Analyzed agent dependency graph",
            called_by=len(dependencies.get("called_by", [])),
            calls=len(dependencies.get("calls", [])),
        ),
    }


def kubernetes_inspector_node(state: dict[str, Any]) -> dict[str, Any]:
    ctx = _ctx(state)
    bindings = scan_kubernetes_bindings(ctx)
    dangerous = [item for item in bindings if item.is_dangerous]
    return {
        "kubernetes_bindings": [item.model_dump(mode="json") for item in bindings],
        "audit_trace": append_audit(state, "kubernetes_inspector", "Inspected Kubernetes bindings", total=len(bindings), dangerous=len(dangerous)),
    }


def _typed_agent(state: dict[str, Any]) -> AgentRecord | None:
    return AgentRecord(**state["agent"]) if state.get("agent") else None


def _typed_connections(state: dict[str, Any]) -> list[ToolConnection]:
    return [ToolConnection(**item) for item in state.get("tool_connections", [])]


def _typed_tokens(state: dict[str, Any]) -> list[TokenRecord]:
    return [TokenRecord(**item) for item in state.get("tokens", [])]


def _typed_memory(state: dict[str, Any]) -> list[MemoryNamespace]:
    return [MemoryNamespace(**item) for item in state.get("memory_namespaces", [])]


def _typed_inbound(state: dict[str, Any]) -> list[InboundInvocation]:
    return [InboundInvocation(**item) for item in state.get("inbound_invocations", [])]


def _typed_bindings(state: dict[str, Any]) -> list[KubernetesBinding]:
    return [KubernetesBinding(**item) for item in state.get("kubernetes_bindings", [])]


def risk_scorer_node(state: dict[str, Any]) -> dict[str, Any]:
    agent = _typed_agent(state)
    connections = _typed_connections(state)
    tokens = _typed_tokens(state)
    memory = _typed_memory(state)
    inbound = _typed_inbound(state)
    dependencies = state.get("dependencies") or {}
    bindings = _typed_bindings(state)

    findings = build_findings(agent, connections, tokens, memory, inbound, dependencies, bindings)
    risk = calculate_residual_risk(agent, connections, tokens, memory, inbound, dependencies, bindings)
    return {
        "findings": [item.model_dump(mode="json") for item in findings],
        "risk": risk.model_dump(mode="json"),
        "audit_trace": append_audit(state, "risk_scorer", "Calculated residual risk", score=risk.score, level=risk.level.value),
    }


def decommission_planner_node(state: dict[str, Any]) -> dict[str, Any]:
    plan = build_decommission_plan(
        _typed_agent(state),
        _typed_connections(state),
        _typed_tokens(state),
        _typed_memory(state),
        _typed_inbound(state),
        state.get("dependencies") or {},
        _typed_bindings(state),
    )
    return {
        "plan": [item.model_dump(mode="json") for item in plan],
        "audit_trace": append_audit(state, "decommission_planner", "Built staged decommission plan", action_count=len(plan)),
    }


def static_approval_node(state: dict[str, Any], approved: bool, approver: str = "local-user", reason: str | None = None) -> dict[str, Any]:
    decision = ApprovalDecision(
        approved=approved,
        approver=approver,
        reason=reason or ("Auto-approved local demo run" if approved else "Rejected local demo run"),
    )
    plan = apply_approval(
        [__import__("ghostgraph.models", fromlist=["RevocationAction"]).RevocationAction(**item) for item in state.get("plan", [])],
        decision,
    )
    return {
        "approval": decision.model_dump(mode="json"),
        "plan": [item.model_dump(mode="json") for item in plan],
        "audit_trace": append_audit(state, "approval_gate", "Approval decision recorded", approved=approved, approver=approver),
    }


def revocation_executor_node(state: dict[str, Any]) -> dict[str, Any]:
    from .models import RevocationAction

    output_dir = Path(state.get("output_dir") or "outputs")
    plan = [RevocationAction(**item) for item in state.get("plan", [])]
    approval = ApprovalDecision(**state["approval"]) if state.get("approval") else None
    executor = MockRevocationExecutor(output_dir)
    executed = executor.execute(plan, approval)
    return {
        "executed_actions": [item.model_dump(mode="json") for item in executed],
        "audit_trace": append_audit(state, "revocation_executor", "Executed mock revocation plan", action_count=len(executed)),
    }


def certificate_node(state: dict[str, Any]) -> dict[str, Any]:
    risk = RiskAssessment(**state["risk"]) if state.get("risk") else None
    certificate = issue_certificate(
        agent_id=(state.get("request") or {}).get("agent_id", "unknown"),
        risk=risk,
        findings=state.get("findings", []),
        executed_actions=state.get("executed_actions", []),
    )
    return {
        "certificate": certificate.model_dump(mode="json"),
        "audit_trace": append_audit(state, "certificate", "Issued signed decommission certificate", status=certificate.status),
    }


def report_node(state: dict[str, Any]) -> dict[str, Any]:
    markdown, path = write_report(state.get("output_dir") or "outputs", state)
    return {
        "report_markdown": markdown,
        "report_path": path,
        "audit_trace": append_audit(state, "report", "Wrote markdown decommission report", path=path),
    }
