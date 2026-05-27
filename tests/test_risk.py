from ghostgraph.data_loader import DataStore
from ghostgraph.dependency_graph import analyze_dependencies
from ghostgraph.risk import build_findings, calculate_residual_risk


def test_high_risk_agent_scores_critical():
    store = DataStore("sample_enterprise")
    agent_id = "agent-prod-finance-reconciler"
    agent = store.get_agent(agent_id)
    deps = analyze_dependencies(agent_id, store.get_dependency_edges())
    risk = calculate_residual_risk(
        agent,
        store.get_tool_connections(agent_id),
        store.get_tokens(agent_id),
        store.get_memory_namespaces(agent_id),
        store.get_inbound_invocations(agent_id),
        deps,
        store.get_kubernetes_bindings(agent_id),
    )
    assert risk.score == 100
    assert risk.level == "critical"


def test_clean_agent_scores_low():
    store = DataStore("sample_enterprise")
    agent_id = "agent-dev-doc-summarizer"
    agent = store.get_agent(agent_id)
    deps = analyze_dependencies(agent_id, store.get_dependency_edges())
    risk = calculate_residual_risk(
        agent,
        store.get_tool_connections(agent_id),
        store.get_tokens(agent_id),
        store.get_memory_namespaces(agent_id),
        store.get_inbound_invocations(agent_id),
        deps,
        store.get_kubernetes_bindings(agent_id),
    )
    assert risk.score == 0
    assert risk.level == "low"


def test_findings_include_resurrection_signal():
    store = DataStore("sample_enterprise")
    agent_id = "agent-prod-finance-reconciler"
    agent = store.get_agent(agent_id)
    deps = analyze_dependencies(agent_id, store.get_dependency_edges())
    findings = build_findings(
        agent,
        store.get_tool_connections(agent_id),
        store.get_tokens(agent_id),
        store.get_memory_namespaces(agent_id),
        store.get_inbound_invocations(agent_id),
        deps,
        store.get_kubernetes_bindings(agent_id),
    )
    ids = {finding.finding_id for finding in findings}
    assert "GG-RESURRECTION-001" in ids
    assert "GG-K8S-001" in ids
