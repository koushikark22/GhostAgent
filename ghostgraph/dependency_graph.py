from __future__ import annotations

from typing import Any

try:
    import networkx as nx
except Exception:  # pragma: no cover - networkx is in requirements, but fallback keeps core resilient.
    nx = None

from .models import DependencyEdge, Environment


def analyze_dependencies(agent_id: str, edges: list[DependencyEdge]) -> dict[str, Any]:
    active_edges = [edge for edge in edges if edge.status == "active"]

    if nx is not None:
        graph = nx.DiGraph()
        for edge in active_edges:
            graph.add_edge(
                edge.source_agent_id,
                edge.target_agent_id,
                relation=edge.relation,
                environment=edge.environment.value,
            )
        called_by = [
            {"agent_id": source, **data}
            for source, _, data in graph.in_edges(agent_id, data=True)
        ]
        calls = [
            {"agent_id": target, **data}
            for _, target, data in graph.out_edges(agent_id, data=True)
        ]
    else:
        called_by = [
            {
                "agent_id": edge.source_agent_id,
                "relation": edge.relation,
                "environment": edge.environment.value,
            }
            for edge in active_edges
            if edge.target_agent_id == agent_id
        ]
        calls = [
            {
                "agent_id": edge.target_agent_id,
                "relation": edge.relation,
                "environment": edge.environment.value,
            }
            for edge in active_edges
            if edge.source_agent_id == agent_id
        ]

    production_callers = [item for item in called_by if item.get("environment") == Environment.production.value]
    return {
        "called_by": called_by,
        "calls": calls,
        "production_callers": production_callers,
        "has_blocking_dependencies": bool(production_callers),
    }
