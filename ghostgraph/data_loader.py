from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .models import (
    AgentRecord,
    DependencyEdge,
    InboundInvocation,
    KubernetesBinding,
    MemoryNamespace,
    RetirementRequest,
    TokenRecord,
    ToolConnection,
)


class DataStore:
    """Loads the mock enterprise inventory used by GhostGraph.

    The class intentionally keeps file parsing separate from graph nodes so the node
    logic can later be backed by real systems instead of local JSON/YAML files.
    """

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        if not self.data_dir.exists():
            raise FileNotFoundError(f"Data directory not found: {self.data_dir}")

    def _json(self, filename: str) -> Any:
        path = self.data_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Required data file missing: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _yaml(self, filename: str) -> Any:
        path = self.data_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Required data file missing: {path}")
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    def load_request(self, agent_id: str) -> RetirementRequest:
        requests = self._json("retirement_requests.json")
        for item in requests:
            if item["agent_id"] == agent_id:
                return RetirementRequest(**item)
        return RetirementRequest(agent_id=agent_id, reason="Ad hoc local retirement request")

    def list_agents(self) -> list[AgentRecord]:
        """Return all registered agents from the mock enterprise inventory."""
        return [AgentRecord(**item) for item in self._json("agent_registry.json")]

    def get_agent(self, agent_id: str) -> AgentRecord | None:
        for item in self._json("agent_registry.json"):
            if item["agent_id"] == agent_id:
                return AgentRecord(**item)
        return None

    def get_tool_connections(self, agent_id: str) -> list[ToolConnection]:
        return [ToolConnection(**item) for item in self._json("tool_connections.json") if item["agent_id"] == agent_id]

    def get_tokens(self, agent_id: str) -> list[TokenRecord]:
        return [TokenRecord(**item) for item in self._json("token_inventory.json") if item["agent_id"] == agent_id]

    def get_memory_namespaces(self, agent_id: str) -> list[MemoryNamespace]:
        return [MemoryNamespace(**item) for item in self._json("memory_namespaces.json") if item["agent_id"] == agent_id]

    def get_inbound_invocations(self, agent_id: str) -> list[InboundInvocation]:
        return [InboundInvocation(**item) for item in self._json("inbound_invocations.json") if item["agent_id"] == agent_id]

    def get_dependency_edges(self) -> list[DependencyEdge]:
        return [DependencyEdge(**item) for item in self._json("delegation_graph.json").get("edges", [])]

    def get_kubernetes_bindings(self, agent_id: str) -> list[KubernetesBinding]:
        raw = self._yaml("kubernetes_bindings.yaml") or []
        return [KubernetesBinding(**item) for item in raw if item.get("agent_id") == agent_id]
