from __future__ import annotations

from typing import Any, TypedDict


class GhostGraphState(TypedDict, total=False):
    request: dict[str, Any]
    data_dir: str
    output_dir: str
    agent: dict[str, Any] | None
    tool_connections: list[dict[str, Any]]
    tokens: list[dict[str, Any]]
    memory_namespaces: list[dict[str, Any]]
    inbound_invocations: list[dict[str, Any]]
    dependencies: dict[str, Any]
    kubernetes_bindings: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    risk: dict[str, Any] | None
    plan: list[dict[str, Any]]
    approval: dict[str, Any] | None
    executed_actions: list[dict[str, Any]]
    certificate: dict[str, Any] | None
    report_markdown: str | None
    report_path: str | None
    audit_trace: list[dict[str, Any]]
    errors: list[str]
