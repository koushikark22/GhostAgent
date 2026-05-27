from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .dependency_graph import analyze_dependencies
from .engine import load_request_for_agent, run_pure_python
from .data_loader import DataStore
from .models import AgentStatus
from .risk import calculate_residual_risk


def _langgraph_available() -> bool:
    try:
        import langgraph  # noqa: F401
        return True
    except Exception:
        return False


def _agent_summary(store: DataStore, agent_id: str) -> dict[str, object]:
    agent = store.get_agent(agent_id)
    tool_connections = store.get_tool_connections(agent_id)
    tokens = store.get_tokens(agent_id)
    memory_namespaces = store.get_memory_namespaces(agent_id)
    inbound_invocations = store.get_inbound_invocations(agent_id)
    dependencies = analyze_dependencies(agent_id, store.get_dependency_edges())
    kubernetes_bindings = store.get_kubernetes_bindings(agent_id)
    risk = calculate_residual_risk(
        agent,
        tool_connections,
        tokens,
        memory_namespaces,
        inbound_invocations,
        dependencies,
        kubernetes_bindings,
    )

    return {
        "agent_id": agent_id,
        "owner": agent.owner if agent else "unknown",
        "status": agent.status.value if agent else "missing",
        "environment": agent.environment.value if agent else "unknown",
        "active_tokens": sum(1 for item in tokens if item.is_active),
        "privileged_tools": sum(1 for item in tool_connections if item.is_active and item.is_privileged),
        "active_inbound": sum(1 for item in inbound_invocations if item.is_active),
        "writable_memory": sum(1 for item in memory_namespaces if item.status == "active" and item.writable),
        "dangerous_kubernetes_bindings": sum(
            1 for item in kubernetes_bindings if item.status == "active" and item.is_dangerous
        ),
        "blocking_dependencies": len(dependencies.get("production_callers", [])),
        "risk_score": risk.score,
        "risk_level": risk.level.value,
    }


def _print_table(rows: list[dict[str, object]]) -> None:
    if not rows:
        print("No agents found.")
        return

    columns = [
        ("agent_id", "Agent ID"),
        ("status", "Status"),
        ("environment", "Env"),
        ("active_tokens", "Tok"),
        ("privileged_tools", "Tools"),
        ("active_inbound", "In"),
        ("writable_memory", "Mem"),
        ("dangerous_kubernetes_bindings", "K8s"),
        ("blocking_dependencies", "Deps"),
        ("risk_score", "Risk"),
        ("risk_level", "Level"),
    ]
    widths = {
        key: max(len(title), *(len(str(row[key])) for row in rows))
        for key, title in columns
    }
    header = "  ".join(title.ljust(widths[key]) for key, title in columns)
    divider = "  ".join("-" * widths[key] for key, _ in columns)
    print(header)
    print(divider)
    for row in rows:
        print("  ".join(str(row[key]).ljust(widths[key]) for key, _ in columns))


def list_agents_command(args: argparse.Namespace) -> int:
    store = DataStore(args.data_dir)
    agents = store.list_agents()
    if args.retired_only:
        agents = [agent for agent in agents if agent.status in {AgentStatus.retiring, AgentStatus.retired, AgentStatus.decommissioned}]

    rows = [_agent_summary(store, agent.agent_id) for agent in agents]
    rows.sort(key=lambda row: (-int(row["risk_score"]), str(row["agent_id"])))

    if args.json:
        print(json.dumps(rows, indent=2, default=str))
    else:
        _print_table(rows)
    return 0


def run_command(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)
    request = load_request_for_agent(args.agent_id, data_dir)

    use_langgraph = args.use_langgraph
    if use_langgraph and not _langgraph_available():
        print("LangGraph is not installed in this environment. Install requirements.txt or run with --no-use-langgraph.", file=sys.stderr)
        return 2

    if use_langgraph:
        from .graph import run_langgraph
        state = run_langgraph(request, data_dir=data_dir, output_dir=output_dir, auto_approve=args.auto_approve)
        if "__interrupt__" in state:
            print(json.dumps(state["__interrupt__"], indent=2, default=str))
            print("Graph paused for approval. Re-run with --auto-approve for the local demo.")
            return 0
    else:
        state = run_pure_python(request, data_dir=data_dir, output_dir=output_dir, auto_approve=args.auto_approve)

    summary = {
        "agent_id": args.agent_id,
        "risk": state.get("risk"),
        "certificate": state.get("certificate"),
        "report_path": state.get("report_path"),
        "planned_actions": len(state.get("plan") or []),
        "executed_actions": len(state.get("executed_actions") or []),
        "errors": state.get("errors") or [],
    }
    print(json.dumps(summary, indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GhostGraph agent offboarding runner")
    sub = parser.add_subparsers(dest="command", required=True)

    list_agents = sub.add_parser("list-agents", help="List agents and residual-access risk summary")
    list_agents.add_argument("--data-dir", default="sample_enterprise")
    list_agents.add_argument("--retired-only", action="store_true", help="Only show retiring, retired, or decommissioned agents")
    list_agents.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    list_agents.set_defaults(func=list_agents_command)

    run = sub.add_parser("run", help="Run an agent offboarding workflow")
    run.add_argument("--agent-id", required=True)
    run.add_argument("--data-dir", default="sample_enterprise")
    run.add_argument("--output-dir", default="outputs")
    run.add_argument("--auto-approve", action="store_true", help="Approve the local demo plan automatically")
    group = run.add_mutually_exclusive_group()
    group.add_argument("--use-langgraph", dest="use_langgraph", action="store_true", default=True)
    group.add_argument("--no-use-langgraph", dest="use_langgraph", action="store_false")
    run.set_defaults(func=run_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
