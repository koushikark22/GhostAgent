from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _table(rows: list[tuple[str, str]]) -> str:
    if not rows:
        return "_None._\n"
    lines = ["| Field | Value |", "|---|---|"]
    for key, value in rows:
        safe = str(value).replace("\n", "<br>")
        lines.append(f"| {key} | {safe} |")
    return "\n".join(lines) + "\n"


def build_markdown_report(state: dict[str, Any]) -> str:
    request = state.get("request") or {}
    agent = state.get("agent") or {}
    risk = state.get("risk") or {}
    certificate = state.get("certificate") or {}
    findings = state.get("findings") or []
    executed_actions = state.get("executed_actions") or []
    dependencies = state.get("dependencies") or {}

    parts: list[str] = []
    parts.append(f"# GhostGraph Decommission Report: `{request.get('agent_id', 'unknown')}`\n")
    parts.append("## Request\n")
    parts.append(_table([
        ("Agent ID", request.get("agent_id", "")),
        ("Requested by", request.get("requested_by", "")),
        ("Reason", request.get("reason", "")),
        ("Status", request.get("status", "")),
    ]))

    parts.append("## Agent\n")
    parts.append(_table([
        ("Owner", agent.get("owner", "unknown")),
        ("Environment", agent.get("environment", "unknown")),
        ("Registry status", agent.get("status", "unknown")),
        ("Service account", agent.get("service_account", "unknown")),
    ]))

    parts.append("## Residual Risk\n")
    parts.append(_table([
        ("Score", risk.get("score", "unknown")),
        ("Level", risk.get("level", "unknown")),
        ("Reasons", ", ".join(risk.get("reasons", []))),
        ("Breakdown", json.dumps(risk.get("score_breakdown", {}), sort_keys=True)),
    ]))

    parts.append("## Findings\n")
    if findings:
        for item in findings:
            parts.append(f"### {item.get('finding_id')} — {item.get('title')}\n")
            parts.append(_table([
                ("Severity", item.get("severity", "")),
                ("Category", item.get("category", "")),
                ("Description", item.get("description", "")),
                ("Evidence", ", ".join(item.get("evidence", []))),
                ("Recommended action", item.get("recommended_action", "")),
            ]))
    else:
        parts.append("_No findings._\n")

    parts.append("## Dependency Graph Summary\n")
    parts.append(_table([
        ("Called by", ", ".join(item.get("agent_id", "") for item in dependencies.get("called_by", [])) or "None"),
        ("Calls", ", ".join(item.get("agent_id", "") for item in dependencies.get("calls", [])) or "None"),
        ("Blocking production dependencies", str(dependencies.get("has_blocking_dependencies", False))),
    ]))

    parts.append("## Executed Mock Actions\n")
    if executed_actions:
        lines = ["| Action | Target | Status | Policy | Evidence |", "|---|---|---|---|---|"]
        for action in executed_actions:
            lines.append(
                f"| {action.get('action_type')} | {action.get('target')} | {action.get('status')} | "
                f"{action.get('policy_decision')} | {action.get('evidence_file') or ''} |"
            )
        parts.append("\n".join(lines) + "\n")
    else:
        parts.append("_No actions executed._\n")

    parts.append("## Signed Certificate\n")
    parts.append(_table([
        ("Certificate status", certificate.get("status", "unknown")),
        ("Evidence hash", certificate.get("evidence_hash", "")),
        ("Certificate hash", certificate.get("certificate_hash", "")),
        ("Signature algorithm", certificate.get("signature_algorithm", "")),
        ("Signature", certificate.get("signature", "")),
        ("Public key", certificate.get("public_key", "")),
    ]))

    return "\n".join(parts)


def write_report(output_dir: str | Path, state: dict[str, Any]) -> tuple[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    markdown = build_markdown_report(state)
    agent_id = (state.get("request") or {}).get("agent_id", "unknown")
    path = out / f"{agent_id}_decommission_report.md"
    path.write_text(markdown, encoding="utf-8")
    return markdown, str(path)
