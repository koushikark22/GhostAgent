from __future__ import annotations

from .types import ScanContext


def scan_tool_connections(ctx: ScanContext):
    return ctx.store.get_tool_connections(ctx.agent_id)
