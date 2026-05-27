from __future__ import annotations

from .types import ScanContext


def resolve_agent(ctx: ScanContext):
    return ctx.store.get_agent(ctx.agent_id)
