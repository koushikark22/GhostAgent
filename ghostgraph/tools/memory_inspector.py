from __future__ import annotations

from .types import ScanContext


def inspect_memory_namespaces(ctx: ScanContext):
    return ctx.store.get_memory_namespaces(ctx.agent_id)
