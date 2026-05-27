from __future__ import annotations

from .types import ScanContext


def scan_kubernetes_bindings(ctx: ScanContext):
    return ctx.store.get_kubernetes_bindings(ctx.agent_id)
