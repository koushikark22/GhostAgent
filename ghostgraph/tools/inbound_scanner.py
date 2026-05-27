from __future__ import annotations

from .types import ScanContext


def scan_inbound_invocations(ctx: ScanContext):
    return ctx.store.get_inbound_invocations(ctx.agent_id)
