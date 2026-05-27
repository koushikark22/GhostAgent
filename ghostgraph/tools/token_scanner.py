from __future__ import annotations

from .types import ScanContext


def scan_tokens(ctx: ScanContext):
    return ctx.store.get_tokens(ctx.agent_id)
