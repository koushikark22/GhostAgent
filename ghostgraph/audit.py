from __future__ import annotations

from typing import Any

from .models import AuditEvent


def append_audit(state: dict[str, Any], step: str, message: str, **details: Any) -> list[dict[str, Any]]:
    trace = list(state.get("audit_trace") or [])
    trace.append(AuditEvent(step=step, message=message, details=details).model_dump(mode="json"))
    return trace


def append_error(state: dict[str, Any], message: str) -> list[str]:
    errors = list(state.get("errors") or [])
    errors.append(message)
    return errors
