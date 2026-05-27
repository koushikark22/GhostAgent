from __future__ import annotations

import base64
import json
from datetime import timezone
from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import DecommissionCertificate, RiskAssessment


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sha256_hex(data: Any) -> str:
    return "sha256:" + sha256(canonical_json(data)).hexdigest()


def issue_certificate(
    agent_id: str,
    risk: RiskAssessment | None,
    findings: list[dict[str, Any]],
    executed_actions: list[dict[str, Any]],
) -> DecommissionCertificate:
    blocked_actions = [action for action in executed_actions if action.get("status") == "blocked"]
    critical_findings = [finding for finding in findings if finding.get("severity") == "critical"]
    incomplete_actions = [
        action
        for action in executed_actions
        if action.get("status") not in {"executed_mock", "skipped"}
    ]

    if blocked_actions or incomplete_actions:
        status = "blocked"
    elif critical_findings and risk and risk.score >= 80:
        status = "requires_review"
    else:
        status = "complete"

    evidence_payload = {
        "agent_id": agent_id,
        "risk": risk.model_dump(mode="json") if risk else None,
        "findings": findings,
        "executed_actions": executed_actions,
    }
    evidence_hash = sha256_hex(evidence_payload)

    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(evidence_hash.encode("utf-8"))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    summary = {
        "risk_score": risk.score if risk else None,
        "risk_level": risk.level.value if risk else None,
        "finding_count": len(findings),
        "critical_finding_count": len(critical_findings),
        "action_count": len(executed_actions),
        "blocked_action_count": len(blocked_actions),
    }

    certificate_body = {
        "agent_id": agent_id,
        "status": status,
        "evidence_hash": evidence_hash,
        "summary": summary,
    }
    certificate_hash = sha256_hex(certificate_body)

    return DecommissionCertificate(
        agent_id=agent_id,
        status=status,
        evidence_hash=evidence_hash,
        certificate_hash=certificate_hash,
        signature_algorithm="Ed25519",
        signature=base64.b64encode(signature).decode("ascii"),
        public_key=base64.b64encode(public_key).decode("ascii"),
        summary=summary,
    )
