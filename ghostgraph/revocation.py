from __future__ import annotations

import json
from pathlib import Path

from .models import ApprovalDecision, RevocationAction
from .policy import PolicyEngine


class MockRevocationExecutor:
    """Writes evidence files instead of changing real systems."""

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.actions_dir = self.output_dir / "actions"
        self.actions_dir.mkdir(parents=True, exist_ok=True)
        self.policy = PolicyEngine()

    def execute(self, plan: list[RevocationAction], approval: ApprovalDecision | None) -> list[RevocationAction]:
        approved = bool(approval and approval.approved)
        executed: list[RevocationAction] = []

        for action in plan:
            decision = self.policy.evaluate(action, approved=approved)
            data = action.model_dump(mode="json")
            data["policy_decision"] = "allowed" if decision.allowed else "blocked"
            data["policy_reason"] = decision.reason

            if not decision.allowed:
                data["status"] = "blocked"
                executed.append(RevocationAction(**data))
                continue

            if action.status == "rejected":
                data["status"] = "skipped"
                data["policy_reason"] = "Human rejected the decommission plan."
                executed.append(RevocationAction(**data))
                continue

            evidence = {
                "action_id": action.action_id,
                "action_type": action.action_type,
                "target": action.target,
                "mode": "mock",
                "result": "executed_mock",
                "description": action.description,
                "rollback": action.rollback,
                "policy_decision": data["policy_decision"],
                "policy_reason": data["policy_reason"],
            }
            evidence_path = self.actions_dir / f"{action.action_id.lower()}_{action.action_type}.json"
            evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")

            data["status"] = "executed_mock"
            data["evidence_file"] = str(evidence_path)
            executed.append(RevocationAction(**data))

        return executed
