from ghostgraph.models import Environment, RevocationAction
from ghostgraph.policy import PolicyEngine


def test_policy_blocks_destructive_action_without_approval():
    action = RevocationAction(
        action_id="ACT-001",
        action_type="revoke_token",
        target="github:token",
        description="Revoke token",
        environment=Environment.production,
        rollback="Issue a new short-lived token",
    )
    decision = PolicyEngine().evaluate(action, approved=False)
    assert not decision.allowed
    assert "approval" in decision.reason.lower()


def test_policy_allows_approved_revocation():
    action = RevocationAction(
        action_id="ACT-001",
        action_type="revoke_token",
        target="github:token",
        description="Revoke token",
        environment=Environment.production,
        rollback="Issue a new short-lived token",
    )
    decision = PolicyEngine().evaluate(action, approved=True)
    assert decision.allowed


def test_policy_denies_permanent_delete_even_with_approval():
    action = RevocationAction(
        action_id="ACT-999",
        action_type="delete_audit_logs",
        target="audit-log-store",
        description="Delete audit logs",
        environment=Environment.production,
        rollback="No rollback",
    )
    decision = PolicyEngine().evaluate(action, approved=True)
    assert not decision.allowed
