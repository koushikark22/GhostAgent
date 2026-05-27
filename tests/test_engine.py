from pathlib import Path

from ghostgraph.engine import load_request_for_agent, run_pure_python


def test_engine_runs_and_writes_report(tmp_path: Path):
    request = load_request_for_agent("agent-prod-finance-reconciler", "sample_enterprise")
    state = run_pure_python(request, "sample_enterprise", tmp_path, auto_approve=True)
    assert state["risk"]["score"] == 100
    assert state["certificate"]["evidence_hash"].startswith("sha256:")
    assert Path(state["report_path"]).exists()
    assert state["executed_actions"]
    assert all(action["status"] == "executed_mock" for action in state["executed_actions"])


def test_engine_without_approval_blocks_actions(tmp_path: Path):
    request = load_request_for_agent("agent-prod-finance-reconciler", "sample_enterprise")
    state = run_pure_python(request, "sample_enterprise", tmp_path, auto_approve=False)
    assert state["executed_actions"]
    assert any(action["status"] == "blocked" for action in state["executed_actions"])
    assert state["certificate"]["status"] == "blocked"
