from ghostgraph.cli import main


def test_list_agents_command_outputs_inventory(capsys):
    exit_code = main(["list-agents", "--data-dir", "sample_enterprise"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "agent-prod-finance-reconciler" in captured.out
    assert "agent-dev-doc-summarizer" in captured.out
    assert "Risk" in captured.out


def test_list_agents_json(capsys):
    exit_code = main(["list-agents", "--data-dir", "sample_enterprise", "--retired-only", "--json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"agent_id": "agent-prod-finance-reconciler"' in captured.out
    assert '"risk_score": 100' in captured.out
