import importlib.util

import pytest


@pytest.mark.skipif(importlib.util.find_spec("langgraph") is None, reason="LangGraph is not installed")
def test_langgraph_builds():
    from ghostgraph.graph import build_graph

    graph = build_graph()
    assert graph is not None
