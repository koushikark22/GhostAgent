#!/usr/bin/env bash
set -euo pipefail
python -m ghostgraph.cli run --agent-id agent-prod-finance-reconciler --data-dir sample_enterprise --output-dir outputs --auto-approve --no-use-langgraph
python -m ghostgraph.cli run --agent-id agent-dev-doc-summarizer --data-dir sample_enterprise --output-dir outputs --auto-approve --no-use-langgraph
