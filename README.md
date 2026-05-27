# GhostGraph: Agent Offboarding and Residual Access Hunter

GhostGraph is a LangGraph-based security project for safely retiring artificial intelligence agents and proving they no longer have residual access.

Most agent projects focus on onboarding and runtime execution. GhostGraph focuses on the overlooked end-of-life phase:

> When an enterprise agent is retired, are its tokens, tool permissions, webhooks, queue triggers, memory namespaces, service accounts, and downstream dependencies actually gone?

This project is intentionally local-first and mock-driven so you can demo it without real production credentials. Later, each mock scanner can be replaced with a real GitHub, Slack, Jira, Kubernetes, scheduler, queue, or vector database connector.

---

## Core capabilities

- LangGraph workflow with stateful nodes and a human approval gate
- Agent registry resolution
- Tool and connector inventory
- Token last-use analysis
- Inbound invocation scanner
- Memory namespace quarantine detection
- Agent dependency graph analysis
- Kubernetes role binding inspection
- Residual risk score from 0 to 100
- Staged revocation plan generation
- Policy enforcement before revocation
- Mock revocation executor that writes evidence artifacts
- Signed decommission certificate using Ed25519
- Markdown report generation
- Command-line interface
- Optional FastAPI service
- Pytest test suite

---

## Architecture

```text
Retirement Request
      ↓
Agent Identity Resolver
      ↓
Tool Connector Inventory
      ↓
Token and Secret Scanner
      ↓
Memory Store Inspector
      ↓
Inbound Invocation Scanner
      ↓
Delegation Graph Analyzer
      ↓
Kubernetes Binding Inspector
      ↓
Residual Risk Scorer
      ↓
Decommission Plan Generator
      ↓
Human Approval Gate
      ↓
Revocation Executor
      ↓
Forensic Report + Signed Certificate
```

LangGraph is used for the production-style workflow. The project also includes a deterministic pure-Python runner so tests and demos can still run in environments where LangGraph is not installed.

---

## Installation

```bash
cd ghostgraph-agent-offboarding
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

For a minimal test-only install, the project can run most unit tests without LangGraph. For the full project, install all requirements.

---

## Run the demo

### List registered agents and risk summary

```bash
python -m ghostgraph.cli list-agents --data-dir sample_enterprise
```

For JSON output:

```bash
python -m ghostgraph.cli list-agents --data-dir sample_enterprise --json
```

### High-risk retired production agent

```bash
python -m ghostgraph.cli run \
  --agent-id agent-prod-finance-reconciler \
  --data-dir sample_enterprise \
  --output-dir outputs \
  --auto-approve
```

Expected result: high or critical residual risk, active tokens, active inbound triggers, writable memory, Kubernetes role binding, and production dependencies.

### Clean retired development agent

```bash
python -m ghostgraph.cli run \
  --agent-id agent-dev-doc-summarizer \
  --data-dir sample_enterprise \
  --output-dir outputs \
  --auto-approve
```

Expected result: low residual risk and a clean decommission certificate.

### Run with LangGraph explicitly

```bash
python -m ghostgraph.cli run \
  --agent-id agent-prod-finance-reconciler \
  --data-dir sample_enterprise \
  --output-dir outputs \
  --auto-approve \
  --use-langgraph
```

If LangGraph is not installed, the command will clearly tell you and fall back only when `--no-use-langgraph` is used.

---

## Run tests

```bash
pytest -q
```

The graph compile test is skipped automatically when LangGraph is not installed. Core risk, policy, certificate, scanner, and engine tests should still run.

---

## Optional API server

```bash
uvicorn ghostgraph.api:app --reload
```

Then call:

```bash
curl -X POST http://127.0.0.1:8000/runs \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"agent-prod-finance-reconciler","auto_approve":true}'
```

---

## Important safety model

GhostGraph does not directly delete anything in the local demo. All revocations are mock executions that write evidence artifacts under `outputs/`.

The policy layer requires approval for destructive or production-affecting actions, including:

- Token revocation
- Inbound trigger disablement
- Memory quarantine
- Kubernetes binding removal
- Agent decommission marking
- Dependency migration

This is intentional. The project demonstrates governed autonomy, not blind autonomy.

---

## Where to extend this project

Replace these mock scanners with real connectors:

- `ghostgraph/tools/token_scanner.py` → GitHub App, Vault, cloud secret managers
- `ghostgraph/tools/inbound_scanner.py` → webhooks, queues, schedulers, application programming interface gateways
- `ghostgraph/tools/memory_inspector.py` → vector databases and memory stores
- `ghostgraph/tools/kubernetes_inspector.py` → Kubernetes API
- `ghostgraph/tools/connector_inventory.py` → Slack, Jira, GitHub, internal tools

Advanced production additions:

- OpenTelemetry traces
- PostgreSQL LangGraph checkpointer
- Role-based approval workflow
- Real pull request generation instead of mock revocation
- Evidence retention policy
- Agent resurrection monitoring
- User interface dashboard with dependency graph visualization

---

## Resume bullet

Built GhostGraph, a LangGraph-based agent offboarding and residual access detection platform that discovers retired agent identities, active tool tokens, memory namespaces, inbound triggers, Kubernetes bindings, and downstream dependencies, then generates approval-gated revocation plans and signed decommission evidence reports.
