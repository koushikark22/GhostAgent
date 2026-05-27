from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .engine import load_request_for_agent, run_pure_python


class RunRequest(BaseModel):
    agent_id: str
    auto_approve: bool = False
    data_dir: str = "sample_enterprise"
    output_dir: str = "outputs"


app = FastAPI(title="GhostGraph", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/runs")
def create_run(payload: RunRequest) -> dict[str, Any]:
    try:
        request = load_request_for_agent(payload.agent_id, payload.data_dir)
        state = run_pure_python(
            request=request,
            data_dir=Path(payload.data_dir),
            output_dir=Path(payload.output_dir),
            auto_approve=payload.auto_approve,
        )
        return {
            "agent_id": payload.agent_id,
            "risk": state.get("risk"),
            "certificate": state.get("certificate"),
            "report_path": state.get("report_path"),
            "findings": state.get("findings"),
            "executed_actions": state.get("executed_actions"),
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
