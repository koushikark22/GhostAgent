from __future__ import annotations

from dataclasses import dataclass

from ghostgraph.data_loader import DataStore


@dataclass(frozen=True)
class ScanContext:
    agent_id: str
    store: DataStore
