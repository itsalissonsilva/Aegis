from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or Path.cwd()) / ".aegis"
        self.root.mkdir(exist_ok=True)
        self.path = self.root / "state.json"
        if not self.path.exists():
            self.path.write_text(json.dumps({"runs": {}, "inventories": {}}, indent=2), encoding="utf-8")

    def _load(self) -> dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, payload: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def save_run(self, tool: str, params: dict[str, Any], result: dict[str, Any]) -> str:
        payload = self._load()
        run_id = f"{tool}_{uuid.uuid4().hex[:12]}"
        payload["runs"][run_id] = {
            "id": run_id,
            "tool": tool,
            "params": params,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._save(payload)
        return run_id

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        return self._load()["runs"].get(run_id)

    def save_inventory(self, source_scan_ids: list[str], result: dict[str, Any]) -> str:
        payload = self._load()
        inventory_id = f"inventory_{uuid.uuid4().hex[:12]}"
        payload["inventories"][inventory_id] = {
            "id": inventory_id,
            "scan_ids": source_scan_ids,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._save(payload)
        return inventory_id

    def get_inventory(self, inventory_id: str) -> dict[str, Any] | None:
        return self._load()["inventories"].get(inventory_id)
