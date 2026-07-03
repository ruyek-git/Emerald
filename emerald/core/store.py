"""Persist benchmark runs to disk and list/load them (run history)."""
from __future__ import annotations

import json
import time
from pathlib import Path

RESULTS_DIR = Path("_results")


def save_run(results: list, label: str = "", results_dir: Path = RESULTS_DIR) -> str:
    Path(results_dir).mkdir(parents=True, exist_ok=True)
    rid = "run_" + time.strftime("%Y%m%d_%H%M%S")
    payload = {"id": rid, "label": label, "created": time.strftime("%Y-%m-%dT%H:%M:%S"), "results": results}
    (Path(results_dir) / (rid + ".json")).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return rid


def list_runs(results_dir: Path = RESULTS_DIR) -> list[dict]:
    d = Path(results_dir)
    if not d.exists():
        return []
    runs = []
    for f in sorted(d.glob("run_*.json"), reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            runs.append({"id": data.get("id", f.stem), "label": data.get("label", ""),
                         "created": data.get("created", ""), "path": str(f),
                         "n": len(data.get("results", []))})
        except Exception:
            pass
    return runs


def load_run(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
