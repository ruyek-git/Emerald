"""Benchmark orchestration: run selected scanners across selected corpus apps."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import yaml

from .runner import run_scanner


def load_corpus(path: str | None = None) -> list[dict]:
    p = Path(path) if path else Path(__file__).resolve().parent.parent / "corpus" / "corpus.yaml"
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    apps = data.get("apps", [])
    for a in apps:
        gt = a.get("ground_truth")
        gp = p.parent / gt if gt else None
        a["_ground_truth"] = yaml.safe_load(gp.read_text(encoding="utf-8")) if (gp and gp.exists()) else None
    return apps


def _clone(repo: str, dest: Path) -> tuple[bool, str]:
    r = subprocess.run(["git", "clone", "--depth", "1", repo, str(dest)],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr[-300:]


def run_target(registry, app: dict, scanners: list[str], workdir: str,
               progress=None, keys: dict | None = None) -> dict:
    dest = Path(workdir) / app["name"]
    ok, err = _clone(app["repo"], dest)
    out = {"app": app["name"], "language": app.get("language"), "repo": app["repo"], "scanners": {}}
    if not ok:
        out["error"] = "clone failed: " + err
        return out
    for name in scanners:
        spec = registry.get(name)
        if not spec:
            continue
        if progress:
            progress(app["name"], name)
        out["scanners"][name] = run_scanner(spec, str(dest), app.get("language", ""), keys).to_dict()
    return out


def run_benchmark(registry, apps: list[dict], scanners: list[str],
                  progress=None, keys: dict | None = None) -> list[dict]:
    results = []
    with tempfile.TemporaryDirectory() as wd:
        for app in apps:
            results.append(run_target(registry, app, scanners, wd, progress, keys))
    return results
