"""Content-addressed cache for scan results.

Keyed by a stable target identity (git commit SHA when the target is a checkout,
else a cheap content signature) + scanner name + a hash of the scanner manifest.
An unchanged (target, scanner) pair is served from cache instead of re-running.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict
from pathlib import Path

CACHE_DIR = Path(".emerald_cache")
VERSION = "1"


def _target_id(target: str) -> str:
    r = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"],
                       capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return "sha:" + r.stdout.strip()[:16]
    h = hashlib.sha256()
    for p in sorted(Path(target).rglob("*")):
        if p.is_file():
            try:
                h.update(f"{p.relative_to(target)}:{p.stat().st_size}".encode())
            except Exception:
                pass
    return "sig:" + h.hexdigest()[:16]


def _spec_sig(spec) -> str:
    d = asdict(spec)
    d.pop("scanner_dir", None)                 # install path must not change the key
    return hashlib.sha256(json.dumps(d, sort_keys=True, default=str).encode()).hexdigest()[:10]


def key(target: str, spec) -> str:
    raw = f"{VERSION}|{_target_id(target)}|{spec.name}|{_spec_sig(spec)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def get(k: str, cache_dir: Path = CACHE_DIR):
    f = Path(cache_dir) / (k + ".json")
    if f.exists():
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def put(k: str, data: dict, cache_dir: Path = CACHE_DIR) -> None:
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    (Path(cache_dir) / (k + ".json")).write_text(json.dumps(data), encoding="utf-8")
