"""Run one scanner adapter against a target repo and return a ScanResult.

Every `kind` funnels into the same normalized Finding list, so built-in,
LLM, and user-supplied scanners are all directly comparable.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import time
from pathlib import Path

from . import normalize as N
from .models import Finding, ScanResult


def run_scanner(spec, target: str, language: str = "", timeout: int = 1800) -> ScanResult:
    if not spec.supports(language):
        return ScanResult(spec.name, target, ok=True, skipped=f"unsupported language: {language}")
    if not spec.available():
        need = spec.requires or ("docker" if spec.kind == "docker" else spec.name)
        return ScanResult(spec.name, target, ok=False, error=f"{need} not available")
    t0 = time.time()
    try:
        if spec.kind in ("command", "builtin"):
            findings = _run_command(spec, target, timeout)
        elif spec.kind == "python":
            findings = _run_python(spec, target)
        elif spec.kind == "docker":
            findings = _run_docker(spec, target, timeout)
        elif spec.kind == "llm":
            from ..adapters.llm import run_llm
            findings = run_llm(spec, target, language)
        else:
            return ScanResult(spec.name, target, ok=False, error=f"unknown kind: {spec.kind}")
        return ScanResult(spec.name, target, findings=findings, seconds=round(time.time() - t0, 1))
    except Exception as e:  # a scanner failing must never crash the run
        return ScanResult(spec.name, target, ok=False, error=f"{type(e).__name__}: {e}",
                          seconds=round(time.time() - t0, 1))


def _run_command(spec, target: str, timeout: int) -> list[Finding]:
    with tempfile.TemporaryDirectory() as tmp:
        output = spec.output.format(target=target, tmp=tmp, output="")
        cmd = spec.run.format(target=target, tmp=tmp, output=output)
        env = dict(os.environ, **(spec.env or {}))
        subprocess.run(shlex.split(cmd), capture_output=True, text=True, env=env, timeout=timeout)
        if not Path(output).exists():
            return []
        return N.normalize(spec.format, output, spec.name, target)


def _run_python(spec, target: str) -> list[Finding]:
    import importlib
    mod = importlib.import_module(spec.module)
    raw = mod.scan(target)  # user contract: return list[dict]
    return N.from_emerald_json({"findings": raw}, spec.name, target)


def _run_docker(spec, target: str, timeout: int) -> list[Finding]:
    with tempfile.TemporaryDirectory() as tmp:
        cmd = ["docker", "run", "--rm", "--network", "none",
               "-v", f"{Path(target).resolve()}:/src:ro", "-v", f"{tmp}:/out", spec.image]
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = Path(tmp) / "out.sarif"
        return N.normalize("sarif", out, spec.name, target) if out.exists() else []
