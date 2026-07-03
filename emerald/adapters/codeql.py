"""CodeQL adapter (python kind).

Builds a database with `--build-mode=none` and analyzes it with the language's
security-and-quality suite. Requires the `codeql` CLI on PATH (gated by
`requires: codeql` in the manifest).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

LANG_MAP = {"python": "python", "javascript": "javascript", "typescript": "javascript",
            "java": "java", "csharp": "csharp", "go": "go", "cpp": "cpp", "c": "cpp", "ruby": "ruby"}


def _band(sev):
    try:
        v = float(sev)
        return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low"
    except (TypeError, ValueError):
        return sev or "unknown"


def scan(target: str, language: str = "") -> list[dict]:
    if not shutil.which("codeql"):
        raise RuntimeError("codeql CLI not on PATH")
    lang = LANG_MAP.get((language or "").lower())
    if not lang:
        raise RuntimeError(f"codeql: need a supported language hint (got '{language}')")
    with tempfile.TemporaryDirectory() as tmp:
        db, out = Path(tmp) / "db", Path(tmp) / "out.sarif"
        create = subprocess.run(
            ["codeql", "database", "create", str(db), "--language=" + lang,
             "--source-root=" + str(target), "--build-mode=none", "--overwrite"],
            capture_output=True, text=True)
        if not db.exists():
            raise RuntimeError("codeql database create failed: " + create.stderr[-300:])
        subprocess.run(
            ["codeql", "database", "analyze", str(db), lang + "-security-and-quality.qls",
             "--format=sarif-latest", "--output=" + str(out)],
            capture_output=True, text=True)
        if not out.exists():
            return []
        data = json.loads(out.read_text(encoding="utf-8", errors="replace"))

    findings = []
    for run in data.get("runs", []) or []:
        rules = {}
        for r in (run.get("tool", {}).get("driver", {}) or {}).get("rules", []) or []:
            props = r.get("properties", {}) or {}
            rules[r.get("id")] = props.get("security-severity") or \
                (r.get("defaultConfiguration", {}) or {}).get("level")
        for res in run.get("results", []) or []:
            phys = (res.get("locations") or [{}])[0].get("physicalLocation", {}) or {}
            findings.append({
                "rule": res.get("ruleId", ""),
                "severity": _band(rules.get(res.get("ruleId"), "")),
                "file": (phys.get("artifactLocation", {}) or {}).get("uri", ""),
                "line": (phys.get("region", {}) or {}).get("startLine"),
                "message": (res.get("message", {}) or {}).get("text", "")[:300],
            })
    return findings
