"""Normalize scanner output into Finding objects.

Two input contracts are understood out of the box:
  - `sarif`         : the industry-standard SARIF 2.1.0 log (most scanners emit it)
  - `emerald-json`  : a tolerant JSON shape - a list, or {"findings": [...]},
                      or {"results": [...]} - with flexible field aliases so most
                      ad-hoc scanner JSON (bandit, semgrep-json, custom) just works.
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, norm_severity


def _rel(path: str, target: str) -> str:
    """Make a scanner path repo-relative. Prefix-based (not substring) so a
    target string appearing mid-path can't mangle the file name."""
    p = (path or "").replace("\\", "/")
    t = (target or "").replace("\\", "/").rstrip("/")
    if not t:
        return p.lstrip("/")
    if p.startswith(t):                       # absolute path under the target
        return p[len(t):].lstrip("/")
    base = t.rsplit("/", 1)[-1]
    if base and p.startswith(base + "/"):     # relative path prefixed with the clone dir name
        return p[len(base) + 1:]
    return p.lstrip("/")                       # already relative


def _load(source):
    if isinstance(source, (str, Path)) and Path(str(source)).exists():
        source = Path(source).read_text(encoding="utf-8", errors="replace")
    return json.loads(source) if isinstance(source, str) else source


def _band(sev):
    """A numeric (CVSS-ish) security-severity -> qualitative band."""
    try:
        v = float(sev)
        return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low"
    except (TypeError, ValueError):
        return sev


def from_sarif(source, scanner: str, target: str = "") -> list[Finding]:
    data = _load(source)
    out: list[Finding] = []
    for run in data.get("runs", []) or []:
        rules = {}
        for r in (run.get("tool", {}).get("driver", {}) or {}).get("rules", []) or []:
            lvl = (r.get("defaultConfiguration", {}) or {}).get("level")
            props = r.get("properties", {}) or {}
            rules[r.get("id")] = lvl or props.get("security-severity") or props.get("severity")
        for res in run.get("results", []) or []:
            loc = (res.get("locations") or [{}])[0]
            phys = loc.get("physicalLocation", {}) or {}
            art = phys.get("artifactLocation", {}) or {}
            region = phys.get("region", {}) or {}
            rid = res.get("ruleId") or ""
            sev = res.get("level") or rules.get(rid) or ""
            out.append(Finding(
                rule=rid,
                severity=norm_severity(_band(sev)),
                file=_rel(art.get("uri", ""), target),
                line=region.get("startLine"),
                message=(res.get("message", {}) or {}).get("text", "")[:300],
                scanner=scanner,
            ))
    return out


def from_emerald_json(source, scanner: str, target: str = "") -> list[Finding]:
    data = _load(source)
    if isinstance(data, dict):
        items = data.get("findings") or data.get("results") or []
    else:
        items = data or []
    out: list[Finding] = []
    for f in items:
        if not isinstance(f, dict):
            continue
        out.append(Finding(
            rule=f.get("rule") or f.get("check_id") or f.get("check") or f.get("id") or f.get("test_id") or "",
            severity=norm_severity(f.get("severity") or f.get("issue_severity") or ""),
            file=_rel(f.get("file") or f.get("path") or f.get("filename") or "", target),
            line=f.get("line") or f.get("start_line") or f.get("line_number"),
            message=(f.get("message") or f.get("msg") or f.get("issue_text") or "")[:300],
            scanner=scanner,
        ))
    return out


def normalize(fmt: str, source, scanner: str, target: str = "") -> list[Finding]:
    if fmt == "sarif":
        return from_sarif(source, scanner, target)
    return from_emerald_json(source, scanner, target)
