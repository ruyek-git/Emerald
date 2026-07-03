"""Scoring: recall against labelled ground truth, and cross-scanner overlap.

Operates on plain finding dicts (as produced by ScanResult.to_dict()), so it
works equally on live results and results loaded from disk.
"""
from __future__ import annotations

from collections import defaultdict


def _norm(s: str) -> str:
    return (s or "").replace("\\", "/").lower()


def caught(findings: list[dict], item: dict) -> bool:
    """True if any finding matches a ground-truth item (file substring + keyword)."""
    gf = _norm(item.get("file"))
    kws = [k.lower() for k in item.get("match", [])]
    for f in findings:
        if gf and gf not in _norm(f.get("file")):
            continue
        hay = _norm(f.get("rule")) + " " + _norm(f.get("message"))
        if any(k in hay for k in kws):
            return True
    return False


def recall(findings: list[dict], ground_truth: dict) -> tuple[int, int]:
    items = ground_truth.get("items", [])
    hit = sum(1 for it in items if caught(findings, it))
    return hit, len(items)


def overlap(findings_by_scanner: dict[str, list[dict]]) -> dict:
    """Location-keyed agreement across scanners."""
    loc: dict[tuple, set] = defaultdict(set)
    for name, findings in findings_by_scanner.items():
        for f in findings:
            key = (_norm(f.get("file")), f.get("line"), _norm(f.get("rule")))
            loc[key].add(name)
    n = len(findings_by_scanner)
    return {
        "locations": len(loc),
        "shared_all": sum(1 for s in loc.values() if len(s) == n),
        "unique": {name: sum(1 for s in loc.values() if s == {name}) for name in findings_by_scanner},
    }
