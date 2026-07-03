"""Emerald command line.

  emerald list
  emerald scan <repo-path-or-git-url> [--language py] [--only semgrep,claude] [--out r.json]
  emerald scan <repo> --scanners my_scanners.yaml --only my-scanner
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from .adapters.registry import load_registry
from .core.runner import run_scanner


def _resolve_target(target: str, workdir: str) -> str:
    if target.startswith(("http://", "https://", "git@")):
        dest = Path(workdir) / "repo"
        subprocess.run(["git", "clone", "--depth", "1", target, str(dest)],
                       check=True, capture_output=True, text=True)
        return str(dest)
    return target


def cmd_list(a) -> None:
    reg = load_registry(*a.scanners)
    for name, spec in reg.items():
        state = "ok" if spec.available() else "missing"
        langs = ",".join(spec.languages) or "all"
        print(f"  {name:16} kind={spec.kind:8} fmt={spec.format:12} langs={langs:20} [{state}]")


def cmd_scan(a) -> dict:
    reg = load_registry(*a.scanners)
    picks = [p for p in a.only.split(",") if p] if a.only else list(reg)
    results = []
    with tempfile.TemporaryDirectory() as wd:
        target = _resolve_target(a.target, wd)
        print(f"target: {a.target}")
        for name in picks:
            spec = reg.get(name)
            if not spec:
                print(f"  ! unknown scanner: {name}", file=sys.stderr)
                continue
            r = run_scanner(spec, target, a.language)
            tag = r.skipped or (f"ERROR: {r.error}" if not r.ok else f"{r.count} findings ({r.seconds}s)")
            print(f"  {name:16} {tag}")
            results.append(r.to_dict())
    out = {"target": a.target, "language": a.language, "results": results}
    if a.out:
        Path(a.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"-> {a.out}")
    return out


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="emerald",
                                 description="Orchestrated testing harness for code scanners.")
    ap.add_argument("--scanners", action="append", default=[],
                    help="extra scanner manifest YAML (repeatable)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a repo path or git URL with selected scanners")
    s.add_argument("target")
    s.add_argument("--language", default="", help="language hint used to gate single-language scanners")
    s.add_argument("--only", default="", help="comma-separated scanner names (default: all)")
    s.add_argument("--out", default="", help="write full results JSON here")
    s.set_defaults(fn=cmd_scan)

    l = sub.add_parser("list", help="list registered scanners and availability")
    l.set_defaults(fn=cmd_list)

    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
