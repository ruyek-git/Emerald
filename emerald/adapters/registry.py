"""A scanner is described by a manifest, not code.

Two axes make it plug in "anything":
  kind    - how to invoke it:  builtin | command | python | docker | llm
  format  - how it reports:    sarif | emerald-json

Drop a YAML with the shape below (or pass --scanners your.yaml) and Emerald can
run it. Your scanner's source never has to live in this repo - a private
`command`/`docker` adapter points at wherever it already is.

    scanners:
      my-scanner:
        kind: command                 # any CLI
        requires: my-scanner          # binary that must be on PATH
        format: sarif
        languages: [python, go]       # optional; empty = all
        run: "my-scanner --sarif -o {output} {target}"
        output: "{tmp}/my.sarif"
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ScannerSpec:
    name: str
    kind: str                                   # builtin|command|python|docker|llm
    format: str = "sarif"                       # sarif|emerald-json
    run: str = ""                               # command template: {target} {output} {tmp}
    image: str = ""                             # docker image (kind: docker)
    module: str = ""                            # python module exposing scan(target)->list[dict]
    languages: list[str] = field(default_factory=list)   # gate; empty = all
    output: str = "{tmp}/out.sarif"
    env: dict[str, str] = field(default_factory=dict)
    requires: str = ""                          # binary that must exist (kind: command)
    provider: str = ""                          # for kind: llm (anthropic|openai|google|...)
    model: str = ""                             # for kind: llm
    meta: dict[str, Any] = field(default_factory=dict)

    def supports(self, language: str) -> bool:
        return (not self.languages) or (not language) or (language in self.languages)

    def available(self) -> bool:
        if self.kind == "command" and self.requires:
            return shutil.which(self.requires) is not None
        if self.kind == "docker":
            return shutil.which("docker") is not None
        return True


def load_registry(*extra_paths) -> dict[str, ScannerSpec]:
    """Load built-in scanners.yaml plus any extra manifests (later wins)."""
    registry: dict[str, ScannerSpec] = {}
    default = Path(__file__).with_name("scanners.yaml")
    for path in [default, *extra_paths]:
        p = Path(path)
        if not p.exists():
            continue
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        for name, cfg in (data.get("scanners") or {}).items():
            registry[name] = ScannerSpec(name=name, **(cfg or {}))
    return registry
