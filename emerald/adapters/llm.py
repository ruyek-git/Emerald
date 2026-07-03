"""LLM-as-scanner adapter. One code path, many providers - the user brings
whichever API key they have (Anthropic, OpenAI, Google, DeepSeek, or any
OpenAI-compatible endpoint via base_url).

Two modes:
  single  - one pass over (capped) repo source -> findings.
  agent   - an agent that explores the repo file-by-file across rounds, then
            self-verifies its findings to cut false positives.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..core.models import Finding, norm_severity

CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".go", ".rb", ".php", ".c", ".cpp", ".h"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__", "vendor"}
CAP = 120_000

KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
           "google": "GOOGLE_API_KEY", "deepseek": "DEEPSEEK_API_KEY"}
DEFAULT_BASE = {"deepseek": "https://api.deepseek.com"}

SYSTEM = (
    "You are a precise static application security testing (SAST) engine. "
    "Identify real, exploitable security vulnerabilities in the provided source. "
    "Respond with ONLY compact JSON, no prose: "
    '{"findings":[{"rule":"CWE-89 SQL Injection","severity":"critical|high|medium|low",'
    '"file":"relative/path.py","line":123,"message":"one concise sentence"}]}'
)

AGENT_SYSTEM = (
    "You are an application security agent auditing a repository across rounds. "
    "Respond with ONLY JSON each round. To inspect files: {\"read\":[\"path\",...]} (max 12). "
    "When finished: {\"findings\":[{\"rule\":...,\"severity\":\"critical|high|medium|low\","
    "\"file\":...,\"line\":123,\"message\":...}]}. Read the relevant files before concluding; "
    "prioritize real, exploitable issues over style."
)

VERIFY_SYSTEM = (
    "You are a strict security reviewer. Keep a candidate finding ONLY if it is a real, "
    "exploitable vulnerability supported by the code. Return ONLY JSON {\"findings\":[...]} of the kept ones."
)


def _list_code_files(target: str) -> list[str]:
    root = Path(target)
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in CODE_EXTS and not any(s in SKIP_DIRS for s in p.parts):
            out.append(p.relative_to(root).as_posix())
    return out


def gather_source(target: str, cap: int = CAP):
    """Return (concatenated_source, truncated, file_count)."""
    root = Path(target)
    blobs, total, count, truncated = [], 0, 0, False
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in CODE_EXTS:
            continue
        if any(seg in SKIP_DIRS for seg in p.parts):
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        chunk = f"\n\n===== {p.relative_to(root).as_posix()} =====\n{txt}"
        if total + len(chunk) > cap:
            truncated = True
            continue
        blobs.append(chunk)
        total += len(chunk)
        count += 1
    return "".join(blobs), truncated, count


def _resolve(spec, keys: dict | None):
    provider = spec.provider or "openai"
    key = ((keys or {}).get(provider)
           or os.environ.get(KEY_ENV.get(provider, ""), "")
           or os.environ.get("EMERALD_LLM_KEY", ""))
    if not key:
        raise RuntimeError(f"no API key for provider '{provider}' "
                           f"(set {KEY_ENV.get(provider, 'the provider key')})")
    return provider, key


def _call(provider: str, model: str, key: str, base_url: str, system: str, user: str) -> str:
    if provider == "anthropic":
        import anthropic
        m = anthropic.Anthropic(api_key=key).messages.create(
            model=model, max_tokens=4000, system=system, messages=[{"role": "user", "content": user}])
        return m.content[0].text
    if provider == "google":
        from google import genai
        return genai.Client(api_key=key).models.generate_content(
            model=model, contents=system + "\n\n" + user).text
    from openai import OpenAI
    base = base_url or DEFAULT_BASE.get(provider)
    cli = OpenAI(api_key=key, base_url=base or None)
    r = cli.chat.completions.create(
        model=model, max_tokens=4000,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
    return r.choices[0].message.content


def _mk(items, scanner) -> list[Finding]:
    return [Finding(rule=f.get("rule", ""), severity=norm_severity(f.get("severity", "")),
                    file=f.get("file", ""), line=f.get("line"),
                    message=(f.get("message") or "")[:300], scanner=scanner)
            for f in (items or []) if isinstance(f, dict)]


def run_llm(spec, target: str, language: str = "", keys: dict | None = None) -> list[Finding]:
    if spec.mode == "agent":
        return run_agent(spec, target, language, keys)
    provider, key = _resolve(spec, keys)
    src, truncated, _ = gather_source(target)
    if not src.strip():
        return []
    raw = _call(provider, spec.model, key, spec.meta.get("base_url", ""), SYSTEM, "Repository source:\n" + src)
    items = _extract_json(raw)
    items = items.get("findings") if isinstance(items, dict) else items
    return _mk(items, spec.name)


def run_agent(spec, target: str, language: str = "", keys: dict | None = None,
              max_rounds: int = 4, max_files: int = 40) -> list[Finding]:
    provider, key = _resolve(spec, keys)
    base = spec.meta.get("base_url", "")
    files = _list_code_files(target)[:800]
    if not files:
        return []
    history = "Repository files:\n" + "\n".join(files)
    seen, budget, found = set(), max_files, None
    for _ in range(max_rounds):
        data = _extract_json(_call(provider, spec.model, key, base, AGENT_SYSTEM, history))
        if isinstance(data, dict) and "findings" in data:
            found = data["findings"]
            break
        reads = (data.get("read") if isinstance(data, dict) else None) or []
        chunk = ""
        for rel in reads[:12]:
            if rel in seen or budget <= 0:
                continue
            fp = Path(target) / rel
            if not fp.exists():
                continue
            try:
                chunk += f"\n\n===== {rel} =====\n{fp.read_text(encoding='utf-8', errors='replace')[:20000]}"
            except Exception:
                continue
            seen.add(rel)
            budget -= 1
        history += ("\n\nFile contents:" + chunk + "\n\nRead more or return findings JSON."
                    if chunk else "\n\nNo more files available. Return findings JSON now.")
    if found is None:
        data = _extract_json(_call(provider, spec.model, key, base, AGENT_SYSTEM,
                                   history + "\n\nReturn findings JSON now."))
        found = data.get("findings") if isinstance(data, dict) else data
    # self-verification pass to drop false positives
    if found:
        v = _extract_json(_call(provider, spec.model, key, base, VERIFY_SYSTEM,
                                "Candidate findings:\n" + json.dumps({"findings": found})))
        kept = v.get("findings") if isinstance(v, dict) else v
        if kept:
            found = kept
    return _mk(found, spec.name)


def _extract_json(text: str):
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text[:4].lower() == "json":
            text = text[4:]
    i, j = text.find("{"), text.rfind("}")
    try:
        return json.loads(text[i:j + 1])
    except Exception:
        return {"findings": []}
