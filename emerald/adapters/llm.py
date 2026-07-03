"""LLM-as-scanner adapter. One code path, many providers - the user brings
whichever API key they have (Anthropic, OpenAI, Google, DeepSeek, or any
OpenAI-compatible endpoint via base_url)."""
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


def gather_source(target: str, cap: int = CAP) -> str:
    root = Path(target)
    blobs, total = [], 0
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
            continue
        blobs.append(chunk)
        total += len(chunk)
    return "".join(blobs)


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
    from openai import OpenAI  # openai / deepseek / any compatible endpoint
    base = base_url or DEFAULT_BASE.get(provider)
    cli = OpenAI(api_key=key, base_url=base or None)
    r = cli.chat.completions.create(
        model=model, max_tokens=4000,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
    return r.choices[0].message.content


def run_llm(spec, target: str, language: str = "") -> list[Finding]:
    provider = spec.provider or "openai"
    key = os.environ.get(KEY_ENV.get(provider, ""), "") or os.environ.get("EMERALD_LLM_KEY", "")
    if not key:
        raise RuntimeError(f"no API key for provider '{provider}' "
                           f"(set {KEY_ENV.get(provider, 'the provider key')})")
    src = gather_source(target)
    if not src.strip():
        return []
    raw = _call(provider, spec.model, key, spec.meta.get("base_url", ""),
                SYSTEM, "Repository source:\n" + src)
    data = _extract_json(raw)
    items = data.get("findings") if isinstance(data, dict) else data
    return [Finding(rule=f.get("rule", ""), severity=norm_severity(f.get("severity", "")),
                    file=f.get("file", ""), line=f.get("line"),
                    message=(f.get("message") or "")[:300], scanner=spec.name)
            for f in (items or []) if isinstance(f, dict)]


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
