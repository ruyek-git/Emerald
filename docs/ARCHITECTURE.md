# Emerald architecture

Emerald is a thin orchestration layer around a single idea: **make every scanner
produce the same shape of result, so they can be compared.**

```
target repo ──► [ scanner adapters ] ──► normalize ──► Finding[] ──► score / compare / display
                 semgrep, bandit,                       (one model)     recall vs ground truth
                 njsscan, gosec,                                        cross-scanner overlap
                 claude/gpt/gemini,                                     dashboard + JSON
                 your-scanner ...
```

## 1. The Finding model

Everything normalizes to `emerald.core.models.Finding`:
`rule, severity, file, line, message, scanner, extra`. Severities are mapped
onto one ladder (`critical > high > medium > low > info > unknown`) so tools with
different vocabularies line up.

## 2. Scanner adapters (the contract)

A scanner is described by a **manifest entry**, never by code that must live in
this repo. Two axes:

- **`kind`** — how Emerald invokes it:
  - `command` — any CLI. Emerald fills `{target}`, `{output}`, `{tmp}` and runs it.
  - `python` — a module exposing `scan(target) -> list[dict]`.
  - `docker` — an image run as `docker run --rm --network none -v repo:/src:ro -v out:/out <image>`;
    the container writes `/out/out.sarif`.
  - `llm` — an LLM-as-scanner (see §4).
  - `builtin` — same as `command`; label for shipped defaults.
- **`format`** — how it reports: `sarif` (2.1.0) or `emerald-json` (a tolerant
  JSON shape with field aliases, so bandit/semgrep-json/ad-hoc output all parse).

Optional keys: `requires` (binary that must be on PATH), `languages` (gate;
empty = all), `env`, `output`, `provider`/`model` (llm), `image` (docker),
`module` (python), `meta`.

Manifests load in order — built-in `scanners.yaml` first, then any passed via
`--scanners` — so users override or extend without editing Emerald.

### Why this keeps proprietary scanners out

A closed-source scanner (e.g. a vendor's build-aware engine) is added as a
private `command` or `docker` adapter that points at wherever the tool is
already installed. Emerald orchestrates it and reads its output; the scanner's
source is never copied into or distributed with Emerald.

## 3. Normalization

`emerald.core.normalize` converts `sarif` or `emerald-json` into `Finding[]`,
resolving paths to repo-relative and mapping severities. SARIF rule metadata
(including numeric `security-severity`) is honored.

## 4. LLM-as-scanner

`emerald.adapters.llm` gathers repo source (capped), prompts the model to return
strict JSON findings, and parses them. One code path serves Anthropic, OpenAI,
Google, DeepSeek, and any OpenAI-compatible endpoint (via `meta.base_url`). Keys
come from the environment and are never persisted.

## 5. Corpus, ground truth, scoring (landing next)

- `emerald/corpus/corpus.yaml` — public deliberately-vulnerable apps (referenced
  by URL, never vendored).
- `emerald/corpus/ground_truth/*.yaml` — Emerald's own labelled vulnerabilities
  per app (used to compute recall). This is Emerald IP and is MIT-licensed here.
- Scoring computes recall vs. ground truth and cross-scanner overlap.

## 6. Security posture

- Emerald clones over HTTPS and reads source; it does not build untrusted repos.
- `docker` adapters run with `--network none` and a read-only source mount.
- Running an untrusted third-party scanner is inherently risky — prefer the
  `docker` kind for those, and run Emerald itself in a container.
