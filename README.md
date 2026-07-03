<h1>Emerald</h1>

**An orchestrated, vendor-neutral testing harness for code scanners.**

Point Emerald at any repository and it runs the security scanners *and* the LLM
models you have keys for — side by side, normalized into one comparable result.
Or plug in **your own** scanner and benchmark it against a corpus of
deliberately-vulnerable apps and every other scanner.

Bring your own everything. Emerald ships **no proprietary scanner** — it is the
harness, not the scanner.

---

## Two modes

1. **Scan a repo.** Give Emerald a path or a GitHub URL. It runs the open-source
   scanners (Semgrep, Bandit, njsscan, gosec, …) and LLM-as-scanner models
   (Claude, GPT, Gemini, DeepSeek, …) — whichever you have API keys for — and
   shows you what each found.

2. **Benchmark a scanner.** Plug your scanner in via a one-file manifest, pick
   which vulnerable apps to test against and which scanners to compare with, and
   get an apples-to-apples scorecard (recall vs. labelled ground truth, overlap,
   noise).

## Quickstart

```bash
# with Docker (recommended)
docker compose up            # dashboard on http://localhost:8501

# or as a CLI
pip install -e ".[llm]"
emerald list
emerald scan https://github.com/adeyosemanputra/pygoat --language python --only semgrep,bandit,claude
```

LLM scanners read their key from the environment:
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `DEEPSEEK_API_KEY`.
Keys are used only for the run and are never stored.

## Plug in any scanner

A scanner is a **manifest, not code** — two axes make it accept anything:

| axis | values | meaning |
|------|--------|---------|
| `kind` | `command` · `python` · `docker` · `llm` | how Emerald invokes it |
| `format` | `sarif` · `emerald-json` | how it reports (both normalize to one model) |

```yaml
# my_scanners.yaml  ->  emerald scan <repo> --scanners my_scanners.yaml --only my-scanner
scanners:
  my-scanner:
    kind: command
    requires: my-scanner
    format: sarif
    languages: [python, go]        # optional; empty = all
    run: "my-scanner --sarif -o {output} {target}"
    output: "{tmp}/my.sarif"
```

Because a scanner is just a manifest pointing at wherever your tool already
lives, **your scanner's source never has to enter this repo.** See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Dashboard

`docker compose up` (or `streamlit run emerald/app/dashboard.py`) gives you:

- **Scan a repo** — from a GitHub URL, a local path, or a **`.zip` upload**.
- **Benchmark scanners** — pick vulnerable apps + scanners, get a clickable
  scorecard (recall vs. ground truth, drill-down, links to the exact line).
- **Add your own scanner** right in the UI — `command` / `docker` / `python`,
  or a GitHub repo carrying an `emerald-scanner.yaml` — and it instantly joins
  every picker.
- **Bring your own API keys** for the LLM scanners (Claude / GPT / Gemini /
  DeepSeek), entered per-session and never stored.

Built-in adapters: Semgrep, Bandit, njsscan, gosec, Bearer, Trivy, CodeQL, and
the four LLM scanners.

## Status

Early and moving fast — core engine, CLI, clickable dashboard, corpus + scoring,
and a dozen built-in adapters are in. Contributions welcome.

## License

MIT — see [LICENSE](LICENSE).
