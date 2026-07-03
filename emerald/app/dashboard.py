"""Emerald dashboard - navigate everything, click everything.

  streamlit run emerald/app/dashboard.py

Modes:
  - Scan a repo   : point at a GitHub URL / path OR upload a .zip; run the
                    scanners and LLM models you have keys for.
  - Benchmark     : run selected scanners across selected vulnerable apps,
                    scored against ground truth. Add your own scanner and it
                    shows up in the picker. Click app -> repo, row -> findings,
                    finding -> the exact line on GitHub.
  - Scanners      : see every scanner and register your own (command / docker /
                    python / a GitHub repo with an emerald-scanner.yaml).
"""
import io
import subprocess
import tempfile
import zipfile
from pathlib import Path

import streamlit as st
import yaml

from emerald.adapters.registry import ScannerSpec, load_registry
from emerald.core.benchmark import load_corpus, run_benchmark
from emerald.core.runner import run_scanner
from emerald.core.score import recall

st.set_page_config(page_title="Emerald", layout="wide")
st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem; max-width: 1450px;}
    h1 {color:#0b7a5b; letter-spacing:-0.02em;}
    .stTabs [aria-selected="true"] {color:#10b981 !important;}
    .stTabs [data-baseweb="tab-highlight"] {background-color:#10b981;}
    .stButton > button {border-radius:8px; font-weight:600;}
    .stButton > button:hover {border-color:#10b981; color:#10b981;}
    [data-testid="stDataFrame"] thead tr th {background: rgba(16,185,129,0.08); font-weight:700;}
    a {color:#10b981;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Emerald")
st.caption("Orchestrated, vendor-neutral testing harness for code scanners. Scan any repo, or "
           "benchmark a scanner - bring your own scanners, models, and keys.")

BASE_REG = load_registry()
LINK = st.column_config.LinkColumn


def registry() -> dict:
    reg = dict(BASE_REG)
    reg.update(st.session_state.get("custom_scanners", {}))
    return reg


# ---------------------------------------------------------------- sidebar: keys
with st.sidebar:
    st.header("API keys")
    st.caption("Session-only, never written to disk. Needed only for LLM scanners.")
    entered = {
        "anthropic": st.text_input("Anthropic (Claude)", type="password", key="k_anthropic"),
        "openai": st.text_input("OpenAI (GPT)", type="password", key="k_openai"),
        "google": st.text_input("Google (Gemini)", type="password", key="k_google"),
        "deepseek": st.text_input("DeepSeek", type="password", key="k_deepseek"),
    }
    KEYS = {p: v for p, v in entered.items() if v}
    st.caption(f"{len(KEYS)} key(s) active" if KEYS else "no keys entered")


def blob_url(repo: str, file: str, line) -> str:
    if repo and "github.com" in repo and file:
        return repo.rstrip("/") + "/blob/HEAD/" + str(file) + (f"#L{line}" if line else "")
    return repo or ""


def resolve_target(url_or_path: str, uploaded, wd: str):
    if uploaded is not None:
        dest = Path(wd) / "uploaded"
        dest.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(io.BytesIO(uploaded.getvalue())) as z:
                z.extractall(dest)
        except zipfile.BadZipFile:
            return None, "uploaded file is not a valid .zip"
        entries = list(dest.iterdir())
        root = entries[0] if len(entries) == 1 and entries[0].is_dir() else dest
        return str(root), ""
    if url_or_path and url_or_path.startswith(("http://", "https://", "git@")):
        d = Path(wd) / "repo"
        p = subprocess.run(["git", "clone", "--depth", "1", url_or_path, str(d)],
                           capture_output=True, text=True)
        return (None, "clone failed: " + p.stderr[-300:]) if p.returncode else (str(d), "")
    if url_or_path:
        return url_or_path, ""
    return None, "provide a repo URL/path or upload a zip"


def findings_table(rows, repo=""):
    data = [{"scanner": f.get("scanner", ""), "severity": f.get("severity"), "rule": f.get("rule"),
             "source": blob_url(repo, f.get("file"), f.get("line")),
             "message": (f.get("message") or "")[:200]} for f in rows]
    st.dataframe(data or [{"(none)": ""}], use_container_width=True, hide_index=True,
                 column_config={"source": LINK("source (-> code)", display_text=r"/blob/[^/]+/(.+)")})


REG = registry()
t_scan, t_bench, t_scanners = st.tabs(["Scan a repo", "Benchmark scanners", "Scanners"])

# ---------------------------------------------------------------- Scan a repo
with t_scan:
    c1, c2 = st.columns(2)
    target = c1.text_input("Repo path or GitHub URL", placeholder="https://github.com/owner/repo")
    uploaded = c2.file_uploader("...or upload a repo (.zip)", type=["zip"])
    lang = st.selectbox("Language hint", ["", "python", "javascript", "typescript", "java", "csharp", "go"])
    default = [n for n, s in REG.items() if s.available() and s.kind != "llm"][:3]
    picks = st.multiselect("Scanners", list(REG), default=default, key="scan_picks")
    if st.button("Scan", type="primary", key="scan_btn") and (target or uploaded) and picks:
        with tempfile.TemporaryDirectory() as wd:
            tgt, err = resolve_target(target, uploaded, wd)
            if err:
                st.error(err)
            else:
                allf, prog = [], st.progress(0.0)
                for i, name in enumerate(picks):
                    with st.spinner(f"Running {name}..."):
                        r = run_scanner(REG[name], tgt, lang, KEYS)
                    prog.progress((i + 1) / len(picks))
                    status = r.skipped or (f"ERROR: {r.error}" if not r.ok else f"{r.count} findings ({r.seconds}s)")
                    st.write(f"**{name}** - {status}")
                    allf.extend(f.to_dict() for f in r.findings)
                st.subheader("All findings")
                findings_table(allf, repo=target if str(target).startswith("http") else "")

# --------------------------------------------------------- Benchmark scanners
with t_bench:
    corpus = load_corpus()
    gt_by_name = {a["name"]: a.get("_ground_truth") for a in corpus}
    c1, c2 = st.columns(2)
    app_names = c1.multiselect("Vulnerable apps", [a["name"] for a in corpus],
                               default=[a["name"] for a in corpus][:3], key="b_apps")
    scanner_names = c2.multiselect("Scanners to compare", list(REG),
                                   default=[n for n, s in REG.items() if s.available() and s.kind != "llm"][:3],
                                   key="b_scanners")
    with st.expander("Add a one-off target app (git URL)"):
        xurl = st.text_input("Git URL", key="b_xurl")
        xlang = st.selectbox("Language", ["python", "javascript", "typescript", "java", "csharp", "go"], key="b_xlang")

    if st.button("Run benchmark", type="primary", key="b_run") and app_names and scanner_names:
        apps = [a for a in corpus if a["name"] in app_names]
        if xurl:
            apps.append({"name": xurl.rstrip("/").split("/")[-1] or "custom",
                         "language": xlang, "repo": xurl, "_ground_truth": None})
        box = st.empty()
        with st.spinner("Cloning + scanning..."):
            st.session_state["bench"] = run_benchmark(
                REG, apps, scanner_names, lambda a, s: box.write(f"scanning **{a}** with `{s}`..."), KEYS)
            st.session_state["bench_scanners"] = scanner_names
            st.session_state["bench_gt"] = {a["name"]: a.get("_ground_truth") for a in apps}
        box.empty()

    bench = st.session_state.get("bench")
    if bench:
        scanners = st.session_state.get("bench_scanners", [])
        gtmap = st.session_state.get("bench_gt", gt_by_name)
        st.subheader("Comparison matrix")
        rows = []
        for res in bench:
            row = {"app": res.get("repo") or res["app"], "language": res.get("language")}
            gt = gtmap.get(res["app"])
            for sc in scanners:
                sd = res.get("scanners", {}).get(sc)
                if sd is None:
                    row[sc] = "-"
                elif sd.get("skipped"):
                    row[sc] = "n/a"
                elif not sd.get("ok", True):
                    row[sc] = "err"
                else:
                    n = len(sd.get("findings", []))
                    if gt:
                        hit, tot = recall(sd["findings"], gt)
                        row[sc] = f"{n} ({hit}/{tot})"
                    else:
                        row[sc] = str(n)
            rows.append(row)
        ev = st.dataframe(rows, use_container_width=True, hide_index=True,
                          on_select="rerun", selection_mode="single-row", key="bmatrix",
                          column_config={"app": LINK("app (-> repo)", display_text=r"https?://[^/]+/[^/]+/([^/?#]+)")})
        st.caption("Cell = findings; (caught/total) = recall vs ground truth; n/a = unsupported language; "
                   "err = scanner error; - = not run. Click an app name to open its repo; click a row to drill in.")
        sel = []
        try:
            sel = ev.selection.rows
        except Exception:
            pass
        if sel:
            res = bench[sel[0]]
            st.divider()
            st.markdown(f"### {res['app']}  ·  {res.get('language')}")
            if res.get("error"):
                st.error(res["error"])
            for sc in scanners:
                sd = res.get("scanners", {}).get(sc)
                if not sd:
                    continue
                status = sd.get("skipped") or (f"ERROR: {sd.get('error')}" if not sd.get("ok", True)
                                               else f"{len(sd.get('findings', []))} findings")
                with st.expander(f"{sc} - {status}"):
                    findings_table(sd.get("findings", []), repo=res.get("repo", ""))

# ------------------------------------------------------------------ Scanners
with t_scanners:
    reg = registry()
    rows = [{"scanner": n, "kind": s.kind, "format": s.format,
             "languages": ",".join(s.languages) or "all", "available": s.available(),
             "custom": n in st.session_state.get("custom_scanners", {})}
            for n, s in reg.items()]
    st.dataframe(rows, use_container_width=True, hide_index=True)

    with st.expander("➕ Add your own scanner"):
        how = st.radio("How", ["Fill in details", "From GitHub (emerald-scanner.yaml)"], horizontal=True)
        if how == "Fill in details":
            name = st.text_input("Name", key="as_name")
            kind = st.selectbox("Kind", ["command", "docker", "python"], key="as_kind")
            fmt = st.selectbox("Output format", ["sarif", "emerald-json"], key="as_fmt")
            langs = st.text_input("Languages (comma; blank = all)", key="as_langs")
            run = image = module = requires = ""
            output = "{tmp}/out.sarif"
            if kind == "command":
                requires = st.text_input("Required binary (on PATH)", key="as_req")
                run = st.text_input("Run command", placeholder="my-scanner --sarif -o {output} {target}", key="as_run")
                output = st.text_input("Output file", value="{tmp}/out.sarif", key="as_out")
            elif kind == "docker":
                image = st.text_input("Docker image (must write /out/out.sarif)", key="as_img")
            else:
                module = st.text_input("Python module (exposes scan(target, language))", key="as_mod")
                requires = st.text_input("Required binary (optional)", key="as_req2")
            if st.button("Add scanner", key="as_add"):
                if not name:
                    st.warning("Give it a name.")
                else:
                    spec = ScannerSpec(name=name, kind=kind, format=fmt, run=run, image=image,
                                       module=module, requires=requires, output=output,
                                       languages=[x.strip() for x in langs.split(",") if x.strip()])
                    st.session_state.setdefault("custom_scanners", {})[name] = spec
                    st.success(f"Added '{name}'. It now appears in every scanner picker.")
                    st.rerun()
        else:
            st.caption("Point at a repo containing an `emerald-scanner.yaml`. Best for docker-image or "
                       "globally-installed scanners (its run command must not depend on the clone path).")
            url = st.text_input("GitHub repo URL", key="as_gh")
            if st.button("Load from GitHub", key="as_ghbtn") and url:
                with tempfile.TemporaryDirectory() as wd:
                    d = Path(wd) / "s"
                    p = subprocess.run(["git", "clone", "--depth", "1", url, str(d)],
                                       capture_output=True, text=True)
                    mani = d / "emerald-scanner.yaml"
                    if p.returncode:
                        st.error("clone failed: " + p.stderr[-200:])
                    elif not mani.exists():
                        st.error("no emerald-scanner.yaml in repo root")
                    else:
                        data = yaml.safe_load(mani.read_text(encoding="utf-8")) or {}
                        added = []
                        for n, cfg in (data.get("scanners") or {}).items():
                            st.session_state.setdefault("custom_scanners", {})[n] = ScannerSpec(name=n, **(cfg or {}))
                            added.append(n)
                        st.success(f"Registered: {', '.join(added) or '(none)'}")
                        st.rerun()
    st.caption("Or add scanners without the UI: drop a manifest in ./scanners or pass one to the CLI. See docs/ARCHITECTURE.md.")
