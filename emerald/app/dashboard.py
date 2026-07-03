"""Emerald dashboard - navigate everything, click everything.

  streamlit run emerald/app/dashboard.py
"""
import io
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

import streamlit as st
import yaml

from emerald.adapters.registry import ScannerSpec, load_registry
from emerald.core import store
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
STRETCH = "stretch"
SCANNER_HOME = Path(os.path.expanduser("~")) / ".emerald" / "scanners"


def registry() -> dict:
    reg = dict(BASE_REG)
    reg.update(st.session_state.get("custom_scanners", {}))
    return reg


def df(data, **kw):
    st.dataframe(data, width=STRETCH, hide_index=True, **kw)


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
    st.divider()
    st.caption("⚠️ Emerald runs scanners against code you point it at. Run untrusted repos or "
               "third-party scanners in Docker (the `docker` scanner kind is sandboxed with no network). "
               "LLM scanners send source to the provider's API.")


def blob_url(repo, file, line):
    if repo and "github.com" in repo and file:
        return repo.rstrip("/") + "/blob/HEAD/" + str(file) + (f"#L{line}" if line else "")
    return repo or ""


def resolve_target(url_or_path, uploaded, wd):
    if uploaded is not None:
        dest = Path(wd) / "uploaded"
        dest.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(io.BytesIO(uploaded.getvalue())) as z:
                z.extractall(dest)
        except zipfile.BadZipFile:
            return None, "uploaded file is not a valid .zip"
        entries = list(dest.iterdir())
        return str(entries[0] if len(entries) == 1 and entries[0].is_dir() else dest), ""
    if url_or_path and url_or_path.startswith(("http://", "https://", "git@")):
        d = Path(wd) / "repo"
        p = subprocess.run(["git", "clone", "--depth", "1", url_or_path, str(d)],
                           capture_output=True, text=True)
        return (None, "clone failed: " + p.stderr[-300:]) if p.returncode else (str(d), "")
    if url_or_path:
        return url_or_path, ""
    return None, "provide a repo URL/path or upload a zip"


def llm_warning(reg, picks):
    if any(reg[p].kind == "llm" for p in picks if p in reg):
        st.warning("Selected LLM scanners send your repository source to the provider's API.")


def findings_table(rows, repo=""):
    data = [{"scanner": f.get("scanner", ""), "severity": f.get("severity"), "rule": f.get("rule"),
             "source": blob_url(repo, f.get("file"), f.get("line")),
             "message": (f.get("message") or "")[:200]} for f in rows]
    df(data or [{"(none)": ""}],
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
    llm_warning(REG, picks)
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
                    st.write(f"**{name}** - " + (r.skipped or (f"ERROR: {r.error}" if not r.ok
                             else f"{r.count} findings ({r.seconds}s)")))
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
    cc1, cc2 = st.columns(2)
    use_cache = cc1.checkbox("Use result cache (skip unchanged scans)", value=True, key="b_cache")
    save_run = cc2.checkbox("Save this run to history", value=True, key="b_save")
    llm_warning(REG, scanner_names)

    if st.button("Run benchmark", type="primary", key="b_run") and app_names and scanner_names:
        apps = [a for a in corpus if a["name"] in app_names]
        if xurl:
            apps.append({"name": xurl.rstrip("/").split("/")[-1] or "custom",
                         "language": xlang, "repo": xurl, "_ground_truth": None})
        box = st.empty()
        with st.spinner("Cloning + scanning..."):
            res = run_benchmark(REG, apps, scanner_names,
                                lambda a, s: box.write(f"scanning **{a}** with `{s}`..."), KEYS, use_cache)
        box.empty()
        st.session_state["bench"] = res
        st.session_state["bench_scanners"] = scanner_names
        st.session_state["bench_gt"] = {a["name"]: a.get("_ground_truth") for a in apps}
        if save_run:
            rid = store.save_run(res, label=f"{len(apps)} apps x {len(scanner_names)} scanners")
            st.caption(f"saved as {rid}")

    with st.expander("Load a previous run"):
        runs = store.list_runs()
        if runs:
            labels = {f"{r['id']}  ({r['label']})": r for r in runs}
            pick = st.selectbox("Run", list(labels), key="b_loadpick")
            if st.button("Load", key="b_load"):
                data = store.load_run(labels[pick]["path"])
                res = data.get("results", [])
                scs = []
                for r in res:
                    scs.extend(k for k in r.get("scanners", {}) if k not in scs)
                st.session_state["bench"] = res
                st.session_state["bench_scanners"] = scs
                st.session_state["bench_gt"] = gt_by_name
                st.rerun()
        else:
            st.caption("no saved runs yet")

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
                    tag = " *" if sd.get("cached") else ""
                    row[sc] = (f"{n} ({recall(sd['findings'], gt)[0]}/{len(gt['items'])})" if gt else str(n)) + tag
            rows.append(row)
        ev = st.dataframe(rows, width=STRETCH, hide_index=True, on_select="rerun",
                          selection_mode="single-row", key="bmatrix",
                          column_config={"app": LINK("app (-> repo)", display_text=r"https?://[^/]+/[^/]+/([^/?#]+)")})
        st.caption("Cell = findings; (caught/total) = recall; n/a = unsupported; err = error; - = not run; "
                   "* = served from cache. Click an app -> repo; click a row -> findings.")
        try:
            sel = ev.selection.rows
        except Exception:
            sel = []
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
    df([{"scanner": n, "kind": s.kind, "format": s.format, "mode": s.mode,
         "languages": ",".join(s.languages) or "all", "available": s.available(),
         "custom": n in st.session_state.get("custom_scanners", {})} for n, s in reg.items()])

    with st.expander("➕ Add your own scanner"):
        st.caption("⚠️ Scanners you add here run on this machine. For untrusted tools use the `docker` kind "
                   "(sandboxed, no network).")
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
            st.caption("Point at a repo with an `emerald-scanner.yaml`. It is cloned to "
                       "~/.emerald/scanners/<name> (persistent), so command scanners can reference {scanner_dir}.")
            url = st.text_input("GitHub repo URL", key="as_gh")
            if st.button("Load from GitHub", key="as_ghbtn") and url:
                reponame = url.rstrip("/").split("/")[-1].replace(".git", "") or "scanner"
                dest = SCANNER_HOME / reponame
                if dest.exists():
                    shutil.rmtree(dest, ignore_errors=True)
                dest.parent.mkdir(parents=True, exist_ok=True)
                p = subprocess.run(["git", "clone", "--depth", "1", url, str(dest)],
                                   capture_output=True, text=True)
                mani = dest / "emerald-scanner.yaml"
                if p.returncode:
                    st.error("clone failed: " + p.stderr[-200:])
                elif not mani.exists():
                    st.error("no emerald-scanner.yaml in repo root")
                else:
                    data = yaml.safe_load(mani.read_text(encoding="utf-8")) or {}
                    added = []
                    for n, cfg in (data.get("scanners") or {}).items():
                        st.session_state.setdefault("custom_scanners", {})[n] = ScannerSpec(
                            name=n, scanner_dir=str(dest), **(cfg or {}))
                        added.append(n)
                    st.success(f"Registered: {', '.join(added) or '(none)'}")
                    st.rerun()
    st.caption("Or add scanners without the UI: drop a manifest in ./scanners or pass one to the CLI. See docs/ARCHITECTURE.md.")
