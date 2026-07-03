"""Emerald dashboard - navigate everything, click everything.

  streamlit run emerald/app/dashboard.py

Two modes:
  - Scan a repo   : run the scanners you have keys for against any repo.
  - Benchmark     : run selected scanners across selected vulnerable apps,
                    scored against ground truth. Click an app -> its repo;
                    click a row -> drill into findings; click a finding -> the
                    exact line on GitHub.
"""
import subprocess
import tempfile
from pathlib import Path

import streamlit as st

from emerald.adapters.registry import load_registry
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
st.caption("Orchestrated, vendor-neutral testing harness for code scanners. "
           "Scan any repo with the scanners and models you have keys for, or benchmark a scanner against vulnerable apps.")

REG = load_registry()
LINK = st.column_config.LinkColumn


def blob_url(repo: str, file: str, line) -> str:
    if repo and "github.com" in repo and file:
        u = repo.rstrip("/") + "/blob/HEAD/" + str(file)
        return u + (f"#L{line}" if line else "")
    return repo or ""


def clone_if_url(target: str, wd: str):
    if target.startswith(("http://", "https://", "git@")):
        dest = Path(wd) / "repo"
        p = subprocess.run(["git", "clone", "--depth", "1", target, str(dest)],
                           capture_output=True, text=True)
        if p.returncode != 0:
            return None, "clone failed: " + p.stderr[-300:]
        return str(dest), ""
    return target, ""


def findings_table(rows, repo=""):
    data = [{"scanner": f.get("scanner", ""), "severity": f.get("severity"), "rule": f.get("rule"),
             "source": blob_url(repo, f.get("file"), f.get("line")),
             "message": (f.get("message") or "")[:200]} for f in rows]
    st.dataframe(data or [{"(none)": ""}], use_container_width=True, hide_index=True,
                 column_config={"source": LINK("source (-> code)", display_text=r"/blob/[^/]+/(.+)")})


t_scan, t_bench, t_scanners = st.tabs(["Scan a repo", "Benchmark scanners", "Scanners"])

# ---------------------------------------------------------------- Scan a repo
with t_scan:
    target = st.text_input("Repo path or GitHub URL", placeholder="https://github.com/owner/repo")
    lang = st.selectbox("Language hint", ["", "python", "javascript", "typescript", "java", "csharp", "go"])
    default = [n for n, s in REG.items() if s.available() and s.kind != "llm"][:3]
    picks = st.multiselect("Scanners", list(REG), default=default, key="scan_picks")
    if st.button("Scan", type="primary", key="scan_btn") and target and picks:
        with tempfile.TemporaryDirectory() as wd:
            tgt, err = clone_if_url(target, wd)
            if err:
                st.error(err)
            else:
                allf, prog = [], st.progress(0.0)
                for i, name in enumerate(picks):
                    with st.spinner(f"Running {name}..."):
                        r = run_scanner(REG[name], tgt, lang)
                    prog.progress((i + 1) / len(picks))
                    status = r.skipped or (f"ERROR: {r.error}" if not r.ok else f"{r.count} findings ({r.seconds}s)")
                    st.write(f"**{name}** - {status}")
                    allf.extend(f.to_dict() for f in r.findings)
                st.subheader("All findings")
                findings_table(allf, repo=target if target.startswith("http") else "")

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
    if st.button("Run benchmark", type="primary", key="b_run") and app_names and scanner_names:
        apps = [a for a in corpus if a["name"] in app_names]
        box = st.empty()
        def prog(app, scanner):
            box.write(f"scanning **{app}** with `{scanner}`...")
        with st.spinner("Cloning + scanning..."):
            st.session_state["bench"] = run_benchmark(REG, apps, scanner_names, prog)
            st.session_state["bench_scanners"] = scanner_names
        box.empty()

    bench = st.session_state.get("bench")
    if bench:
        scanners = st.session_state.get("bench_scanners", [])
        st.subheader("Comparison matrix")
        rows = []
        for res in bench:
            row = {"app": res.get("repo") or res["app"], "language": res.get("language")}
            gt = gt_by_name.get(res["app"])
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
                   "- = not run. Click an app name to open its repo; click a row to drill into its findings.")
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
    rows = [{"scanner": n, "kind": s.kind, "format": s.format,
             "languages": ",".join(s.languages) or "all", "available": s.available()}
            for n, s in REG.items()]
    st.dataframe(rows, use_container_width=True, hide_index=True)
    st.caption("Add your own: drop a manifest in ./scanners or pass one to the CLI. See docs/ARCHITECTURE.md.")
