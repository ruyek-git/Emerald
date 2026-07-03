"""Minimal Emerald dashboard - scan a repo with the scanners you have.

Run: streamlit run emerald/app/dashboard.py
(The benchmark-a-scanner mode + corpus scoring land next.)
"""
import subprocess
import tempfile
from pathlib import Path

import streamlit as st

from emerald.adapters.registry import load_registry
from emerald.core.runner import run_scanner

st.set_page_config(page_title="Emerald", layout="wide")
st.title("Emerald")
st.caption("Orchestrated testing harness for code scanners. Scan a repo with the "
           "open-source scanners and LLM models you have keys for.")

reg = load_registry()
tab_scan, tab_scanners = st.tabs(["Scan a repo", "Scanners"])

with tab_scanners:
    rows = [{"scanner": n, "kind": s.kind, "format": s.format,
             "languages": ",".join(s.languages) or "all", "available": s.available()}
            for n, s in reg.items()]
    st.dataframe(rows, use_container_width=True, hide_index=True)
    st.caption("Add your own: drop a manifest in ./scanners or pass one to the CLI. See docs/ARCHITECTURE.md.")

with tab_scan:
    target = st.text_input("Repo path or GitHub URL", placeholder="https://github.com/owner/repo")
    lang = st.selectbox("Language hint", ["", "python", "javascript", "typescript", "java", "csharp", "go"])
    default = [n for n, s in reg.items() if s.available() and s.kind != "llm"][:3]
    picks = st.multiselect("Scanners", list(reg), default=default)
    if st.button("Scan", type="primary") and target and picks:
        with tempfile.TemporaryDirectory() as wd:
            tgt = target
            if target.startswith(("http://", "https://", "git@")):
                with st.spinner("Cloning..."):
                    dest = Path(wd) / "repo"
                    p = subprocess.run(["git", "clone", "--depth", "1", target, str(dest)],
                                       capture_output=True, text=True)
                if p.returncode != 0:
                    st.error("clone failed: " + p.stderr[-300:])
                    st.stop()
                tgt = str(dest)
            allf = []
            prog = st.progress(0.0)
            for i, name in enumerate(picks):
                with st.spinner(f"Running {name}..."):
                    r = run_scanner(reg[name], tgt, lang)
                prog.progress((i + 1) / len(picks))
                status = r.skipped or (f"ERROR: {r.error}" if not r.ok else f"{r.count} findings ({r.seconds}s)")
                st.write(f"**{name}** - {status}")
                for f in r.findings:
                    allf.append({"scanner": name, "severity": f.severity, "rule": f.rule,
                                 "file": f.file, "line": f.line, "message": f.message})
            st.subheader("All findings")
            st.dataframe(allf or [{"(none)": ""}], use_container_width=True, hide_index=True)
