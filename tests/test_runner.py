import sys
import types

from emerald.adapters.registry import ScannerSpec
from emerald.core.runner import run_scanner


def test_language_gate():
    spec = ScannerSpec(name="b", kind="command", requires="nope", languages=["python"])
    assert run_scanner(spec, ".", "go").skipped


def test_missing_binary():
    spec = ScannerSpec(name="x", kind="command", requires="definitely-not-a-binary-xyz")
    r = run_scanner(spec, ".", "python")
    assert not r.ok and "not available" in r.error


def test_python_kind(tmp_path):
    m = types.ModuleType("t_scanner_mod")
    m.scan = lambda target, language="": [{"rule": "R", "severity": "high", "file": "a.py",
                                           "line": 2, "message": "m"}]
    sys.modules["t_scanner_mod"] = m
    spec = ScannerSpec(name="t", kind="python", module="t_scanner_mod", format="emerald-json")
    r = run_scanner(spec, str(tmp_path), "python")
    assert r.ok and r.count == 1 and r.findings[0].rule == "R"
