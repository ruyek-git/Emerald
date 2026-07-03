from emerald.adapters.registry import ScannerSpec, load_registry
from emerald.core import cache, store


def test_builtins_load():
    reg = load_registry()
    for name in ["semgrep", "bandit", "codeql", "claude", "bearer", "trivy", "claude-agent"]:
        assert name in reg
    assert reg["bandit"].languages == ["python"]
    assert reg["claude-agent"].mode == "agent"


def test_supports():
    reg = load_registry()
    assert reg["bandit"].supports("python")
    assert not reg["bandit"].supports("go")
    assert reg["semgrep"].supports("anything")     # empty languages = all


def test_cache_roundtrip(tmp_path):
    spec = ScannerSpec(name="s", kind="command")
    cdir = tmp_path / "c"
    k = cache.key(str(tmp_path), spec)
    assert cache.get(k, cdir) is None
    cache.put(k, {"ok": True, "findings": []}, cdir)
    assert cache.get(k, cdir)["ok"] is True


def test_store_roundtrip(tmp_path):
    rid = store.save_run([{"app": "x", "scanners": {}}], "lbl", tmp_path)
    runs = store.list_runs(tmp_path)
    assert runs and runs[0]["id"] == rid
    assert store.load_run(runs[0]["path"])["label"] == "lbl"
