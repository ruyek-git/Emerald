from emerald.core import normalize as N


def test_sarif_basic():
    s = {"runs": [{"tool": {"driver": {"rules": [{"id": "r1", "properties": {"security-severity": "8.8"}}]}},
                   "results": [{"ruleId": "r1", "message": {"text": "SQLi"},
                                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "repo/a.py"},
                                                                    "region": {"startLine": 5}}}]}]}]}
    f = N.from_sarif(s, "sg", "repo")
    assert len(f) == 1
    assert f[0].file == "a.py" and f[0].line == 5
    assert f[0].severity == "high"          # 8.8 banded to high


def test_emerald_json_aliases():
    b = {"results": [{"test_id": "B1", "issue_severity": "HIGH", "filename": "/x/app.py",
                      "line_number": 3, "issue_text": "danger"}]}
    f = N.from_emerald_json(b, "bandit", "/x")
    assert f[0].rule == "B1" and f[0].file == "app.py" and f[0].line == 3 and f[0].severity == "high"


def test_rel_prefix_and_midpath():
    assert N._rel("repo/src/x.js", "repo") == "src/x.js"
    assert N._rel("/w/repo/app.py", "/w/repo") == "app.py"
    assert N._rel("src/x.py", "/tmp/xyz") == "src/x.py"     # already relative, untouched
    assert N._rel("myapp/x.py", "app") == "myapp/x.py"      # 'app' must not mangle mid-path
    assert N._rel("x.py", ".") == "x.py"                    # regression: dot in filename
