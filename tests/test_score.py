from emerald.core.score import caught, overlap, recall


def test_caught_and_recall():
    fs = [{"file": "introduction/mitre.py", "rule": "eval", "message": "code injection"}]
    gt = {"items": [{"file": "introduction", "match": ["eval"]},
                    {"file": "nope", "match": ["zzz"]}]}
    assert caught(fs, gt["items"][0]) is True
    assert caught(fs, gt["items"][1]) is False
    assert recall(fs, gt) == (1, 2)


def test_overlap():
    a = [{"file": "x.py", "line": 1, "rule": "r"}]
    o = overlap({"s1": a, "s2": a})
    assert o["locations"] == 1 and o["shared_all"] == 1
    assert o["unique"] == {"s1": 0, "s2": 0}
