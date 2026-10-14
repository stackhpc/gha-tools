"""`gha blocked`: workflows which won't run given ORG.final.txt."""

from gha_tools.commands.blocked import find_blocked, find_unresolved, format_report

CALLS = {
    "foo/bar@v1": [["org/app/.github/workflows/ci.yml@HEAD"]],
    "deep/dep@abc": [
        ["org/app/.github/workflows/ci.yml@HEAD", "org/shared/.github/workflows/w.yml@main"],
        ["org/other/.github/workflows/x.yml@HEAD", "org/shared/.github/workflows/w.yml@main"],
    ],
    "ok/ok@def": [["org/app/.github/workflows/ci.yml@HEAD"]],
}


def test_find_blocked():
    result = find_blocked({}, CALLS, {"ok/ok@def"})
    assert result == {
        "org/app/.github/workflows/ci.yml@HEAD": {
            "deep/dep@abc": [["org/shared/.github/workflows/w.yml@main"]],
            "foo/bar@v1": [[]],
        },
        "org/other/.github/workflows/x.yml@HEAD": {
            "deep/dep@abc": [["org/shared/.github/workflows/w.yml@main"]],
        },
    }


def test_nothing_blocked():
    assert find_blocked({}, CALLS, set(CALLS)) == {}
    assert format_report({}, []) == ""


def test_report_and_unresolved():
    result = find_blocked({}, CALLS, {"ok/ok@def"})
    report = format_report(result, ["gone/away@v1"])
    assert "org/app/.github/workflows/ci.yml@HEAD\n  missing: deep/dep@abc\n    via: org/shared" in report
    assert "     2  deep/dep@abc\n     1  foo/bar@v1" in report
    assert report.rstrip().endswith("gone/away@v1")
    assert find_unresolved({"a/b": {"v1": {"sha": None}, "v2": {"sha": "x"}}}) == ["a/b@v1"]
