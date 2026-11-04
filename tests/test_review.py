"""`review` (zizmor finding mapping, --base diffs, exit status) and `update` calling it."""

import json

import pytest

from gha_tools.allowlist import ActionEntry
from gha_tools.github import GitHubAPIError
from gha_tools.commands import review, update

SHA_A = "a" * 40


def finding(ident, step, annotation=""):
    return {
        "ident": ident,
        "desc": f"{ident} desc",
        "locations": [{"symbolic": {
            "kind": "Primary",
            "annotation": annotation,
            "route": {"route": [{"Key": "runs"}, {"Key": "steps"}, {"Index": step}, {"Key": "uses"}]},
        }}],
    }


def test_batch_zizmor_maps_findings_to_entries(monkeypatch):
    seen = {}

    def fake_zizmor(input, config=None):
        seen["input"] = input
        return [
            finding("known-vulnerable-actions", 1, "GHSA-xxxx"),
            finding("unpinned-uses", 0),  # dropped: duplicates our weak ref check
            finding("artipacked", 0),  # dropped: disabled in config
            finding("impostor-commit", 0),
        ]

    monkeypatch.setattr(review, "run_zizmor", fake_zizmor)
    entries = ["a/a@v1", f"b/b@{SHA_A}"]
    by_entry = review.batch_zizmor(entries, review._zizmor_disabled_rules())
    assert seen["input"].endswith(f"  steps:\n    - uses: a/a@v1\n    - uses: b/b@{SHA_A}")
    assert [f["ident"] for f in by_entry["a/a@v1"]] == ["impostor-commit"]
    assert [f["ident"] for f in by_entry[f"b/b@{SHA_A}"]] == ["known-vulnerable-actions"]
    assert review.format_finding(by_entry[f"b/b@{SHA_A}"][0]) == (
        "zizmor [known-vulnerable-actions]: known-vulnerable-actions desc (GHSA-xxxx)"
    )


@pytest.fixture
def reviewed(monkeypatch):
    """Stub out zizmor and per-entry checks; record which entries get reviewed.
    Entries named vuln/* are known-vulnerable."""
    calls = []

    def fake_batch(entries, disabled):
        return {e: [finding("known-vulnerable-actions", i)] if e.startswith("vuln/") else []
                for i, e in enumerate(entries)}

    def fake_review_entry(api, uses, info, findings, disabled, ai=False):
        calls.append((uses, info))
        return review.EntryReview(vulnerable=bool(findings))

    monkeypatch.setattr(review, "batch_zizmor", fake_batch)
    monkeypatch.setattr(review, "review_entry", fake_review_entry)
    monkeypatch.setattr(review, "_zizmor_disabled_rules", lambda: set())
    return calls


@pytest.fixture
def org_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def write(entries):
        (tmp_path / "org.final.txt").write_text("".join(f"{e},\n" for e in entries))
        (tmp_path / "jsondata").mkdir(exist_ok=True)
        (tmp_path / "jsondata" / "org.final.json").write_text(json.dumps({e: {"version": e[-2:]} for e in entries}))

    return write


def test_review_org_full(org_files, reviewed, capsys):
    org_files(["a/a@v1", "b/b@v2"])
    assert review.review_org(None, "org") == 0
    assert reviewed == [("a/a@v1", {"version": "v1"}), ("b/b@v2", {"version": "v2"})]
    assert "Removed" not in capsys.readouterr().out


def test_review_org_full_fails_if_vulnerable(org_files, reviewed, capsys):
    org_files(["a/a@v1", "vuln/x@v3"])
    assert review.review_org(None, "org") == 1
    assert "FAIL: known-vulnerable entries:\n  vuln/x@v3\n" in capsys.readouterr().out


def test_review_org_base_only_reviews_added(org_files, reviewed, monkeypatch, capsys):
    monkeypatch.setattr(review, "final_at", lambda org, base: {"a/a@v1", "gone/g@v0", "vuln/old@v9"})
    org_files(["a/a@v1", "b/b@v2", "vuln/old@v9"])
    assert review.review_org(None, "org", "main") == 0  # vuln/old was already there
    assert reviewed == [("b/b@v2", {"version": "v2"})]
    out = capsys.readouterr().out
    assert "Comparing against main: 1 added, 1 removed" in out
    assert "Added entries:\n  + b/b@v2\n" in out
    assert "Removed entries (these are dropped when ORG.final.txt is pasted into the GitHub UI):\n  - gone/g@v0\n" in out


def test_review_org_base_fails_if_added_vulnerable(org_files, reviewed, monkeypatch):
    monkeypatch.setattr(review, "final_at", lambda org, base: {"a/a@v1"})
    org_files(["a/a@v1", "vuln/new@v1"])
    assert review.review_org(None, "org", "main") == 1


def test_review_org_base_nothing_added(org_files, reviewed, monkeypatch, capsys):
    monkeypatch.setattr(review, "final_at", lambda org, base: {"a/a@v1"})
    org_files(["a/a@v1"])
    assert review.review_org(None, "org", "main") == 0
    assert reviewed == []
    out = capsys.readouterr().out
    assert "Nothing to review." in out and "No added entries." in out and "No removed entries." in out


def test_is_github_actions(monkeypatch):
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    assert not review.is_github_actions()
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    assert review.is_github_actions()


def test_write_github_output_lists_failed(monkeypatch, tmp_path):
    out = tmp_path / "output"
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    review.write_github_output(["a/a@v1", "b/b@v2"])
    assert out.read_text() == "failed-uses<<GHA_EOF\na/a@v1\nb/b@v2\nGHA_EOF\n"


def test_write_github_output_not_in_actions(monkeypatch, tmp_path):
    out = tmp_path / "output"
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    review.write_github_output(["a/a@v1"])
    assert not out.exists()


def test_review_org_writes_github_output_if_vulnerable(org_files, reviewed, monkeypatch, tmp_path):
    out = tmp_path / "output"
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    org_files(["a/a@v1", "vuln/x@v3"])
    assert review.review_org(None, "org") == 1
    assert out.read_text() == "failed-uses<<GHA_EOF\nvuln/x@v3\nGHA_EOF\n"


def test_report_failures_writes_all_failed_entries_to_github_output(monkeypatch, tmp_path):
    out = tmp_path / "output"
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    assert review.report_failures({
        "a/a@v1": review.EntryReview(ai="CLEAN"),
        "b/b@v2": review.EntryReview(vulnerable=True),
        "c/c@v3": review.EntryReview(error="no action metadata file found"),
        "d/d@v4": review.EntryReview(ai="SUSPICIOUS"),
        "e/e@v5": review.EntryReview(ai="SKIPPED"),
    }) == 1
    assert out.read_text() == "failed-uses<<GHA_EOF\nb/b@v2\nc/c@v3\nd/d@v4\nGHA_EOF\n"


def test_review_org_no_github_output_if_clean(org_files, reviewed, monkeypatch, tmp_path):
    out = tmp_path / "output"
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    org_files(["a/a@v1"])
    assert review.review_org(None, "org") == 0
    assert not out.exists()


def test_review_warns_when_zizmor_offline(monkeypatch, reviewed, caplog):
    monkeypatch.setenv("ZIZMOR_OFFLINE", "true")
    review.review(None, {"a/a@v1": {}})
    assert "known-vulnerable-actions and other online audits are NOT being run" in caplog.text


def test_run_zizmor_passes_token(monkeypatch):
    seen = {}

    class Done:
        returncode = 0
        stdout = "[]"
        stderr = ""

    def fake_run(cmdline, **kwargs):
        seen["cmdline"], seen["env"] = cmdline, kwargs["env"]
        return Done()

    monkeypatch.setattr(review, "run", fake_run)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    assert review.run_zizmor("x: y") == []
    assert seen["cmdline"][0].endswith("zizmor")
    assert seen["cmdline"][1:3] == ["--format", "json"]
    assert seen["env"]["GH_TOKEN"] == "tok"


# -- update -------------------------------------------------------------------

@pytest.fixture
def stub_update(monkeypatch):
    calls = {"status": 0}
    monkeypatch.setattr(update, "read_actions", lambda org: [ActionEntry(f"a/a@{SHA_A}", None, 1)])
    monkeypatch.setattr(update, "walk", lambda walker, entries: None)
    monkeypatch.setattr(update, "check_versions", lambda walker, entries: None)
    monkeypatch.setattr(update, "build_final", lambda walker, entries, org: {f"a/a@{SHA_A}": {}})
    monkeypatch.setattr(update, "write_final", lambda org, final: calls.setdefault("written", final))
    monkeypatch.setattr(update, "default_base", lambda: "merge-base-sha")

    def fake_review_final(api, org, current, info, base):
        assert "written" not in calls  # review happens before writing
        calls["review"] = (current, base)
        return calls["status"]

    monkeypatch.setattr(update, "review_final", fake_review_final)
    return calls


def test_update_reviews_against_merge_base_then_writes(stub_update):
    assert update.update(None, "org") == 0
    assert stub_update["review"] == ({f"a/a@{SHA_A}"}, "merge-base-sha")
    assert stub_update["written"] == {f"a/a@{SHA_A}": {}}


def test_update_does_not_write_if_review_fails(stub_update):
    stub_update["status"] = 1
    assert update.update(None, "org") == 1
    assert "review" in stub_update and "written" not in stub_update


def test_update_no_review(stub_update):
    assert update.update(None, "org", do_review=False) == 0
    assert "review" not in stub_update and "written" in stub_update


def test_update_vulnerable_leaves_files_untouched(org_files, reviewed, monkeypatch):
    """End-to-end through the real review: a vulnerable addition means the
    existing files are left as they were."""
    org_files(["a/a@v1"])
    before = (open("org.final.txt").read(), open("jsondata/org.final.json").read())
    monkeypatch.setattr(update, "read_actions", lambda org: [])
    monkeypatch.setattr(update, "walk", lambda walker, entries: None)
    monkeypatch.setattr(update, "check_versions", lambda walker, entries: None)
    monkeypatch.setattr(update, "build_final", lambda walker, entries, org: {"a/a@v1": {}, "vuln/new@v1": {}})
    monkeypatch.setattr(review, "final_at", lambda org, base: {"a/a@v1"})
    assert update.update(None, "org") == 1
    assert (open("org.final.txt").read(), open("jsondata/org.final.json").read()) == before


# -- running to completion, and --ai --------------------------------------------

def test_review_continues_after_an_entry_cannot_be_reviewed(monkeypatch, capsys):
    monkeypatch.setattr(review, "batch_zizmor", lambda entries, disabled: {e: [] for e in entries})
    monkeypatch.setattr(review, "_zizmor_disabled_rules", lambda: set())
    seen = []

    def fake_review_entry(api, uses, info, findings, disabled, ai=False):
        seen.append(uses)
        if uses == "b/b@v2":
            raise review.EntryError("no action metadata file found for b/b@v2")
        if uses == "c/c@v3":
            raise GitHubAPIError("rate limited")
        return review.EntryReview(ai="SUSPICIOUS" if uses == "d/d@v4" else "CLEAN")

    monkeypatch.setattr(review, "review_entry", fake_review_entry)
    results = review.review(None, {u: {} for u in ["a/a@v1", "b/b@v2", "c/c@v3", "d/d@v4", "e/e@v5"]}, ai=True)
    assert seen == ["a/a@v1", "b/b@v2", "c/c@v3", "d/d@v4", "e/e@v5"]  # all reviewed
    assert results["b/b@v2"].error and results["c/c@v3"].error == "rate limited"
    assert review.report_failures(results) == 1
    out = capsys.readouterr().out
    assert "FAIL could not review: no action metadata file found for b/b@v2" in out
    assert "FAIL: entries which could not be reviewed:\n  b/b@v2\n  c/c@v3\n" in out
    assert "FAIL: entries failing AI review:\n  d/d@v4\n" in out


def test_report_failures():
    assert review.report_failures({}) == 0
    assert review.report_failures({"a": review.EntryReview(ai="CLEAN"), "b": review.EntryReview(ai="SKIPPED")}) == 0
    assert review.report_failures({"a": review.EntryReview(vulnerable=True)}) == 1
    assert review.report_failures({"a": review.EntryReview(ai="ERROR")}) == 1


def test_review_org_ai_flag_and_base(org_files, monkeypatch):
    seen = []
    monkeypatch.setattr(review, "review", lambda api, entries, ai: seen.append((sorted(entries), ai)) or {})
    monkeypatch.setattr(review, "final_at", lambda org, base: {"a/a@v1"})
    org_files(["a/a@v1", "b/b@v2"])
    review.review_org(None, "org")
    review.review_org(None, "org", ai=True)
    review.review_org(None, "org", "main", ai=True)
    assert seen == [(["a/a@v1", "b/b@v2"], False), (["a/a@v1", "b/b@v2"], True), (["b/b@v2"], True)]


def test_review_org_fails_if_ai_review_fails(org_files, monkeypatch, capsys):
    monkeypatch.setattr(review, "batch_zizmor", lambda entries, disabled: {e: [] for e in entries})
    monkeypatch.setattr(review, "_zizmor_disabled_rules", lambda: set())
    monkeypatch.setattr(review, "review_entry", lambda api, uses, info, findings, disabled, ai: review.EntryReview(
        ai="SUSPICIOUS" if uses.startswith("bad/") else "CLEAN"))
    org_files(["a/a@v1", "bad/x@v1"])
    assert review.review_org(None, "org", ai=True) == 1
    assert "FAIL: entries failing AI review:\n  bad/x@v1\n" in capsys.readouterr().out
    org_files(["a/a@v1"])
    assert review.review_org(None, "org", ai=True) == 0
