"""`review` (zizmor finding mapping, exit status) and `update` (which entries it reviews, ORG.review.txt)."""

import json
import os

import pytest

from gha_tools.allowlist import ActionEntry
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
    Entries named vuln/* are known-vulnerable, bad/* get a SUSPICIOUS AI review, err/* an AI ERROR."""
    calls = []

    def fake_batch(entries, disabled):
        return {e: [finding("known-vulnerable-actions", i)] if e.startswith("vuln/") else []
                for i, e in enumerate(entries)}

    def fake_review_entry(api, uses, info, findings, disabled, ai=True):
        calls.append((uses, info))
        if not ai:
            return review.EntryReview([f"{uses}:", "  using: composite"], None, vulnerable=bool(findings))
        ai_outcome = "SUSPICIOUS" if uses.startswith("bad/") else "ERROR" if uses.startswith("err/") else "CLEAN"
        lines = [f"{uses}:", "  using: composite", f"  AI review: {ai_outcome}", "    examined:    src/"]
        return review.EntryReview(lines, ai_outcome, vulnerable=bool(findings))

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


def test_review_org(org_files, reviewed, capsys):
    org_files(["a/a@v1", "b/b@v2"])
    assert review.review_org(None, "org") == 0
    assert reviewed == [("a/a@v1", {"version": "v1"}), ("b/b@v2", {"version": "v2"})]


def test_review_org_fails_if_vulnerable(org_files, reviewed, capsys):
    org_files(["a/a@v1", "vuln/x@v3"])
    assert review.review_org(None, "org") == 1
    assert "FAIL: known-vulnerable entries:\n  vuln/x@v3\n" in capsys.readouterr().out


def test_review_org_fails_if_suspicious(org_files, reviewed, capsys):
    org_files(["a/a@v1", "bad/x@v1"])
    assert review.review_org(None, "org") == 1
    assert "FAIL: entries with a SUSPICIOUS AI review" in capsys.readouterr().out
    assert "bad/x@v1" in open("org.review.txt").read()  # recorded, so it can be overridden


def test_review_org_fails_if_ai_error(org_files, reviewed, capsys):
    org_files(["a/a@v1", "err/x@v1"])
    assert review.review_org(None, "org") == 1
    assert "FAIL: entries with no AI review result" in capsys.readouterr().out


def test_review_org_passes_ai_flag(org_files, monkeypatch):
    org_files(["a/a@v1"])
    seen = []
    monkeypatch.setattr(review, "review", lambda api, entries, ai: seen.append(ai) or {})
    review.review_org(None, "org")
    review.review_org(None, "org", ai=False)
    assert seen == [True, False]


def test_review_org_records_reviews(org_files, reviewed):
    org_files(["a/a@v1", "b/b@v2"])
    assert review.review_org(None, "org") == 0
    assert open("org.review.txt").read().startswith("a/a@v1:\n  using: composite\n  AI review: CLEAN\n")
    reviewed.clear()
    assert review.review_org(None, "org") == 0
    assert reviewed == []  # they have blocks now


def test_review_org_force_reviews_all_again_and_replaces_blocks(org_files, reviewed):
    org_files(["bad/x@v1"])
    review.review_org(None, "org")
    text = open("org.review.txt").read()
    open("org.review.txt", "w").write(text.replace("  AI review: SUSPICIOUS\n", "  AI review: SUSPICIOUS\n    override: CLEAN - ok\n"))
    reviewed.clear()
    assert review.review_org(None, "org") == 0  # overridden
    assert reviewed == []
    assert review.review_org(None, "org", force=True) == 1  # reviewed again, override gone
    assert [uses for uses, _ in reviewed] == ["bad/x@v1"]
    assert "override" not in open("org.review.txt").read()


def test_review_org_no_ai(org_files, reviewed):
    org_files(["a/a@v1"])
    assert review.review_org(None, "org", ai=False) == 0
    assert "AI review" not in open("org.review.txt").read()
    # ...which doesn't count as reviewed, so the next review with AI does it:
    reviewed.clear()
    assert review.review_org(None, "org") == 0
    assert [uses for uses, _ in reviewed] == ["a/a@v1"]
    assert "AI review: CLEAN" in open("org.review.txt").read()


def test_review_org_no_ai_only_needs_a_block(org_files, reviewed):
    org_files(["a/a@v1", "b/b@v2"])
    open("org.review.txt", "w").write("a/a@v1:\n  using: composite\n")  # a block, but no AI review in it
    assert review.review_org(None, "org", ai=False) == 0
    assert [uses for uses, _ in reviewed] == ["b/b@v2"]  # only the one with no block at all


def test_review_org_force_no_ai_is_a_fresh_review_of_everything(org_files, reviewed):
    """What the nightly job does: all entries, zizmor only; a stored SUSPICIOUS block doesn't matter."""
    org_files(["a/a@v1", "vuln/x@v3"])
    open("org.review.txt", "w").write("a/a@v1:\n  using: composite\n  AI review: SUSPICIOUS\n")
    assert review.review_org(None, "org", ai=False, force=True) == 1  # known-vulnerable
    assert [uses for uses, _ in reviewed] == ["a/a@v1", "vuln/x@v3"]
    org_files(["a/a@v1"])
    assert review.review_org(None, "org", ai=False, force=True) == 0


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
def stub_update(org_files, reviewed, monkeypatch):
    """`update` with the walk stubbed to produce `final["entries"]`, and the real review.txt handling."""
    state = {"entries": ["a/a@v1"]}
    monkeypatch.setattr(update, "read_actions", lambda org: [])
    monkeypatch.setattr(update, "walk", lambda walker, entries: None)
    monkeypatch.setattr(update, "check_versions", lambda walker, entries: None)
    monkeypatch.setattr(update, "build_final", lambda walker, entries, org: {e: {"version": e[-2:]} for e in state["entries"]})
    state["reviewed"] = reviewed
    return state


def final_txt():
    return open("org.final.txt").read() if os.path.exists("org.final.txt") else None


def review_txt():
    return open("org.review.txt").read() if os.path.exists("org.review.txt") else None


def test_update_reviews_entries_without_a_block_then_writes(stub_update):
    stub_update["entries"] = ["a/a@v1", "b/b@v2"]
    assert update.update(None, "org") == 0
    assert [uses for uses, _ in stub_update["reviewed"]] == ["a/a@v1", "b/b@v2"]
    assert final_txt() == "a/a@v1,\nb/b@v2,\n"
    assert review_txt() == (
        "a/a@v1:\n  using: composite\n  AI review: CLEAN\n    examined:    src/\n\n"
        "b/b@v2:\n  using: composite\n  AI review: CLEAN\n    examined:    src/\n")


def test_update_does_not_review_entries_with_a_block(stub_update, capsys):
    update.update(None, "org")
    stub_update["reviewed"].clear()
    stub_update["entries"] = ["a/a@v1", "b/b@v2"]
    assert update.update(None, "org") == 0
    assert [uses for uses, _ in stub_update["reviewed"]] == ["b/b@v2"]
    assert "Comparing against org.review.txt: 1 to review, 0 removed" in capsys.readouterr().out


def test_update_is_idempotent(stub_update):
    update.update(None, "org")
    before = (final_txt(), review_txt())
    stub_update["reviewed"].clear()
    assert update.update(None, "org") == 0
    assert stub_update["reviewed"] == []
    assert (final_txt(), review_txt()) == before


def test_update_keeps_existing_blocks_verbatim_and_drops_removed(stub_update, capsys):
    stub_update["entries"] = ["a/a@v1", "b/b@v2"]
    update.update(None, "org")
    edited = review_txt().replace("    examined:    src/\n\nb/b", "    examined:    src/\n    note: edited by hand\n\nb/b")
    open("org.review.txt", "w").write(edited)
    stub_update["entries"] = ["a/a@v1"]
    assert update.update(None, "org") == 0
    assert review_txt() == "a/a@v1:\n  using: composite\n  AI review: CLEAN\n    examined:    src/\n    note: edited by hand\n"
    out = capsys.readouterr().out
    assert "No entries to review." in out and "Removed entries" in out and "  - b/b@v2" in out


def test_update_ignores_text_outside_blocks(stub_update):
    open("org.review.txt", "w").write(
        "# my notes\n\na/a@v1:\n  using: composite\n  AI review: CLEAN\n\nstray line\n")
    assert update.update(None, "org") == 0
    assert stub_update["reviewed"] == []
    assert review_txt() == "a/a@v1:\n  using: composite\n  AI review: CLEAN\n"  # not kept on rewrite


def test_update_vulnerable_leaves_files_untouched_and_is_not_recorded(stub_update):
    stub_update["entries"] = ["a/a@v1"]
    update.update(None, "org")
    before = (final_txt(), review_txt(), open("jsondata/org.final.json").read())
    stub_update["entries"] = ["a/a@v1", "vuln/new@v1"]
    assert update.update(None, "org") == 1
    assert (final_txt(), review_txt(), open("jsondata/org.final.json").read()) == before


def test_update_ai_error_is_not_recorded_so_is_retried(stub_update):
    stub_update["entries"] = ["a/a@v1", "err/x@v1"]
    assert update.update(None, "org") == 1
    assert final_txt() is None
    assert "err/x@v1" not in review_txt() and "a/a@v1" in review_txt()
    stub_update["reviewed"].clear()
    assert update.update(None, "org") == 1
    assert [uses for uses, _ in stub_update["reviewed"]] == ["err/x@v1"]  # reviewed again


def test_update_suspicious_is_recorded_and_can_be_overridden(stub_update, capsys):
    stub_update["entries"] = ["a/a@v1", "bad/x@v1"]
    assert update.update(None, "org") == 1
    assert final_txt() is None  # not written
    assert "bad/x@v1:\n  using: composite\n  AI review: SUSPICIOUS\n" in review_txt()  # but recorded
    out = capsys.readouterr().out
    assert "FAIL: entries with a SUSPICIOUS AI review" in out and "override: CLEAN" in out

    # Still failing on a re-run: the block is there, so it isn't reviewed again
    stub_update["reviewed"].clear()
    assert update.update(None, "org") == 1
    assert stub_update["reviewed"] == []

    # A person checks it and overrides:
    edited = review_txt().replace("  AI review: SUSPICIOUS\n", "  AI review: SUSPICIOUS\n    override: CLEAN - checked by hand\n")
    open("org.review.txt", "w").write(edited)
    assert update.update(None, "org") == 0
    assert stub_update["reviewed"] == []
    assert final_txt() == "a/a@v1,\nbad/x@v1,\n"
    assert "override: CLEAN - checked by hand" in review_txt()  # kept


@pytest.mark.parametrize("override", ["    override: OK - fine", "    override: SUSPICIOUS", "      override: CLEAN - too indented"])
def test_update_ineffective_overrides(stub_update, override):
    stub_update["entries"] = ["bad/x@v1"]
    update.update(None, "org")
    open("org.review.txt", "w").write(review_txt().replace("  AI review: SUSPICIOUS\n", f"  AI review: SUSPICIOUS\n{override}\n"))
    assert update.update(None, "org") == 1


def test_update_no_review(stub_update):
    stub_update["entries"] = ["bad/x@v1"]
    assert update.update(None, "org", do_review=False) == 0
    assert stub_update["reviewed"] == []
    assert final_txt() == "bad/x@v1,\n" and review_txt() is None
