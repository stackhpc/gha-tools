"""`review` (zizmor finding mapping, --base diffs, exit status) and `update` calling it."""

import json

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
    Entries named vuln/* are known-vulnerable."""
    calls = []

    def fake_batch(entries, disabled):
        return {e: [finding("known-vulnerable-actions", i)] if e.startswith("vuln/") else []
                for i, e in enumerate(entries)}

    def fake_review_entry(api, uses, info, findings, disabled):
        calls.append((uses, info))

    monkeypatch.setattr(review, "batch_zizmor", fake_batch)
    monkeypatch.setattr(review, "review_entry", fake_review_entry)
    monkeypatch.setattr(review, "_zizmor_disabled_rules", lambda: set())
    return calls


@pytest.fixture
def org_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def write(entries):
        (tmp_path / "org.final.txt").write_text("".join(f"{e},\n" for e in entries))
        (tmp_path / "org.final.json").write_text(json.dumps({e: {"version": e[-2:]} for e in entries}))

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
    assert "Removed entries (delete these from the allowlist in the GitHub UI):\n  - gone/g@v0\n" in out


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
    calls = {}
    monkeypatch.setattr(update, "read_actions", lambda org: [ActionEntry(f"a/a@{SHA_A}", None, 1)])
    monkeypatch.setattr(update, "walk", lambda walker, entries: None)
    monkeypatch.setattr(update, "check_versions", lambda walker, entries: None)
    monkeypatch.setattr(update, "build_final", lambda walker, entries, org: {f"a/a@{SHA_A}": {}})
    monkeypatch.setattr(update, "write_final", lambda org, final: calls.setdefault("written", final))
    monkeypatch.setattr(update, "default_base", lambda: "merge-base-sha")

    def fake_review_org(api, org, base):
        calls["review"] = base
        return 1

    monkeypatch.setattr(update, "review_org", fake_review_org)
    return calls


def test_update_writes_then_reviews_against_merge_base(stub_update):
    assert update.update(None, "org") == 1
    assert stub_update == {"written": {f"a/a@{SHA_A}": {}}, "review": "merge-base-sha"}


def test_update_explicit_base(stub_update):
    update.update(None, "org", base="v1.0")
    assert stub_update["review"] == "v1.0"


def test_update_no_review(stub_update):
    assert update.update(None, "org", do_review=False) == 0
    assert "review" not in stub_update and "written" in stub_update
