"""`fix`: rewriting `uses:` lines in a local clone to an allowlisted ref."""

import json
import textwrap

import pytest

from gha_tools.allowlist import AllowlistError
from gha_tools.commands import fix

SHA_A = "a" * 40
SHA_B = "b" * 40


@pytest.fixture
def clone(tmp_path):
    repo = tmp_path / "repo"
    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(textwrap.dedent("""\
        jobs:
          build:
            steps:
              # uses: foo/bar@v1 in a comment line is left alone
              - uses: foo/bar@v1
              - uses: foo/bar@v1 # v1
              - uses: "foo/bar@v1"
              - uses: foo/bar
              - name: x
                uses: foo/bar/sub@main
              - uses: other/thing@v2
              - uses: foo/barbaz@v1
          call:
            uses: foo/bar@main
    """))
    (wf_dir / "notes.txt").write_text("uses: foo/bar@v1\n")
    action_dir = repo / ".github" / "actions" / "setup"
    action_dir.mkdir(parents=True)
    (action_dir / "action.yaml").write_text("runs:\n  using: composite\n  steps:\n    - uses: foo/bar@v0 # v0\n")
    (repo / ".git").mkdir()
    (repo / ".git" / "action.yml").write_text("- uses: foo/bar@v1\n")
    return repo


def read_wf(clone):
    return (clone / ".github" / "workflows" / "ci.yml").read_text()


def test_rewrites_exact_name_only(clone):
    assert fix.update_action(clone, "foo/bar", SHA_A, "v1.2.3") == 6
    assert read_wf(clone) == textwrap.dedent(f"""\
        jobs:
          build:
            steps:
              # uses: foo/bar@v1 in a comment line is left alone
              - uses: foo/bar@{SHA_A} # v1.2.3
              - uses: foo/bar@{SHA_A} # v1.2.3
              - uses: "foo/bar@{SHA_A}" # v1.2.3
              - uses: foo/bar@{SHA_A} # v1.2.3
              - name: x
                uses: foo/bar/sub@main
              - uses: other/thing@v2
              - uses: foo/barbaz@v1
          call:
            uses: foo/bar@{SHA_A} # v1.2.3
    """)
    # action metadata files are fixed too, but not non-workflow files or .git:
    assert (clone / ".github/actions/setup/action.yaml").read_text().endswith(f"- uses: foo/bar@{SHA_A} # v1.2.3\n")
    assert (clone / ".github/workflows/notes.txt").read_text() == "uses: foo/bar@v1\n"
    assert (clone / ".git/action.yml").read_text() == "- uses: foo/bar@v1\n"


def test_path_actions_are_distinct(clone):
    fix.update_action(clone, "foo/bar/sub", SHA_B, "")
    text = read_wf(clone)
    assert f"    uses: foo/bar/sub@{SHA_B}\n" in text
    assert "- uses: foo/bar@v1\n" in text


def test_no_version_drops_comment_and_is_idempotent(clone):
    fix.update_action(clone, "other/thing", SHA_A, "")
    assert f"      - uses: other/thing@{SHA_A}\n" in read_wf(clone)
    assert fix.update_action(clone, "other/thing", SHA_A, "") == 0


def test_rewrite_keeps_crlf():
    text, changes = fix.rewrite_uses("- uses: foo/bar@v1\r\nx: y\r\n", "foo/bar", SHA_A, "v1")
    assert text == f"- uses: foo/bar@{SHA_A} # v1\r\nx: y\r\n"
    assert changes == [("- uses: foo/bar@v1", f"- uses: foo/bar@{SHA_A} # v1")]


@pytest.fixture
def org_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "myorg.actions.txt").write_text(f"foo/bar@{SHA_A}\nmulti/ref@{SHA_A}\nmulti/ref@{SHA_B}\n")
    (tmp_path / "myorg.final.txt").write_text(f"foo/bar@{SHA_A},\nmulti/ref@{SHA_A},\nmulti/ref@{SHA_B},\n")
    (tmp_path / "jsondata").mkdir()
    (tmp_path / "jsondata" / "myorg.final.json").write_text(json.dumps({
        f"foo/bar@{SHA_A}": {"version": "v1.2.3"},
        f"multi/ref@{SHA_A}": {"version": ""},
    }))


def test_resolve_target_ref_from_actions_txt(org_files):
    assert fix.resolve_target("myorg", "foo/bar") == ("foo/bar", SHA_A, "v1.2.3")


def test_resolve_target_explicit_ref(org_files):
    assert fix.resolve_target("myorg", f"multi/ref@{SHA_A}") == ("multi/ref", SHA_A, "")


@pytest.mark.parametrize("action, error", [
    ("multi/ref", "lists 2 refs"),
    ("not/listed", "lists 0 refs"),
    (f"foo/bar@{SHA_B}", "not in myorg.final.txt"),
])
def test_resolve_target_errors(org_files, action, error):
    with pytest.raises(AllowlistError, match=error):
        fix.resolve_target("myorg", action)
