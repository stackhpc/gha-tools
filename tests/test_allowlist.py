"""actions.txt parsing, final.{txt,json} generation from a walk, and git comparison."""

import json
import logging
import subprocess

import pytest

from gha_tools import allowlist
from gha_tools.allowlist import AllowlistError, ActionEntry, parse_actions_text
from gha_tools.github import Transient
from gha_tools.walker import Walker
from test_walker import FakeAPI, sha

SHA_A = "a" * 40
SHA_B = "b" * 40


# -- actions.txt --------------------------------------------------------------

def test_parse_actions_text(caplog):
    text = f"""
# a comment, then a blank line

foo/bar@{SHA_A}, # v1.2.3
foo/bar/sub@{SHA_B}
  spaced/out@{SHA_A} ,   # needed for x, not a version
other/wf/.github/workflows/w.yml@{SHA_A},
tagged/action@v4  # warned
myorg/internal@main
MyOrg/shouty/.github/workflows/x.yml@main
actions/checkout@v4
"""
    with caplog.at_level(logging.WARNING):
        entries = parse_actions_text(text, "myorg")
    assert entries == [
        ActionEntry(f"foo/bar@{SHA_A}", "v1.2.3", 4),
        ActionEntry(f"foo/bar/sub@{SHA_B}", None, 5),
        ActionEntry(f"spaced/out@{SHA_A}", None, 6),
        ActionEntry(f"other/wf/.github/workflows/w.yml@{SHA_A}", None, 7),
        ActionEntry("tagged/action@v4", None, 8),
        ActionEntry("myorg/internal@main", None, 9),
        ActionEntry("MyOrg/shouty/.github/workflows/x.yml@main", None, 10),
        ActionEntry("actions/checkout@v4", None, 11),
    ]
    assert entries[1].name == "foo/bar/sub" and entries[1].ref == SHA_B
    # non-SHA warnings only for external entries; GitHub-owned ones are pointless:
    warnings = [r.getMessage() for r in caplog.records]
    assert warnings == [
        "tagged/action@v4 (line 8) has a non-SHA ref",
        "actions/checkout@v4 (line 11) is GitHub-owned and need not be listed",
    ]


def test_parse_actions_text_errors():
    text = "foo/bar\nfoo/baz@\nok/thing@" + SHA_A + "\n./local@v1\ndocker://alpine:3\n"
    with pytest.raises(AllowlistError) as e:
        parse_actions_text(text, "myorg")
    msg = str(e.value)
    assert "line 1: 'foo/bar' has no ref" in msg
    assert "line 2: 'foo/baz@' has no ref" in msg
    assert "line 3" not in msg
    assert "line 4: './local@v1' is not a remote action" in msg
    assert "line 5" in msg  # docker://alpine:3 has no '@'


# -- building final.{txt,json} ------------------------------------------------

@pytest.fixture
def graph():
    """
    actions.txt roots:
      ext/a@SHA_A           composite -> ext/dep@v3 (tag), myorg/inner@main, actions/checkout@v4
      myorg/tool@main       internal composite -> ext/via-org@SHA_B, ./sub (local, internal)
    myorg/inner@main        internal composite, reached from ext/a -> ext/deep@main (branch), docker://x
    myorg/tool/sub@main     -> ext/a@SHA_A (already a root)
    """
    return FakeAPI(
        files={
            ("ext", "a", "action.yml", SHA_A): """
                runs:
                  using: composite
                  steps:
                    - uses: ext/dep@v3
                    - uses: myorg/inner@main
                    - uses: actions/checkout@v4
            """,
            ("ext", "dep", "action.yml", "v3"): "runs: {using: node20, main: dist/index.js}",
            ("myorg", "inner", "action.yml", "main"): """
                runs:
                  using: composite
                  steps:
                    - uses: ext/deep@main
                    - uses: docker://x
            """,
            ("ext", "deep", "action.yml", "main"): "runs: {using: node20, main: dist/index.js}",
            ("actions", "checkout", "action.yml", "v4"): "runs: {using: node20, main: dist/index.js}",
            ("myorg", "tool", "action.yml", "main"): """
                runs:
                  using: composite
                  steps:
                    - uses: ext/via-org@""" + SHA_B + """
                    - uses: ./sub
            """,
            ("myorg", "tool", "sub/action.yml", "main"): """
                runs:
                  using: composite
                  steps:
                    - uses: ext/a@""" + SHA_A + """
            """,
            ("ext", "via-org", "action.yml", SHA_B): "runs: {using: node20, main: dist/index.js}",
        },
        shas={
            ("ext", "dep", "v3"): sha(3),
            ("myorg", "inner", "main"): sha(4),
            ("ext", "deep", "main"): sha(5),
            ("actions", "checkout", "v4"): sha(6),
            ("myorg", "tool", "main"): sha(7),
        },
        tags={
            ("ext", "a"): {"v1": SHA_A, "v1.0.1": SHA_A},
            ("ext", "dep"): {"v3": sha(3), "v3.1.0": sha(3)},
        },
    )


ENTRIES = [ActionEntry(f"ext/a@{SHA_A}", "v1.0.0", 1), ActionEntry("myorg/tool@main", None, 2)]


def test_build_final(graph):
    walker = Walker(":memory:", api=graph)
    allowlist.walk(walker, ENTRIES)
    final = allowlist.build_final(walker, ENTRIES, "MyOrg")  # org matching is case-insensitive

    # no org-owned, GitHub-owned or docker entries; deps keep their literal refs:
    assert list(final) == [
        f"ext/a@{SHA_A}",
        "ext/deep@main",
        "ext/dep@v3",
        f"ext/via-org@{SHA_B}",
    ]
    assert final[f"ext/a@{SHA_A}"] == {
        "kind": "action", "sha": SHA_A, "version": "v1.0.1", "ref_source": "is_sha", "root": True,
        # also reached from the internal root, via its local ./sub action:
        "chains": [["myorg/tool@main", "myorg/tool/sub@main"]],
    }
    assert final["ext/dep@v3"] == {
        "kind": "action", "sha": sha(3), "version": "v3.1.0", "ref_source": "tag", "root": False,
        # chains start from the nearest actions.txt root:
        "chains": [[f"ext/a@{SHA_A}"]],
    }
    # walked through an org-owned action reached from an external one:
    assert final["ext/deep@main"]["ref_source"] == "branch"
    assert final["ext/deep@main"]["chains"][0] == [f"ext/a@{SHA_A}", "myorg/inner@main"]
    # found via an internal root:
    assert final[f"ext/via-org@{SHA_B}"]["chains"] == [["myorg/tool@main"]]
    assert final[f"ext/via-org@{SHA_B}"]["root"] is False

    assert allowlist.format_final_txt(final) == (
        f"ext/a@{SHA_A},\next/deep@main,\next/dep@v3,\next/via-org@{SHA_B},\n"
    )


def test_check_versions(graph, caplog):
    walker = Walker(":memory:", api=graph)
    allowlist.walk(walker, ENTRIES)
    with caplog.at_level(logging.WARNING):
        allowlist.check_versions(walker, ENTRIES)
    assert [r.getMessage() for r in caplog.records] == [
        f"ext/a@{SHA_A} (line 1) is commented as v1.0.0 but is tagged v1.0.1",
    ]


def test_walk_fails_on_unresolved(graph):
    del graph.files[("ext", "deep", "action.yml", "main")]
    walker = Walker(":memory:", api=graph)
    with pytest.raises(AllowlistError) as e:
        allowlist.walk(walker, ENTRIES)
    assert "ext/deep@main [unresolved]" in str(e.value)
    assert f"via: ext/a@{SHA_A} -> myorg/inner@main -> ext/deep@main" in str(e.value)


def test_walk_retries_then_fails_on_persistent_errors(graph):
    graph.transient.add(("ext", "dep", "action.yml", "v3"))  # fails once, then succeeds
    walker = Walker(":memory:", api=graph)
    allowlist.walk(walker, ENTRIES)
    assert walker.summary() == {"done": 9}

    class AlwaysFlaky(FakeAPI):
        def list_tags(self, owner, repo):
            if repo == "dep":
                raise Transient("still flaky")
            return super().list_tags(owner, repo)

    flaky = AlwaysFlaky(graph.files, graph.shas, graph.tags)
    walker = Walker(":memory:", api=flaky)
    with pytest.raises(AllowlistError, match=r"ext/dep@v3 \[error\]: still flaky"):
        allowlist.walk(walker, ENTRIES)


def test_write_and_read_final(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    final = {"b/b@v1": {"version": "v1"}, f"a/a@{SHA_A}": {"version": ""}}
    allowlist.write_final("org", final)
    assert (tmp_path / "org.final.txt").read_text() == f"a/a@{SHA_A},\nb/b@v1,\n"
    assert allowlist.read_final("org") == ({f"a/a@{SHA_A}", "b/b@v1"}, final)
    assert json.loads((tmp_path / "org.final.json").read_text()) == final


# -- git ----------------------------------------------------------------------

def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True,
                   capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "README").write_text("x")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def test_final_at(repo):
    sub = repo / "orgs"
    sub.mkdir()
    (sub / "org.final.txt").write_text("a/a@v1,\nb/b@v2,\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "add")
    (sub / "org.final.txt").write_text("a/a@v1,\n")
    # paths are relative to the current directory, not the repo root:
    import os
    os.chdir(sub)
    assert allowlist.final_at("org", "HEAD") == {"a/a@v1", "b/b@v2"}
    assert allowlist.final_at("org", "HEAD~1") == set()  # didn't exist then
    with pytest.raises(AllowlistError, match="not a valid git ref"):
        allowlist.final_at("org", "nope")


def test_default_base(repo, caplog):
    with caplog.at_level(logging.WARNING):
        assert allowlist.default_base() == "HEAD"  # no origin/main
    assert "could not find merge-base" in caplog.text

    head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "checkout", "-q", "-b", "feature")
    git(repo, "commit", "-q", "--allow-empty", "-m", "feature work")
    assert allowlist.default_base() == head


def test_no_git_repo(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    with caplog.at_level(logging.WARNING):
        assert allowlist.default_base() == "HEAD"
        assert allowlist.final_at("org", "HEAD") == set()
    assert "not in a git repo" in caplog.text


def test_walk_local_ref_in_external_composite_is_not_walked(graph, caplog):
    # e.g. pypa/gh-action-pypi-publish, which generates a local action at runtime:
    graph.files[("ext", "dep", "action.yml", "v3")] = """
        runs:
          using: composite
          steps:
            - uses: ./.github/.tmp/generated
    """
    # without an org, it is resolved against ext/dep, so is unresolved:
    with pytest.raises(AllowlistError, match=r"ext/dep/\.github/\.tmp/generated@v3 \[unresolved\]"):
        allowlist.walk(Walker(":memory:", api=graph), ENTRIES)

    walker = Walker(":memory:", api=graph, org="MyOrg")  # org matching is case-insensitive
    with caplog.at_level(logging.WARNING):
        allowlist.walk(walker, ENTRIES)
    nodes = {n["node_id"]: n for n in walker.export_nodes()}
    assert nodes["local:./.github/.tmp/generated"]["status"] == "done"
    assert "ext/dep/.github/.tmp/generated@v3" not in nodes
    assert "myorg/tool/sub@main" in nodes  # local refs in internal composite actions are still walked
    assert any("ext/dep@v3 uses ./.github/.tmp/generated" in r.getMessage() for r in caplog.records)
    # and it's not in the allowlist:
    assert list(allowlist.build_final(walker, ENTRIES, "myorg")) == [
        f"ext/a@{SHA_A}", "ext/deep@main", "ext/dep@v3", f"ext/via-org@{SHA_B}",
    ]
