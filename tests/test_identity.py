"""Parsing of `uses:` strings into node identities, and ref helpers."""

import pytest

from gha_tools.identity import (
    NodeIdentity,
    is_full_sha,
    is_reusable_workflow_path,
    resolve_uses,
    root_identity,
    split_action_name,
    tag_specificity,
)

SHA = "34e114876b0b11c390a56381ad16ebd13914f8d5"

ROOT = root_identity("myorg", "myrepo", ".github/workflows/ci.yml", "main")
NESTED_ACTION = NodeIdentity("action", "myorg", "myrepo", "some/deep/path", "main", "./some/deep/path")


@pytest.mark.parametrize(
    "uses, kind, owner, repo, path, ref, node_id",
    [
        ("actions/checkout@v4", "action", "actions", "checkout", "", "v4", "actions/checkout@v4"),
        (f"actions/checkout@{SHA}", "action", "actions", "checkout", "", SHA, f"actions/checkout@{SHA}"),
        ("  actions/checkout@v4  ", "action", "actions", "checkout", "", "v4", "actions/checkout@v4"),
        # action in a subdirectory:
        ("azimuth-cloud/github-actions/s3-lock@master", "action", "azimuth-cloud", "github-actions",
         "s3-lock", "master", "azimuth-cloud/github-actions/s3-lock@master"),
        ("github/codeql-action/init@v3", "action", "github", "codeql-action", "init", "v3",
         "github/codeql-action/init@v3"),
        # reusable workflow in another repo:
        ("other/repo/.github/workflows/build.yml@v1", "reusable_workflow", "other", "repo",
         ".github/workflows/build.yml", "v1", "other/repo/.github/workflows/build.yml@v1"),
        ("other/repo/.github/workflows/build.yaml@main", "reusable_workflow", "other", "repo",
         ".github/workflows/build.yaml", "main", "other/repo/.github/workflows/build.yaml@main"),
        # a .yml action metadata path that is NOT under .github/workflows is an action:
        ("other/repo/sub/action.yml@v1", "action", "other", "repo", "sub/action.yml", "v1",
         "other/repo/sub/action.yml@v1"),
        # refs containing slashes (branch names):
        ("other/repo@feature/thing", "action", "other", "repo", "", "feature/thing", "other/repo@feature/thing"),
    ],
)
def test_resolve_remote(uses, kind, owner, repo, path, ref, node_id):
    ident = resolve_uses(uses, ROOT)
    assert (ident.kind, ident.owner, ident.repo, ident.path, ident.ref) == (kind, owner, repo, path, ref)
    assert ident.node_id == node_id


@pytest.mark.parametrize(
    "uses, kind, path",
    [
        ("./.github/actions/setup", "action", ".github/actions/setup"),
        ("./.github/workflows/reusable.yml", "reusable_workflow", ".github/workflows/reusable.yml"),
        ("./.github/actions/setup/", "action", ".github/actions/setup"),
        ("./a/../b", "action", "b"),
        ("../escape", "action", "../escape"),
    ],
)
def test_resolve_local_uses_callers_identity(uses, kind, path):
    ident = resolve_uses(uses, ROOT)
    assert (ident.kind, ident.owner, ident.repo, ident.path, ident.ref) == (kind, "myorg", "myrepo", path, "main")
    assert ident.raw == uses


def test_local_uses_relative_to_repo_root_not_caller_dir():
    """GitHub resolves ./ relative to the repo root, even from a nested composite action."""
    ident = resolve_uses("./.github/workflows/extra.yml", NESTED_ACTION)
    assert ident.path == ".github/workflows/extra.yml"
    assert ident.kind == "reusable_workflow"
    assert ident.node_id == "myorg/myrepo/.github/workflows/extra.yml@main"


def test_local_uses_inherits_caller_ref():
    caller = NodeIdentity("action", "o", "r", "x", SHA, "o/r/x@" + SHA)
    assert resolve_uses("./y", caller).node_id == f"o/r/y@{SHA}"


def test_local_uses_without_caller_context_is_unresolved():
    caller = NodeIdentity("unresolved", None, None, "", None, "junk")
    ident = resolve_uses("./.github/actions/x", caller)
    assert ident.kind == "unresolved"
    assert ident.node_id == "unresolved:./.github/actions/x"


@pytest.mark.parametrize(
    "uses",
    ["docker://alpine:3.19", "docker://ghcr.io/owner/image@sha256:" + "a" * 64],
)
def test_resolve_docker(uses):
    ident = resolve_uses(uses, ROOT)
    assert ident.kind == "docker"
    assert ident.node_id == f"docker:{uses}"


@pytest.mark.parametrize("uses", ["actions/checkout", "checkout@v4", "", "${{ matrix.action }}", "a/b/@"])
def test_resolve_malformed_is_unresolved(uses):
    ident = resolve_uses(uses, ROOT)
    assert ident.kind == "unresolved"
    assert ident.node_id == f"unresolved:{uses.strip()}"


def test_root_identity():
    ident = root_identity("o", "r", ".github/workflows/ci.yml", "HEAD")
    assert ident.kind == "workflow_root"
    assert ident.node_id == "o/r/.github/workflows/ci.yml@HEAD"


@pytest.mark.parametrize(
    "path, expected",
    [
        (".github/workflows/x.yml", True),
        (".github/workflows/x.yaml", True),
        ("sub/.github/workflows/x.yml", True),
        ("action.yml", False),
        (".github/actions/x", False),
    ],
)
def test_is_reusable_workflow_path(path, expected):
    assert is_reusable_workflow_path(path) is expected


@pytest.mark.parametrize(
    "ref, expected",
    [(SHA, True), (SHA.upper(), False), (SHA[:7], False), ("v4", False), (None, False), ("", False)],
)
def test_is_full_sha(ref, expected):
    assert is_full_sha(ref) is expected


def testtag_specificity_prefers_most_specific():
    tags = ["v1", "v1.2", "v1.2.3", "latest"]
    assert max(tags, key=tag_specificity) == "v1.2.3"
    assert max(["latest", "stable"], key=tag_specificity) == "stable"  # name tiebreak
    assert max(["v2", "latest"], key=tag_specificity) == "v2"  # any version beats non-version


@pytest.mark.parametrize(
    "name, expected",
    [("o/r", ("o", "r", "")), ("o/r/sub", ("o", "r", "sub")), ("o/r/a/b", ("o", "r", "a/b"))],
)
def test_split_action_name(name, expected):
    assert split_action_name(name) == expected


def test_resolve_uses_without_caller():
    assert resolve_uses("foo/bar@v4").node_id == "foo/bar@v4"
    assert resolve_uses("./x").kind == "unresolved"
