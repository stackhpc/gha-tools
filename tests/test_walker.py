"""Call-graph walking against an in-memory fake GitHub."""

import textwrap

import pytest

from gha_tools.github import NotFound, Transient
from gha_tools.walker import Walker, composite_action_children, workflow_style_children
import yaml


def sha(n):
    return f"{n:040x}"


class FakeAPI:
    """Stands in for the walker's GitHub client. Files keyed on
    (owner, repo, path, ref); refs resolve via `shas`, tags via `tags`."""

    def __init__(self, files=None, shas=None, tags=None):
        self.files = {k: textwrap.dedent(v) for k, v in (files or {}).items()}
        self.shas = shas or {}
        self.tags = tags or {}
        self.calls = []
        self.transient = set()  # file keys that raise Transient once

    def get_file_text(self, owner, repo, path, ref):
        key = (owner, repo, path, ref)
        self.calls.append(("file",) + key)
        if key in self.transient:
            self.transient.discard(key)
            raise Transient(f"flaky {key}")
        if key not in self.files:
            raise NotFound(f"404 {key}")
        return self.files[key]

    def resolve_ref_sha(self, owner, repo, ref):
        self.calls.append(("sha", owner, repo, ref))
        if len(ref) == 40:
            return ref
        try:
            return self.shas[(owner, repo, ref)]
        except KeyError:
            raise NotFound(f"no ref {owner}/{repo}@{ref}")

    def list_tags(self, owner, repo):
        self.calls.append(("tags", owner, repo))
        return dict(self.tags.get((owner, repo), {}))


WF = ".github/workflows/ci.yml"


def make_walker(tmp_path, api, **kw):
    return Walker(str(tmp_path / "graph.db"), api=api, **kw)


def nodes_by_id(walker):
    return {n["node_id"]: n for n in walker.export_nodes()}


def test_yaml_children_extraction():
    wf = yaml.safe_load(textwrap.dedent("""
        jobs:
          a:
            steps:
              - run: echo
              - uses: x/y@v1
              - uses: ./local
          b:
            uses: o/r/.github/workflows/w.yml@main
            steps:
              - uses: ignored/because@job-level-uses
          c: "not a dict"
    """))
    assert workflow_style_children(wf) == [
        ("job:a/step:1", "x/y@v1"),
        ("job:a/step:2", "./local"),
        ("job:b", "o/r/.github/workflows/w.yml@main"),
    ]
    assert workflow_style_children({"jobs": ["bad"]}) == []
    assert workflow_style_children({}) == []

    comp = yaml.safe_load("runs: {using: composite, steps: [{run: x}, {uses: a/b@v1}]}")
    assert composite_action_children(comp) == [("step:1", "a/b@v1")]
    assert composite_action_children(yaml.safe_load("runs: {using: node20, main: x.js}")) == []


@pytest.fixture
def graph_api():
    """
    myorg/app ci.yml (default branch)
      -> actions/checkout@v4                      (node action, leaf)
      -> ./.github/actions/setup                  (local composite)
           -> third/party/sub@v1                  (subdir composite, action.yaml)
                -> actions/checkout@v4            (shared leaf; fetched once)
           -> docker://alpine:3                   (docker leaf)
      -> myorg/shared/.github/workflows/r.yml@main (reusable)
           -> third/party/sub@v1
           -> ./.github/workflows/r.yml           (self-cycle via local ref)
      -> does/not-exist@v1                        (404 -> unresolved)
    """
    return FakeAPI(
        files={
            ("myorg", "app", WF, "HEAD"): """
                jobs:
                  build:
                    steps:
                      - uses: actions/checkout@v4
                      - uses: ./.github/actions/setup
                      - uses: does/not-exist@v1
                  call:
                    uses: myorg/shared/.github/workflows/r.yml@main
            """,
            ("myorg", "app", ".github/actions/setup/action.yml", "HEAD"): """
                runs:
                  using: composite
                  steps:
                    - uses: third/party/sub@v1
                    - uses: docker://alpine:3
            """,
            ("actions", "checkout", "action.yml", "v4"): "runs: {using: node20, main: dist/index.js}",
            ("third", "party", "sub/action.yaml", "v1"): """
                runs:
                  using: composite
                  steps:
                    - uses: actions/checkout@v4
            """,
            ("myorg", "shared", ".github/workflows/r.yml", "main"): """
                on: workflow_call
                jobs:
                  j:
                    steps:
                      - uses: third/party/sub@v1
                  again:
                    uses: ./.github/workflows/r.yml
            """,
        },
        shas={
            ("myorg", "app", "HEAD"): sha(1),
            ("actions", "checkout", "v4"): sha(2),
            ("third", "party", "v1"): sha(3),
            ("myorg", "shared", "main"): sha(4),
        },
        tags={
            ("actions", "checkout"): {"v4": sha(2), "v4.2.1": sha(2), "v4.2": sha(2), "v3": sha(9)},
            ("third", "party"): {"v1": sha(3)},
            ("myorg", "shared"): {"v0.1.0": sha(4)},
        },
    )


def test_full_graph(tmp_path, graph_api):
    w = make_walker(tmp_path, graph_api)
    root = w.add_root("myorg", "app", WF)
    assert root == f"myorg/app/{WF}@HEAD"
    w.run()

    nodes = nodes_by_id(w)
    assert {k: v["status"] for k, v in nodes.items()} == {
        root: "done",
        "myorg/app/.github/actions/setup@HEAD": "done",
        "actions/checkout@v4": "done",
        "third/party/sub@v1": "done",
        "docker:docker://alpine:3": "done",
        "myorg/shared/.github/workflows/r.yml@main": "done",
        "does/not-exist@v1": "unresolved",
    }

    co = nodes["actions/checkout@v4"]
    assert (co["kind"], co["resolved_sha"], co["ref_source"], co["ref_version"]) == ("action", sha(2), "tag", "v4.2.1")
    shared = nodes["myorg/shared/.github/workflows/r.yml@main"]
    assert (shared["kind"], shared["ref_source"], shared["ref_version"]) == ("reusable_workflow", "branch", "v0.1.0")
    assert nodes[root]["ref_source"] == "branch"

    edges = {(e["caller_id"], e["callee_id"], e["call_site"]) for e in w.export_edges()}
    assert (root, "actions/checkout@v4", "job:build/step:0") in edges
    assert (root, "myorg/shared/.github/workflows/r.yml@main", "job:call") in edges
    assert ("third/party/sub@v1", "actions/checkout@v4", "step:0") in edges
    assert ("myorg/shared/.github/workflows/r.yml@main", "myorg/shared/.github/workflows/r.yml@main", "job:again") in edges
    assert len(edges) == 9

    # every file fetched at most once, tags once per repo, shas once per (repo, ref):
    file_calls = [c for c in graph_api.calls if c[0] == "file"]
    assert len(file_calls) == len(set(file_calls))
    tag_calls = [c for c in graph_api.calls if c[0] == "tags"]
    assert len(tag_calls) == len(set(tag_calls))
    sha_calls = [c for c in graph_api.calls if c[0] == "sha"]
    assert len(sha_calls) == len(set(sha_calls))

    # action.yml tried before action.yaml:
    assert ("file", "third", "party", "sub/action.yml", "v1") in file_calls
    assert ("file", "third", "party", "sub/action.yaml", "v1") in file_calls


def test_call_chains(tmp_path, graph_api):
    w = make_walker(tmp_path, graph_api)
    root = w.add_root("myorg", "app", WF)
    w.run()
    chains = sorted(w.call_chains_to("actions/checkout@v4"))
    shared = "myorg/shared/.github/workflows/r.yml@main"
    assert [root, "actions/checkout@v4"] in chains
    assert [root, "myorg/app/.github/actions/setup@HEAD", "third/party/sub@v1", "actions/checkout@v4"] in chains
    assert [root, shared, "third/party/sub@v1", "actions/checkout@v4"] in chains
    # the self-calling reusable workflow is reported as a cycle rather than looping:
    assert [shared, "...(cycle)", shared, "third/party/sub@v1", "actions/checkout@v4"] in chains


def test_sha_ref_classified(tmp_path):
    s = sha(7)
    api = FakeAPI(
        files={("o", "r", WF, "HEAD"): f"jobs: {{j: {{steps: [{{uses: x/y@{s}}}]}}}}",
               ("x", "y", "action.yml", s): "runs: {using: node20, main: dist/i.js}"},
        shas={("o", "r", "HEAD"): sha(1)},
        tags={("x", "y"): {"v1.0.0": s}},
    )
    w = make_walker(tmp_path, api)
    w.add_root("o", "r", WF)
    w.run()
    node = nodes_by_id(w)[f"x/y@{s}"]
    assert (node["ref_source"], node["ref_version"], node["resolved_sha"]) == ("is_sha", "v1.0.0", s)


def test_transient_error_retried_on_next_run(tmp_path, graph_api):
    graph_api.transient.add(("third", "party", "sub/action.yml", "v1"))
    w = make_walker(tmp_path, graph_api)
    w.add_root("myorg", "app", WF)
    w.run()
    errors = w.list_errors()
    assert [e["node_id"] for e in errors] == ["third/party/sub@v1"]
    assert errors[0]["retries"] == 1

    w.run()
    assert w.list_errors() == []
    assert nodes_by_id(w)["third/party/sub@v1"]["status"] == "done"
    assert w.summary() == {"done": 6, "unresolved": 1}


def test_resume_recovers_in_progress(tmp_path, graph_api):
    w = make_walker(tmp_path, graph_api)
    w.add_root("myorg", "app", WF)
    w._claim_batch(1)  # simulate being killed mid-batch
    assert w.summary() == {"in_progress": 1}

    w2 = make_walker(tmp_path, graph_api, resume=True)
    w2.run()
    assert w2.summary() == {"done": 6, "unresolved": 1}


def test_no_resume_starts_fresh(tmp_path, graph_api):
    w = make_walker(tmp_path, graph_api)
    w.add_root("myorg", "app", WF)
    w.run()
    w.mark_repo_scanned("app")
    w.db.close()

    w2 = make_walker(tmp_path, graph_api, resume=False)
    assert w2.export_nodes() == []
    assert not w2.is_repo_scanned("app")


def test_parse_error_is_unresolved(tmp_path):
    api = FakeAPI(files={("o", "r", WF, "HEAD"): "jobs: [unbalanced"}, shas={("o", "r", "HEAD"): sha(1)})
    w = make_walker(tmp_path, api)
    w.add_root("o", "r", WF)
    w.run()
    node = nodes_by_id(w)[f"o/r/{WF}@HEAD"]
    assert node["status"] == "unresolved"
    assert node["error"].startswith("parse error")


def test_add_action_root(tmp_path, graph_api):
    w = Walker(":memory:", api=graph_api, resume=False)
    root = w.add_action_root("third/party/sub@v1")
    assert root == "third/party/sub@v1"
    w.run()
    assert w.summary() == {"done": 2}
    assert w.call_chains_to("actions/checkout@v4") == [["third/party/sub@v1", "actions/checkout@v4"]]
    assert not (tmp_path / ":memory:").exists()


def test_add_action_root_reusable_workflow(graph_api):
    w = Walker(":memory:", api=graph_api)
    assert w.add_action_root("myorg/shared/.github/workflows/r.yml@main") == "myorg/shared/.github/workflows/r.yml@main"
    w.run()
    assert set(nodes_by_id(w)) == {
        "myorg/shared/.github/workflows/r.yml@main", "third/party/sub@v1", "actions/checkout@v4"}


@pytest.mark.parametrize("uses", ["./local", "docker://alpine", "not-an-action"])
def test_add_action_root_rejects_non_remote(graph_api, uses):
    with pytest.raises(ValueError):
        Walker(":memory:", api=graph_api).add_action_root(uses)
