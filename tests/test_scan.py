"""`gha scan` output suitable for ORG.actions.txt."""

from gha_tools.commands.scan import format_actions_txt, summarise
from gha_tools.walker import Walker
from test_walker import FakeAPI, WF, make_walker, sha


def test_format_actions_txt(tmp_path):
    api = FakeAPI(
        files={
            ("org", "app", WF, "HEAD"): f"""
                jobs:
                  a:
                    steps:
                      - uses: foo/bar@v1
                      - uses: actions/checkout@v4
                      - uses: ./.github/actions/setup
                      - uses: org/shared/.github/workflows/w.yml@main
            """,
            ("org", "shared", ".github/workflows/w.yml", "main"): f"""
                jobs:
                  b:
                    steps:
                      - uses: deep/dep@{sha(9)}
            """,
            ("org", "app", ".github/actions/setup/action.yml", "HEAD"): "runs: {using: node20, main: dist/i.js}",
            ("foo", "bar", "action.yml", "v1"): "runs: {using: node20, main: dist/i.js}",
            ("deep", "dep", "action.yml", sha(9)): "runs: {using: node20, main: dist/i.js}",
        },
        shas={("org", "app", "HEAD"): sha(3), ("foo", "bar", "v1"): sha(1), ("org", "shared", "main"): sha(2)},
        tags={("foo", "bar"): {"v1": sha(1)}},
    )
    w = make_walker(tmp_path, api, org="org")
    w.add_root("org", "app", WF)
    w.run()

    out = format_actions_txt(w, "org").splitlines()
    assert out[0] == ""
    assert out[1].startswith("# --- Start of org.actions.txt")
    assert out[2:] == [
        f"foo/bar@v1, # v1 (not a SHA: currently {sha(1)})",
        "org/shared/.github/workflows/w.yml@main,",
    ]  # no local ./.github/actions/setup; no deep/dep: only called via org/shared, so found by `gha update`


def test_summarise_includes_reusable_workflows(tmp_path):
    api = FakeAPI(
        files={
            ("org", "app", WF, "HEAD"): """
                jobs:
                  a:
                    uses: ext/wf/.github/workflows/w.yml@v1
            """,
            ("ext", "wf", ".github/workflows/w.yml", "v1"): "jobs: {}",
        },
        shas={("org", "app", "HEAD"): sha(3), ("ext", "wf", "v1"): sha(1)},
    )
    w = make_walker(tmp_path, api, org="org")
    w.add_root("org", "app", WF)
    w.run()

    actions, calls = summarise(w, "org")
    assert actions["ext/wf/.github/workflows/w.yml"]["v1"]["repos"] == ["app"]
    assert "ext/wf/.github/workflows/w.yml@v1" in calls
