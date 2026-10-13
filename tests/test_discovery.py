"""Finding an org's repos and their in-use workflows."""

import re

import pytest

from gha_tools import discovery
from gha_tools.github import NotFound


class FakeAPI:
    def __init__(self, get=None, paginated=None, existing=(), branch_files=()):
        self._get = get or {}
        self._paginated = paginated or {}
        self.existing = set(existing)          # URLs that HEAD 200
        self.branch_files = set(branch_files)  # "branch:path" present in the repo
        self.graphql_queries = []

    def get(self, url, **params):
        result = self._get[url]
        if isinstance(result, Exception):
            raise result
        return result

    def get_paginated(self, url, **params):
        return self._paginated[url]

    def exists(self, url):
        return url in self.existing

    def graphql(self, query):
        self.graphql_queries.append(query)
        fields = re.findall(r'(\w+): object\(expression: "([^"]*)"\)', query)
        return {"repository": {a: ({"oid": "x"} if e in self.branch_files else None) for a, e in fields}}


def wf(path, state="active"):
    return {"path": path, "state": state}


def repo_api(enabled=True, permissions_error=None, workflows=(), runs=1):
    perms = permissions_error or {"enabled": enabled}
    return FakeAPI(get={
        "repos/o/r/actions/permissions": perms,
        "repos/o/r/actions/workflows": {"workflows": list(workflows)},
        "repos/o/r/actions/runs": {"total_count": runs},
    })


def test_list_org_repos_skips_archived_and_sorts():
    api = FakeAPI(paginated={"orgs/o/repos": [
        {"name": "zeta", "archived": False},
        {"name": "old", "archived": True},
        {"name": "alpha", "archived": False},
    ]})
    assert discovery.list_org_repos(api, "o") == ["alpha", "zeta"]


def test_active_workflows_filters():
    api = repo_api(workflows=[
        wf(".github/workflows/ci.yml"),
        wf(".github/workflows/old.yml", state="disabled_manually"),
        wf("dynamic/dependabot/dependabot-updates"),
    ])
    assert discovery.get_active_workflows(api, "o", "r") == [".github/workflows/ci.yml"]


def test_actions_disabled_skips_repo():
    """Needs admin to see; a token without it gets 403 and assumes enabled."""
    api = repo_api(enabled=False, workflows=[wf(".github/workflows/ci.yml")])
    assert discovery.get_active_workflows(api, "o", "r") == []


@pytest.mark.parametrize("status", [401, 403, 404])
def test_no_permission_to_check_assumes_enabled(status):
    api = repo_api(permissions_error=NotFound("nope", status), workflows=[wf(".github/workflows/ci.yml")])
    assert discovery.get_active_workflows(api, "o", "r") == [".github/workflows/ci.yml"]


def test_other_permission_errors_propagate():
    api = repo_api(permissions_error=NotFound("teapot", 418))
    with pytest.raises(NotFound):
        discovery.get_active_workflows(api, "o", "r")


def test_no_runs_skips_repo():
    api = repo_api(workflows=[wf(".github/workflows/ci.yml")], runs=0)
    assert discovery.get_active_workflows(api, "o", "r") == []


def test_find_workflows_default_branch_then_other_branches(monkeypatch):
    monkeypatch.setattr(discovery, "GRAPHQL_BATCH_SIZE", 3)
    api = FakeAPI(
        existing={"repos/o/r/contents/.github/workflows/main.yml"},
        paginated={"repos/o/r/branches": [{"name": n} for n in ["a", "b", "c", "d"]]},
        branch_files={"c:.github/workflows/feat.yml", "d:.github/workflows/feat.yml",
                      "b:.github/workflows/other.yml"},
    )
    found = discovery.find_workflows(
        api, "o", "r", [".github/workflows/main.yml", ".github/workflows/feat.yml",
                        ".github/workflows/other.yml", ".github/workflows/gone.yml"])
    assert sorted(found, key=lambda t: t[2]) == [
        ("o", "r", ".github/workflows/feat.yml", "c"),   # first branch in API order wins
        ("o", "r", ".github/workflows/main.yml", None),  # default branch
        ("o", "r", ".github/workflows/other.yml", "b"),
    ]
    # batched (3 per query) and deterministic, never re-asking for found paths:
    assert len(api.graphql_queries) == 4
    assert all(q.count("object(") <= 3 for q in api.graphql_queries)
    assert "b:.github/workflows/other.yml" not in "".join(api.graphql_queries[2:])
