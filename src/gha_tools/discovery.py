"""Find an organisation's repos and the workflows in them that are actually in use."""

from __future__ import annotations

import logging

from .github import GitHubAPI, NotFound

log = logging.getLogger(__name__)

GRAPHQL_BATCH_SIZE = 300  # keep individual queries a sane size


def list_org_repos(api: GitHubAPI, org: str) -> list[str]:
    """Sorted names of all non-archived repos in org."""
    repos = api.get_paginated(f"orgs/{org}/repos")
    return sorted(r["name"] for r in repos if not r["archived"])


def get_active_workflows(api: GitHubAPI, org: str, repo_name: str) -> list[str]:
    """Returns a list of workflow paths"""

    # filter for enabled workflows (needs org admin):
    try:
        enabled = api.get(f"repos/{org}/{repo_name}/actions/permissions")["enabled"]
    except NotFound as e:
        if e.status in (401, 403, 404):  # not admin on repo or owner of org, have to assume they are enabled
            enabled = True
        else:
            raise
    if not enabled:
        log.debug(f"  Skipping {repo_name}: workflows disabled")
        return []

    # filter for active workflows:
    all_workflows = api.get(f"repos/{org}/{repo_name}/actions/workflows")["workflows"]
    real_workflows = [wf for wf in all_workflows if not wf["path"].startswith("dynamic/")]
    active_workflows = [wf for wf in real_workflows if wf["state"] == "active"]
    if not active_workflows:
        log.debug(f"  Skipping {repo_name}: no active workflows")
        return []

    # filter for repo has workflow runs:
    # is a warning b/c really we'd rather use the enabled check
    runs = api.get(f"repos/{org}/{repo_name}/actions/runs")
    if runs["total_count"] == 0:
        log.warning(f"  Skipping {repo_name} as 0 workflow runs in repo")
        return []

    return [wf["path"] for wf in active_workflows]


def find_workflows(api: GitHubAPI, org: str, repo_name: str, paths: list[str]) -> list[tuple]:
    """Find a branch for all specified workflow paths. Returns a list of
    (org, repo_name, path, branch_name) tuples, where branch_name may be None for
    the default branch. Other branches are tried shortest name first. Note this does NOT find all content-unique workflows,
    just a "representative" for each path.
    """

    results = {}
    # Check if workflows are available on default branch:
    for path in paths:
        if api.exists(f"repos/{org}/{repo_name}/contents/{path}"):
            results[path] = (org, repo_name, path, None)

    missing_paths = set(paths) - set(results)

    # Find a branch for each missing workflow. Batch-check existence of every
    # (branch, missing path) combination in one (or a few, chunked) GraphQL
    # queries via aliasing
    if missing_paths:
        # Shortest names first (then alphabetical), as short names are likelier to be
        # long-lived branches like "main" or "dev" rather than e.g. "feature/foo-bar".
        branches = sorted((r["name"] for r in api.get_paginated(f"repos/{org}/{repo_name}/branches")),
                          key=lambda name: (len(name), name))
        combos = [(b, p) for b in branches for p in sorted(missing_paths)]
        for i in range(0, len(combos), GRAPHQL_BATCH_SIZE):
            if not missing_paths:
                break
            chunk = [(b, p) for b, p in combos[i:i + GRAPHQL_BATCH_SIZE] if p in missing_paths]
            if not chunk:
                continue
            fields = "\n".join(
                f'a{j}: object(expression: "{branch}:{path}") {{ oid }}'
                for j, (branch, path) in enumerate(chunk)
            )
            data = api.graphql(f'query {{ repository(owner: "{org}", name: "{repo_name}") {{ {fields} }} }}')
            repo_data = data["repository"]
            for j, (branch, path) in enumerate(chunk):
                if repo_data[f"a{j}"] is not None and path in missing_paths:
                    log.debug(f"  Found workflow for {path} on {branch}")
                    missing_paths.discard(path)
                    results[path] = (org, repo_name, path, branch)

    if missing_paths:
        log.warning(f"  Workflows not found on any branch:{','.join(sorted(missing_paths))}")

    return list(results.values())


def get_repo_workflows(api: GitHubAPI, org: str, repo: str) -> list[tuple]:
    """(org, repo, path, ref) tuples for all active workflows in a repo, where
    ref None is the default branch."""
    paths = get_active_workflows(api, org, repo)
    return find_workflows(api, org, repo, paths)
