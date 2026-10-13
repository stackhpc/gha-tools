"""`gha scan`: find every action used, directly or indirectly, by an org's active workflows."""

from __future__ import annotations

import json
import logging
from typing import Optional

from ..discovery import get_repo_workflows, list_org_repos
from ..github import GitHubAPI
from ..walker import Walker

log = logging.getLogger(__name__)


def scan(api: GitHubAPI, org: str, repo: Optional[str] = None, resume: bool = False) -> None:
    if repo is None:
        log.info("Finding relevant repos ...")
        org_repos = list_org_repos(api, org)
    else:
        org_repos = [repo]
    log.info(f"Processing {len(org_repos)} non-archived repos")

    walker = Walker(f"{org}.db", api=api, resume=resume, org=org)
    for repo in org_repos:
        if walker.is_repo_scanned(repo):
            log.info(f"  {repo}: already scanned, skipping")
            continue
        workflows = get_repo_workflows(api, org, repo)
        log.info(f"  {repo}: Got {len(workflows)} workflows")
        for wf in workflows:
            walker.add_root(*wf)
        walker.mark_repo_scanned(repo)
    log.info("Processing call graph ...")
    walker.run()

    actions_output, calls_output = summarise(walker, org)
    with open(f"{org}.json", "w") as f_json:
        json.dump(actions_output, f_json, indent=2)
    with open(f"{org}.calls.json", "w") as f_calls:
        json.dump(calls_output, f_calls, indent=2)


def summarise(walker: Walker, org: str) -> tuple[dict, dict]:
    """Returns (actions, calls) for all actions from outside org:
    actions: {address: {ref: {repos, sha, source, version}}}
    calls:   {address@ref: [call chain, ...]}, each chain a list of node_ids
             from a root workflow down to (but excluding) the action itself
    """
    actions_output: dict = {}
    calls_output: dict = {}

    for node in walker.export_nodes():
        if node["kind"] == "action" and node["owner"] != org:
            ref = node["ref"]
            chains = walker.call_chains_to(node["node_id"])

            caller_org_repos = set()
            for chain in chains:
                last_org, last_repo = chain[-2].split("/", maxsplit=2)[:2]
                if last_org == org:
                    caller_org_repos.add(last_repo)
            address = f"{node['owner']}/{node['repo']}"
            address += f"/{node['path']}" if node["path"] else ""

            actions_output.setdefault(address, {})[ref] = {
                "repos": sorted(caller_org_repos),
                "sha": node["resolved_sha"],
                "source": node["ref_source"],
                "version": node["ref_version"],
            }
            calls_output[f"{address}@{ref}"] = sorted(chain[:-1] for chain in chains)  # :-1 to not re-list the action itself

    return actions_output, calls_output
