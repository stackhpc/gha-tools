"""`gha scan`: find every action used, directly or indirectly, by an org's active workflows."""

from __future__ import annotations

import json
import logging
from typing import Optional

from ..allowlist import FINAL_KINDS, is_github_owned
from ..discovery import get_repo_workflows, list_org_repos
from ..github import GitHubAPI
from ..identity import is_org_owned
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

    print(format_actions_txt(walker, org), end="")


def format_actions_txt(walker: Walker, org: str) -> str:
    """Text for `ORG.actions.txt`: every non-GitHub action/reusable workflow
    (including the org's own) called directly by a workflow. Things only
    called by other actions/reusable workflows are left out, as `gha update`
    finds them by walking the entries which call them.
    Everything from the marker line onwards can be copied into the file."""
    nodes = walker.export_nodes()
    roots = {n["node_id"]: n for n in nodes if n["kind"] == "workflow_root"}

    def called_remotely_by_root(node: dict) -> bool:
        # A `uses: ./path` is resolved to the calling repo and ref, so is
        # indistinguishable from (and treated as) a call into its own repo at
        # that ref. Those are always allowed, so are left out.
        return any(
            (roots[c]["owner"], roots[c]["repo"], roots[c]["ref"]) != (node["owner"], node["repo"], node["ref"])
            for c in walker.callers_of(node["node_id"]) if c in roots
        )

    entries = []
    for node in nodes:
        if node["kind"] not in FINAL_KINDS or is_github_owned(node["owner"]):
            continue
        if not called_remotely_by_root(node):
            continue
        internal = is_org_owned(node["owner"], org)
        comments = []
        if node["ref_version"]:
            comments.append(node["ref_version"])
        if node["ref_source"] != "is_sha" and not internal and node["resolved_sha"]:
            comments.append(f"(not a SHA: currently {node['resolved_sha']})")
        entries.append((internal, node["node_id"], " ".join(comments)))

    lines = ["", f"# --- Start of {org}.actions.txt content: copy from here ---"]
    for internal, uses, comment in sorted(entries):
        lines.append(f"{uses}," + (f" # {comment}" if comment else ""))
    return "\n".join(lines) + "\n"


def summarise(walker: Walker, org: str) -> tuple[dict, dict]:
    """Returns (actions, calls) for all actions and reusable workflows from outside org:
    actions: {address: {ref: {repos, sha, source, version}}}
    calls:   {address@ref: [call chain, ...]}, each chain a list of node_ids
             from a root workflow down to (but excluding) the action itself
    """
    actions_output: dict = {}
    calls_output: dict = {}

    for node in walker.export_nodes():
        if node["kind"] in FINAL_KINDS and node["owner"] != org:
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
