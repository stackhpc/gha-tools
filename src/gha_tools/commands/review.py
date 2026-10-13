"""`gha review`: check allowlisted actions for known vulnerabilities, weak refs, mutability and zizmor findings."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from importlib import resources
from pathlib import Path
from subprocess import run
from typing import Optional

import yaml

from ..allowlist import final_at, read_final
from ..github import GitHubAPI
from ..identity import is_full_sha, resolve_uses, split_action_name

log = logging.getLogger(__name__)

KNOWN_VULNERABLE = "known-vulnerable-actions"


def _zizmor_config_path():
    """Path to the zizmor config bundled with this package."""
    return str(resources.files("gha_tools") / "zizmor.yml")


def _zizmor_disabled_rules() -> set[str]:
    # zizmor ignores its config for some inputs (e.g. composite actions), so filter ourselves:
    with open(_zizmor_config_path()) as f:
        cfg = yaml.safe_load(f)
    return {rule for (rule, args) in cfg["rules"].items() if (args or {}).get("disable") is True}


def _zizmor_command() -> str:
    """zizmor is a dependency, so prefer the one installed alongside this
    interpreter, which isn't on PATH if the venv isn't activated."""
    local = Path(sys.executable).parent / "zizmor"
    return str(local) if local.exists() else "zizmor"


def run_zizmor(input: str, config: Optional[str] = None) -> list[dict]:
    """Run zizmor on yaml-as-str, returning its findings."""
    config_args = [] if config is None else ["--config", config]
    cmdline = [_zizmor_command(), "--format", "json"] + config_args + ["-"]
    env = dict(os.environ)
    # zizmor's online audits (e.g. known-vulnerable-actions) need a token:
    if "GH_TOKEN" not in env and "GITHUB_TOKEN" in env:
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    zp = run(cmdline, input=input, capture_output=True, text=True, env=env)
    if zp.returncode not in [0, 11, 12, 13, 14]:  # https://docs.zizmor.sh/usage/#exit-codes
        sys.exit(f"  FATAL error from zizmor: [{zp.returncode}]:\n{zp.stderr}")
    return json.loads(zp.stdout or "[]")


def format_finding(finding: dict) -> str:
    annotations = [
        loc["symbolic"].get("annotation", "")
        for loc in finding.get("locations", [])
        if loc.get("symbolic", {}).get("kind") == "Primary"
    ]
    detail = f" ({'; '.join(a for a in annotations if a)})" if any(annotations) else ""
    return f"zizmor [{finding['ident']}]: {finding['desc']}{detail}"


def batch_zizmor(entries: list[str], disabled: set[str]) -> dict[str, list[dict]]:
    """Run zizmor once over a fake composite action calling every entry,
    returning {entry: [findings about its `uses:` line]}."""
    steps = [f"    - uses: {uses}" for uses in entries]
    fake_action = "\n".join(["name: fake", "description: fake", "runs:", "  using: composite", "  steps:"] + steps)
    by_entry: dict[str, list[dict]] = {uses: [] for uses in entries}
    for finding in run_zizmor(fake_action, config=_zizmor_config_path()):
        # unpinned-uses duplicates our own weak ref check:
        if finding["ident"] in disabled or finding["ident"] == "unpinned-uses":
            continue
        for loc in finding.get("locations", []):
            route = loc.get("symbolic", {}).get("route", {}).get("route", [])
            indexes = [r["Index"] for r in route if "Index" in r]
            if loc["symbolic"].get("kind") == "Primary" and indexes:
                by_entry[entries[indexes[0]]].append(finding)
                break
    return by_entry


def get_action_metadata(api: GitHubAPI, action_name: str, action_ref: str) -> str:
    """Return the metadata file (i.e. the actual action.y*ml) as yaml str

    See https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax#runs-for-composite-actions
    for its syntax.
    """
    owner, repo, path = split_action_name(action_name)
    listing = api.list_dir(owner, repo, path, action_ref)
    metadata_files = [f["name"] for f in listing if f["name"].startswith("action.y")]
    if len(metadata_files) != 1:
        sys.exit(f"  FATAL found {len(metadata_files)} action metadata files for {action_name}@{action_ref}")
    return api.get_file_text(owner, repo, f"{path}/{metadata_files[0]}".lstrip("/"), action_ref)


def review_action_metadata(api: GitHubAPI, owner: str, repo: str, path: str, ref: str, action_yml: str) -> None:
    """Check for specific mutability things depending on action type."""
    action_data = yaml.safe_load(action_yml)
    using = str(action_data["runs"]["using"])
    if using == "docker":
        print("  using: docker")
        image = action_data["runs"]["image"]
        if image == "Dockerfile":
            baseimage = None
            dockerfile = api.get_file_text(owner, repo, f"{path}/Dockerfile".lstrip("/"), ref)
            for line in dockerfile.splitlines():
                if line.strip().upper().startswith("FROM"):
                    baseimage = line.split(maxsplit=1)[-1]
                    break
            if not re.search(r"@sha256:[a-fA-F0-9]{64}", baseimage or ""):
                print(f"  WARNING base image not pinned to sha: {baseimage}")
            else:
                print(f"  baseimage ok: {baseimage}")
        else:
            # Zizmor should be able to catch this in pedantic persona
            # but https://github.com/zizmorcore/zizmor/issues/1942
            if "@" not in image or not re.search(r"@sha256:[a-fA-F0-9]{64}", image):
                print(f"  WARNING image not pinned to sha: {image}")

    elif using.startswith("node"):
        print(f"  using: {using}")
        main = action_data["runs"]["main"]
        if main.split("/")[0] not in ["dist", "lib", "out"]:
            print(f"  WARNING entry unbundled: {main}")

    elif using == "composite":
        print("  using: composite")

    else:
        raise ValueError(using)


def review_entry(api: GitHubAPI, uses: str, info: dict, findings: list[dict], disabled: set[str]) -> None:
    ident = resolve_uses(uses)
    owner, repo, path, ref = ident.owner, ident.repo, ident.path, ident.ref
    version = info.get("version") or ""
    fetch_ref = info.get("sha") or ref

    print(f"\n{uses}" + (f" ({version})" if version else "") + ":")
    if not is_full_sha(ref):
        print(f"  WARNING weak reference: {info.get('ref_source') or 'not a SHA'}")
    for finding in findings:
        print(f"  {'FAIL' if finding['ident'] == KNOWN_VULNERABLE else 'WARNING'} {format_finding(finding)}")

    # Check version for mutability:
    if not version:
        print("  WARNING no version specified")
    else:
        release = api.get_release(owner, repo, version)
        if release is None:
            print("  WARNING release not found!")
        elif not release["immutable"]:
            print("  WARNING release is mutable")

    if ident.kind == "reusable_workflow":
        print("  reusable workflow")
        content = api.get_file_text(owner, repo, path, fetch_ref)
    else:
        content = get_action_metadata(api, f"{owner}/{repo}/{path}".rstrip("/"), fetch_ref)
        review_action_metadata(api, owner, repo, path, fetch_ref, content)

    # Run a limited zizmor scan on JUST the action.y{a,}ml / workflow file:
    for finding in run_zizmor(content):
        if finding["ident"] not in disabled:
            print(f"  {format_finding(finding)}")


def review(api: GitHubAPI, entries: dict[str, dict]) -> list[str]:
    """Review {uses: final.json info}. Returns the known-vulnerable entries."""
    if not entries:
        print("\nNothing to review.")
        return []
    if os.environ.get("ZIZMOR_OFFLINE", "").lower() in ("1", "true", "yes"):
        log.warning("ZIZMOR_OFFLINE is set: known-vulnerable-actions and other online audits are NOT being run")
    disabled = _zizmor_disabled_rules()
    names = sorted(entries)
    print(f"\nRunning zizmor against {len(names)} entries ...")
    findings = batch_zizmor(names, disabled)
    for uses in names:
        review_entry(api, uses, entries[uses], findings[uses], disabled)
    return [uses for uses in names if any(f["ident"] == KNOWN_VULNERABLE for f in findings[uses])]


def review_org(api: GitHubAPI, org: str, base: Optional[str] = None) -> int:
    """Review all of an org's final.txt, or (with base) only entries added
    since that git ref. Returns an exit status: 1 if any reviewed entry is
    known-vulnerable."""
    current, info = read_final(org)
    removed: set[str] = set()
    if base is None:
        to_review = current
    else:
        previous = final_at(org, base)
        to_review = current - previous
        removed = previous - current
        print(f"Comparing against {base}: {len(to_review)} added, {len(removed)} removed")

    vulnerable = review(api, {uses: info.get(uses, {}) for uses in to_review})

    if base is not None:
        print("\nAdded entries:" if to_review else "\nNo added entries.")
        for uses in sorted(to_review):
            print(f"  + {uses}")
        print("\nRemoved entries (delete these from the allowlist in the GitHub UI):" if removed else "\nNo removed entries.")
        for uses in sorted(removed):
            print(f"  - {uses}")
    if vulnerable:
        print("\nFAIL: known-vulnerable entries:")
        for uses in vulnerable:
            print(f"  {uses}")
        return 1
    return 0


def review_single(api: GitHubAPI, target: str) -> int:
    """Review a single action@ref, without its dependencies."""
    ident = resolve_uses(target)
    if ident.kind not in ("action", "reusable_workflow"):
        sys.exit(f"FATAL: {target!r} is not owner/repo[/path]@ref")
    info = {} if is_full_sha(ident.ref) else {"version": ident.ref}
    return 1 if review(api, {target: info}) else 0
