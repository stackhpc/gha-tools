"""`gha review`: check allowlisted actions for known vulnerabilities, weak refs, mutability and zizmor findings,
and optionally (by AI) for signs of compromise."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from subprocess import run
from typing import Optional

import yaml

from ..aireview import ERROR, SKIPPED, SUSPICIOUS, AIReviewError, ai_review, format_verdict
from ..allowlist import final_at, read_final
from ..github import GitHubAPI, GitHubAPIError, NotFound, get_action_metadata
from ..identity import is_full_sha, resolve_uses

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


class EntryError(Exception):
    """An entry which could not be reviewed (as opposed to one which failed review)."""


@dataclass
class EntryReview:
    """The result of reviewing one entry."""
    vulnerable: bool = False  # known-vulnerable, according to zizmor
    ai: Optional[str] = None  # AI review outcome (CLEAN, SUSPICIOUS, ERROR, SKIPPED), None if not run
    error: Optional[str] = None  # why the entry could not be reviewed

    @property
    def ai_failed(self) -> bool:
        return self.ai in (SUSPICIOUS, ERROR)

    @property
    def failed(self) -> bool:
        return self.vulnerable or self.ai_failed or self.error is not None


def review_entry(
    api: GitHubAPI, uses: str, info: dict, findings: list[dict], disabled: set[str], ai: bool = False,
) -> EntryReview:
    ident = resolve_uses(uses)
    owner, repo, path, ref = ident.owner, ident.repo, ident.path, ident.ref
    version = info.get("version") or ""
    fetch_ref = info.get("sha") or ref

    print(f"\n{uses}" + (f" ({version})" if version else "") + ":")
    if not is_full_sha(ref):
        print(f"  WARNING weak reference: {info.get('ref_source') or 'not a SHA'}")
    for finding in findings:
        print(f"  {'FAIL' if finding['ident'] == KNOWN_VULNERABLE else 'WARNING'} {format_finding(finding)}")
    result = EntryReview(vulnerable=any(f["ident"] == KNOWN_VULNERABLE for f in findings))

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
        try:
            content = get_action_metadata(api, owner, repo, path, fetch_ref)
        except NotFound:
            raise EntryError(f"no action metadata file found for {owner}/{repo}/{path}@{fetch_ref}")
        review_action_metadata(api, owner, repo, path, fetch_ref, content)

    # Run a limited zizmor scan on JUST the action.y{a,}ml / workflow file:
    for finding in run_zizmor(content):
        if finding["ident"] not in disabled:
            print(f"  {format_finding(finding)}")

    if not ai:
        return result
    if not is_full_sha(ref):  # NOT fetch_ref: a mutable ref is not reviewed, even if resolved to a sha
        result.ai = SKIPPED
        print(f"  AI review: {SKIPPED}: unpinned")
        return result
    try:
        verdict = ai_review(api, owner, repo, path, fetch_ref, ident.kind)
    except AIReviewError as e:
        result.ai = ERROR
        print(f"  AI review: {ERROR}: {' '.join(str(e).split())}")
        return result
    result.ai = verdict["verdict"]
    print("\n".join(format_verdict(verdict)), flush=True)
    return result


def review(api: GitHubAPI, entries: dict[str, dict], ai: bool = False) -> dict[str, EntryReview]:
    """Review {uses: final.json info}, returning {uses: result}. Every entry is reviewed even if some fail
    or can't be reviewed, so that all the problems are reported."""
    if not entries:
        print("\nNothing to review.")
        return {}
    if os.environ.get("ZIZMOR_OFFLINE", "").lower() in ("1", "true", "yes"):
        log.warning("ZIZMOR_OFFLINE is set: known-vulnerable-actions and other online audits are NOT being run")
    disabled = _zizmor_disabled_rules()
    names = sorted(entries)
    print(f"\nRunning zizmor against {len(names)} entries ...")
    findings = batch_zizmor(names, disabled)
    results = {}
    for uses in names:
        try:
            results[uses] = review_entry(api, uses, entries[uses], findings[uses], disabled, ai)
        except (EntryError, GitHubAPIError) as e:
            print(f"  FAIL could not review: {e}")
            results[uses] = EntryReview(
                vulnerable=any(f["ident"] == KNOWN_VULNERABLE for f in findings[uses]), error=str(e))
    return results


def report_failures(results: dict[str, EntryReview]) -> int:
    """Print the entries which failed review. Returns an exit status: 1 if there are any."""
    for heading, failed in (
        ("known-vulnerable entries", [uses for uses, r in results.items() if r.vulnerable]),
        ("entries which could not be reviewed", [uses for uses, r in results.items() if r.error is not None]),
        ("entries failing AI review", [uses for uses, r in results.items() if r.ai_failed]),
    ):
        if failed:
            print(f"\nFAIL: {heading}:")
            for uses in failed:
                print(f"  {uses}")
    return 1 if any(r.failed for r in results.values()) else 0


def review_org(api: GitHubAPI, org: str, base: Optional[str] = None, ai: bool = False) -> int:
    """Review all of an org's final.txt, or (with base) only entries added
    since that git ref. Returns an exit status: 1 if any reviewed entry fails."""
    current, info = read_final(org)
    return review_final(api, org, current, info, base, ai)


def review_final(
    api: GitHubAPI, org: str, current: set[str], info: dict, base: Optional[str] = None, ai: bool = False,
) -> int:
    """As review_org, but for final.txt entries and final.json info which
    have not necessarily been written yet."""
    removed: set[str] = set()
    if base is None:
        to_review = current
    else:
        previous = final_at(org, base)
        to_review = current - previous
        removed = previous - current
        print(f"Comparing against {base}: {len(to_review)} added, {len(removed)} removed")

    results = review(api, {uses: info.get(uses, {}) for uses in to_review}, ai)

    if base is not None:
        print("\nAdded entries:" if to_review else "\nNo added entries.")
        for uses in sorted(to_review):
            print(f"  + {uses}")
        print("\nRemoved entries (these are dropped when ORG.final.txt is pasted into the GitHub UI):" if removed else "\nNo removed entries.")
        for uses in sorted(removed):
            print(f"  - {uses}")
    return report_failures(results)


def review_single(api: GitHubAPI, target: str, ai: bool = False) -> int:
    """Review a single action@ref, without its dependencies."""
    ident = resolve_uses(target)
    if ident.kind not in ("action", "reusable_workflow"):
        sys.exit(f"FATAL: {target!r} is not owner/repo[/path]@ref")
    info = {} if is_full_sha(ident.ref) else {"version": ident.ref}
    return report_failures(review(api, {target: info}, ai))
