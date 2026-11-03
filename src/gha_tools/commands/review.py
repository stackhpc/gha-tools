"""`gha review`: check allowlisted actions for known vulnerabilities, weak refs, mutability, zizmor findings
and (by AI) signs of compromise."""

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
from ..allowlist import read_final, review_txt_path
from ..github import GitHubAPI, NotFound, get_action_metadata
from ..identity import is_full_sha, resolve_uses
from ..reviewfile import has_ai_review, is_blocking, read_review, write_review

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


def review_action_metadata(api: GitHubAPI, owner: str, repo: str, path: str, ref: str, action_yml: str) -> list[str]:
    """Check for specific mutability things depending on action type, returning the lines to report."""
    lines = []
    action_data = yaml.safe_load(action_yml)
    using = str(action_data["runs"]["using"])
    if using == "docker":
        lines.append("  using: docker")
        image = action_data["runs"]["image"]
        if image == "Dockerfile":
            baseimage = None
            dockerfile = api.get_file_text(owner, repo, f"{path}/Dockerfile".lstrip("/"), ref)
            for line in dockerfile.splitlines():
                if line.strip().upper().startswith("FROM"):
                    baseimage = line.split(maxsplit=1)[-1]
                    break
            if not re.search(r"@sha256:[a-fA-F0-9]{64}", baseimage or ""):
                lines.append(f"  WARNING base image not pinned to sha: {baseimage}")
            else:
                lines.append(f"  baseimage ok: {baseimage}")
        else:
            # Zizmor should be able to catch this in pedantic persona
            # but https://github.com/zizmorcore/zizmor/issues/1942
            if "@" not in image or not re.search(r"@sha256:[a-fA-F0-9]{64}", image):
                lines.append(f"  WARNING image not pinned to sha: {image}")

    elif using.startswith("node"):
        lines.append(f"  using: {using}")
        main = action_data["runs"]["main"]
        if main.split("/")[0] not in ["dist", "lib", "out"]:
            lines.append(f"  WARNING entry unbundled: {main}")

    elif using == "composite":
        lines.append("  using: composite")

    else:
        raise ValueError(using)
    return lines


@dataclass
class EntryReview:
    """The result of reviewing one entry."""
    lines: list[str]  # the review block as printed, starting with its unindented header line
    ai: Optional[str] = None  # AI review outcome (CLEAN, SUSPICIOUS, ERROR, SKIPPED), None if not run
    vulnerable: bool = False  # known-vulnerable, according to zizmor

    @property
    def failed(self) -> bool:
        return self.vulnerable or self.ai in (SUSPICIOUS, ERROR)


def review_entry(
    api: GitHubAPI, uses: str, info: dict, findings: list[dict], disabled: set[str], ai: bool = True,
) -> EntryReview:
    """Review one entry, printing the review block as it is produced and returning it."""
    ident = resolve_uses(uses)
    owner, repo, path, ref = ident.owner, ident.repo, ident.path, ident.ref
    version = info.get("version") or ""
    fetch_ref = info.get("sha") or ref

    lines: list[str] = []

    def emit(text: str, header: bool = False) -> None:
        # Block lines are one per line and indented, so they can't be mistaken for a header:
        for line in text.splitlines() or [""]:
            line = line.rstrip()
            if not header and not line.startswith(" "):
                line = "  " + line
            lines.append(line)
            print(line, flush=True)

    print()
    emit(f"{uses}" + (f" ({version})" if version else "") + ":", header=True)
    if not is_full_sha(ref):
        emit(f"  WARNING weak reference: {info.get('ref_source') or 'not a SHA'}")
    for finding in findings:
        emit(f"  {'FAIL' if finding['ident'] == KNOWN_VULNERABLE else 'WARNING'} {format_finding(finding)}")

    # Check version for mutability:
    if not version:
        emit("  WARNING no version specified")
    else:
        release = api.get_release(owner, repo, version)
        if release is None:
            emit("  WARNING release not found!")
        elif not release["immutable"]:
            emit("  WARNING release is mutable")

    if ident.kind == "reusable_workflow":
        emit("  reusable workflow")
        content = api.get_file_text(owner, repo, path, fetch_ref)
    else:
        try:
            content = get_action_metadata(api, owner, repo, path, fetch_ref)
        except NotFound:
            sys.exit(f"  FATAL no action metadata file found for {owner}/{repo}/{path}@{fetch_ref}")
        for line in review_action_metadata(api, owner, repo, path, fetch_ref, content):
            emit(line)

    # Run a limited zizmor scan on JUST the action.y{a,}ml / workflow file:
    for finding in run_zizmor(content):
        if finding["ident"] not in disabled:
            emit(f"  {format_finding(finding)}")

    result = EntryReview(lines, vulnerable=any(f["ident"] == KNOWN_VULNERABLE for f in findings))
    if not ai:
        return result
    if not is_full_sha(ref):  # NOT fetch_ref: a mutable ref is not reviewed, even if resolved to a sha
        result.ai = SKIPPED
        emit(f"  AI review: {SKIPPED}: unpinned")
        return result
    try:
        verdict = ai_review(api, owner, repo, path, fetch_ref, ident.kind)
    except AIReviewError as e:
        result.ai = ERROR
        emit(f"  AI review: {ERROR}: {' '.join(str(e).split())}")
        return result
    result.ai = verdict["verdict"]
    for line in format_verdict(verdict):
        emit(line)
    return result


def review(api: GitHubAPI, entries: dict[str, dict], ai: bool = True) -> dict[str, EntryReview]:
    """Review {uses: final.json info}, returning {uses: result}."""
    if not entries:
        print("\nNothing to review.")
        return {}
    if os.environ.get("ZIZMOR_OFFLINE", "").lower() in ("1", "true", "yes"):
        log.warning("ZIZMOR_OFFLINE is set: known-vulnerable-actions and other online audits are NOT being run")
    disabled = _zizmor_disabled_rules()
    names = sorted(entries)
    print(f"\nRunning zizmor against {len(names)} entries ...")
    findings = batch_zizmor(names, disabled)
    return {uses: review_entry(api, uses, entries[uses], findings[uses], disabled, ai) for uses in names}


def report_failures(results: dict[str, EntryReview]) -> int:
    """Print the entries which failed review. Returns an exit status: 1 if there are any."""
    vulnerable = [uses for uses, r in results.items() if r.vulnerable]
    ai_failed = [uses for uses, r in results.items() if r.ai in (SUSPICIOUS, ERROR)]
    if vulnerable:
        print("\nFAIL: known-vulnerable entries:")
        for uses in vulnerable:
            print(f"  {uses}")
    if ai_failed:
        print("\nFAIL: entries failing AI review:")
        for uses in ai_failed:
            print(f"  {uses}")
    return 1 if vulnerable or ai_failed else 0


def review_and_record(api: GitHubAPI, org: str, final: dict, force: bool = False, ai: bool = True) -> int:
    """Review the entries of final ({uses: final.json info}) which have no block in ORG.review.txt yet (or all
    of them, if force), and record the results there. Blocks for entries no longer in final are dropped, and
    the others are kept as they are. With ai, a block must also have an AI review in it to count (so an entry
    reviewed with --no-ai is reviewed again); without, any block counts. Returns an exit status: non-zero if any entry fails review."""
    stored = read_review(org)
    added = sorted(final if force else {
        uses for uses in final if uses not in stored or (ai and not has_ai_review(stored[uses]))})
    removed = sorted(stored.keys() - set(final))
    print(f"Comparing against {review_txt_path(org)}: {len(added)} to review{' (forced)' if force else ''}, {len(removed)} removed")

    results = review(api, {uses: final[uses] for uses in added}, ai)

    blocks = {uses: lines for uses, lines in stored.items() if uses in final and uses not in added}
    for uses, result in results.items():
        # Not recorded, so that they are reviewed again next time: known-vulnerable (fix by changing the
        # entry) and ERROR (no result). A SUSPICIOUS review IS recorded, so that it can be overridden.
        if not result.vulnerable and result.ai != ERROR:
            blocks[uses] = result.lines
    write_review(org, blocks)

    print("\nReviewed entries:" if added else "\nNo entries to review.")
    for uses in added:
        print(f"  + {uses}")
    print("\nRemoved entries (these are dropped when ORG.final.txt is pasted into the GitHub UI):"
          if removed else "\nNo removed entries.")
    for uses in removed:
        print(f"  - {uses}")

    vulnerable = [uses for uses, r in results.items() if r.vulnerable]
    errors = [uses for uses, r in results.items() if r.ai == ERROR]
    suspicious = sorted(uses for uses, lines in blocks.items() if is_blocking(lines))
    if vulnerable:
        print("\nFAIL: known-vulnerable entries:")
        for uses in vulnerable:
            print(f"  {uses}")
    if errors:
        print("\nFAIL: entries with no AI review result (they will be reviewed again next time):")
        for uses in errors:
            print(f"  {uses}")
    if suspicious:
        print(f"\nFAIL: entries with a SUSPICIOUS AI review. If you have checked one and it is fine, add a line\n"
              f"      `    override: CLEAN - reason` (4 spaces) to its block in {review_txt_path(org)} and re-run:")
        for uses in suspicious:
            print(f"  {uses}")
    return 1 if vulnerable or errors or suspicious else 0


def review_org(api: GitHubAPI, org: str, ai: bool = True, force: bool = False) -> int:
    """Review the entries of ORG.final.txt which have no review in ORG.review.txt (or all, if force) and record
    the results there, as `gha update` does. Returns an exit status: non-zero if any entry fails review."""
    current, info = read_final(org)
    return review_and_record(api, org, {uses: info.get(uses, {}) for uses in current}, force, ai)


def review_single(api: GitHubAPI, target: str, ai: bool = True) -> int:
    """Review a single action@ref, without its dependencies."""
    ident = resolve_uses(target)
    if ident.kind not in ("action", "reusable_workflow"):
        sys.exit(f"FATAL: {target!r} is not owner/repo[/path]@ref")
    info = {} if is_full_sha(ident.ref) else {"version": ident.ref}
    return report_failures(review(api, {target: info}, ai))
