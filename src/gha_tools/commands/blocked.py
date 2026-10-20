"""`gha blocked`: report workflows which won't run given the current ORG.final.txt."""

from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict

from ..allowlist import AllowlistError, final_txt_path, json_path, parse_final_txt

log = logging.getLogger(__name__)


def load_scan(org: str) -> tuple[dict, dict]:
    """The (ORG.json, ORG.calls.json) written by `gha scan`."""
    try:
        with open(json_path(f"{org}.json")) as f_json, open(json_path(f"{org}.calls.json")) as f_calls:
            return json.load(f_json), json.load(f_calls)
    except FileNotFoundError as e:
        raise AllowlistError(f"{e.filename} not found: run `gha scan {org}` first") from e


def find_blocked(actions: dict, calls: dict, allowed: set[str]) -> dict[str, dict[str, list[list[str]]]]:
    """{root workflow: {missing action@ref: [chain below the root, ...]}} for
    every external action/workflow reached by a root which is not in `allowed`."""
    blocked: dict[str, dict[str, list[list[str]]]] = defaultdict(lambda: defaultdict(list))
    for uses, chains in calls.items():
        if uses in allowed:
            continue
        for chain in chains:
            blocked[chain[0]][uses].append(chain[1:])
    return {root: dict(sorted(missing.items())) for root, missing in sorted(blocked.items())}


def find_unresolved(actions: dict) -> list[str]:
    """Entries which couldn't be resolved by the scan, so their dependencies are unknown."""
    return sorted(
        f"{address}@{ref}" for address, refs in actions.items() for ref, info in refs.items() if info["sha"] is None
    )


def format_report(blocked: dict, unresolved: list[str]) -> str:
    lines = []
    for root, missing in blocked.items():
        lines.append(f"{root}")
        for uses, chains in missing.items():
            lines.append(f"  missing: {uses}")
            for chain in chains:
                if chain:
                    lines.append(f"    via: {' -> '.join(chain)}")
    if blocked:
        counts: dict[str, int] = defaultdict(int)
        for missing in blocked.values():
            for uses in missing:
                counts[uses] += 1
        lines.append("")
        lines.append("Missing entries, by number of workflows blocked:")
        for uses, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"  {n:4d}  {uses}")
    if unresolved:
        lines.append("")
        lines.append("Could not be resolved by the scan (their dependencies are unknown):")
        lines.extend(f"  {uses}" for uses in unresolved)
    return "\n".join(lines) + ("\n" if lines else "")


def blocked(org: str) -> int:
    """Prints the report to stdout. Returns 1 if any workflow is blocked."""
    actions, calls = load_scan(org)
    try:
        with open(final_txt_path(org)) as f:
            allowed = parse_final_txt(f.read())
    except FileNotFoundError as e:
        raise AllowlistError(f"{e.filename} not found: run `gha update {org}` first") from e

    scanned = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(json_path(f"{org}.calls.json"))))
    log.info(f"Using scan from {scanned}; {len(allowed)} entries in {final_txt_path(org)}")

    result = find_blocked(actions, calls, allowed)
    unresolved = find_unresolved(actions)
    print(format_report(result, unresolved), end="")
    if result:
        log.error(f"{len(result)} workflows would be blocked")
    return 1 if result else 0
