"""
The allowlist files:

- `<org>.actions.txt`: hand-maintained input, one `owner/repo[/path]@ref` per
  line - every action / reusable workflow the org calls directly, plus
  (optionally) the org's own actions/workflows so their dependencies are found.
- `<org>.final.txt`: generated allowlist, pasteable into the GitHub web UI.
- `<org>.final.json`: generated provenance for each final.txt entry.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass
from typing import Optional

from .identity import is_full_sha, is_org_owned, resolve_uses
from .walker import Walker

log = logging.getLogger(__name__)

GITHUB_OWNERS = {"actions", "github"}  # allowed by "Allow actions created by GitHub"
FINAL_KINDS = ("action", "reusable_workflow")
_VERSION_COMMENT_RE = re.compile(r"^v?\d+(\.\d+)*\S*$")


class AllowlistError(Exception):
    pass


def actions_path(org: str) -> str:
    return f"{org}.actions.txt"


def final_txt_path(org: str) -> str:
    return f"{org}.final.txt"


def final_json_path(org: str) -> str:
    return f"{org}.final.json"


def is_github_owned(owner: Optional[str]) -> bool:
    return bool(owner) and owner.lower() in GITHUB_OWNERS


# --------------------------------------------------------------------------
# <org>.actions.txt
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ActionEntry:
    uses: str  # owner/repo[/path]@ref
    version: Optional[str]  # from a trailing `# vX.Y.Z` comment, if any
    lineno: int

    @property
    def name(self) -> str:
        return self.uses.split("@", 1)[0]

    @property
    def ref(self) -> str:
        return self.uses.split("@", 1)[1]


def parse_actions_text(text: str, org: str) -> list[ActionEntry]:
    """Parse the contents of an actions.txt file. Raises AllowlistError
    listing every invalid line; logs a warning for external entries with a
    non-SHA ref."""
    entries: list[ActionEntry] = []
    errors: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        content, _, comment = line.partition("#")
        uses = content.strip().rstrip(",").strip()
        if not uses:
            continue
        words = comment.split()
        version = words[0] if words and _VERSION_COMMENT_RE.match(words[0]) else None

        name, _, ref = uses.partition("@")
        if not ref:
            errors.append(f"line {lineno}: {uses!r} has no ref (expected owner/repo[/path]@ref)")
            continue
        ident = resolve_uses(uses)
        if ident.kind not in FINAL_KINDS:
            errors.append(f"line {lineno}: {uses!r} is not a remote action or reusable workflow")
            continue
        if is_github_owned(ident.owner):
            log.warning(f"{uses} (line {lineno}) is GitHub-owned and need not be listed")
        elif not is_org_owned(ident.owner, org) and not is_full_sha(ref):
            log.warning(f"{uses} (line {lineno}) has a non-SHA ref")
        entries.append(ActionEntry(uses, version, lineno))
    if errors:
        raise AllowlistError("invalid entries in actions file:\n  " + "\n  ".join(errors))
    return entries


def read_actions(org: str) -> list[ActionEntry]:
    with open(actions_path(org)) as f:
        return parse_actions_text(f.read(), org)


# --------------------------------------------------------------------------
# Building <org>.final.{txt,json} from a completed walk
# --------------------------------------------------------------------------

def chains_from_roots(walker: Walker, node_id: str, roots: set[str]) -> list[list[str]]:
    """Every call chain to node_id (excluding it), each starting from the
    nearest root, i.e. an actions.txt entry or a node with no callers."""
    chains: list[list[str]] = []

    def walk_up(current: str, trail: list[str], seen: set[str]) -> None:
        callers = walker.callers_of(current)
        if (current in roots and trail) or not callers:
            chains.append([current] + trail)
            return
        for caller in callers:
            if caller in seen:  # cycle
                continue
            walk_up(caller, [current] + trail, seen | {current})

    walk_up(node_id, [], set())
    return sorted(c[:-1] for c in chains if len(c) > 1)


def walk(walker: Walker, entries: list[ActionEntry]) -> None:
    """Walk all dependencies of entries. Raises AllowlistError if anything
    could not be resolved, as the allowlist would then be incomplete."""
    for entry in entries:
        walker.add_action_root(entry.uses)
    for _ in range(3):  # retry transient errors a couple of times
        walker.run()
        if not walker.list_errors():
            break
    failed = [n for n in walker.export_nodes() if n["status"] != "done"]
    if failed:
        lines = []
        for node in failed:
            roots = {resolve_uses(e.uses).node_id for e in entries}
            chains = [" -> ".join(c + [node["node_id"]]) for c in chains_from_roots(walker, node["node_id"], roots)]
            lines.append(f"{node['node_id']} [{node['status']}]: {node['error']}\n    via: " + "\n    via: ".join(chains))
        raise AllowlistError("could not resolve all dependencies:\n  " + "\n  ".join(lines))


def build_final(walker: Walker, entries: list[ActionEntry], org: str) -> dict:
    """{uses: info} for every node which belongs in the allowlist: external,
    non-GitHub actions and reusable workflows, at the literal ref used."""
    roots = {resolve_uses(e.uses).node_id for e in entries}
    final = {}
    for node in walker.export_nodes():
        if node["kind"] not in FINAL_KINDS:
            continue
        if is_org_owned(node["owner"], org) or is_github_owned(node["owner"]):
            continue
        uses = node["node_id"]
        chains = chains_from_roots(walker, uses, roots)
        final[uses] = {
            "kind": node["kind"],
            "sha": node["resolved_sha"],
            "version": node["ref_version"],
            "ref_source": node["ref_source"],
            "root": uses in roots,
            "chains": chains,
        }
    return dict(sorted(final.items()))


def check_versions(walker: Walker, entries: list[ActionEntry]) -> None:
    """Warn where a `# version` comment in actions.txt doesn't match tags."""
    nodes = {n["node_id"]: n for n in walker.export_nodes()}
    for entry in entries:
        if entry.version is None:
            continue
        actual = nodes[resolve_uses(entry.uses).node_id]["ref_version"] or ""
        if entry.version != actual:
            log.warning(
                f"{entry.uses} (line {entry.lineno}) is commented as {entry.version} "
                f"but is tagged {actual or '(no tag)'}"
            )


def format_final_txt(final: dict) -> str:
    return "".join(f"{uses},\n" for uses in sorted(final))


def write_final(org: str, final: dict) -> None:
    with open(final_txt_path(org), "w") as f:
        f.write(format_final_txt(final))
    with open(final_json_path(org), "w") as f:
        json.dump(final, f, indent=2)
        f.write("\n")


def parse_final_txt(text: str) -> set[str]:
    return {line.strip().rstrip(",").strip() for line in text.splitlines() if line.strip()}


def read_final(org: str) -> tuple[set[str], dict]:
    """(entries in final.txt, final.json data)"""
    with open(final_txt_path(org)) as f:
        entries = parse_final_txt(f.read())
    with open(final_json_path(org)) as f:
        info = json.load(f)
    return entries, info


# --------------------------------------------------------------------------
# Comparison against git
# --------------------------------------------------------------------------

def _git(*args: str) -> Optional[str]:
    """stdout of a git command, or None if it fails (incl. git not installed)."""
    try:
        p = subprocess.run(["git", *args], capture_output=True, text=True)
    except FileNotFoundError:
        return None
    return p.stdout if p.returncode == 0 else None


def default_base() -> str:
    """The merge-base with origin/main, i.e. what a PR will be compared
    against, falling back to HEAD."""
    merge_base = _git("merge-base", "HEAD", "origin/main")
    if merge_base:
        return merge_base.strip()
    log.warning("could not find merge-base with origin/main, comparing against HEAD")
    return "HEAD"


def final_at(org: str, base: str) -> set[str]:
    """The entries in final.txt at a git ref; empty if it doesn't exist there."""
    if _git("rev-parse", "--verify", "--quiet", f"{base}^{{commit}}") is None:
        if base != "HEAD":
            raise AllowlistError(f"{base!r} is not a valid git ref")
        log.warning("not in a git repo with commits, treating all entries as added")
        return set()
    text = _git("show", f"{base}:./{final_txt_path(org)}")
    if text is None:
        log.warning(f"{final_txt_path(org)} does not exist at {base}, treating all entries as added")
        return set()
    return parse_final_txt(text)
