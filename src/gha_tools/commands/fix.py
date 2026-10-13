"""`gha fix`: rewrite every `uses:` of one action in a repo to an allowlisted ref."""

from __future__ import annotations

import pathlib
import re
import sys
from subprocess import run

from ..allowlist import AllowlistError, actions_path, final_txt_path, read_actions, read_final

# A `uses:` line, as a YAML mapping entry, optionally a list item, optionally quoted, optionally commented:
_USES_LINE_RE = re.compile(
    r"""^(?P<prefix>\s*(?:-\s+)?uses:\s*)(?P<quote>["']?)(?P<name>[^@\s"'#]+)(?:@(?P<ref>[^\s"'#]*))?(?P=quote)"""
    r"""(?P<comment>\s*#.*)?(?P<eol>\r?\n?)$"""
)


def ensure_clone(org, repo_name, base_dir):
    clone_path = pathlib.Path(base_dir) / repo_name
    if not clone_path.exists():
        clone_repo = f"git@github.com:{org}/{repo_name}.git"
        clone_cmd = ["git", "clone", clone_repo, clone_path]
        print(f"cloning {clone_repo} to {clone_path}")
        run(clone_cmd, text=True, capture_output=True, check=True)
    else:
        print(f"{clone_path} already exists")
    return clone_path


def resolve_target(org: str, action: str) -> tuple[str, str, str]:
    """ACTION[@REF] -> (name, ref, version), checked against the allowlist files."""
    name, _, ref = action.partition("@")
    if not ref:
        refs = sorted({e.ref for e in read_actions(org) if e.name.lower() == name.lower()})
        if len(refs) != 1:
            raise AllowlistError(
                f"{actions_path(org)} lists {len(refs)} refs for {name}{': ' + ', '.join(refs) if refs else ''}"
                " - specify one as ACTION@REF"
            )
        ref = refs[0]
    final, info = read_final(org)
    uses = f"{name}@{ref}"
    if uses not in final:
        raise AllowlistError(f"{uses} is not in {final_txt_path(org)}, so would be blocked by the allowlist")
    return name, ref, info.get(uses, {}).get("version") or ""


def workflow_files(repo_path: pathlib.Path) -> list[pathlib.Path]:
    """Workflows, plus any action metadata files (internal actions are workflow code too)."""
    files = set()
    wf_dir = repo_path / ".github" / "workflows"
    if wf_dir.is_dir():
        files.update(p for p in wf_dir.iterdir() if p.suffix in (".yml", ".yaml") and p.is_file())
    for pattern in ("action.yml", "action.yaml"):
        files.update(p for p in repo_path.rglob(pattern) if ".git" not in p.relative_to(repo_path).parts)
    return sorted(files)


def rewrite_uses(text: str, name: str, ref: str, version: str) -> tuple[str, list[tuple[str, str]]]:
    """Rewrite `uses: name@<anything>` lines (name matched exactly) to
    `uses: name@ref # version`. Returns (new text, [(old line, new line)])."""
    out, changes = [], []
    for line in text.splitlines(keepends=True):
        m = _USES_LINE_RE.match(line)
        if m and m["name"].lower() == name.lower():
            q = m["quote"]
            comment = f" # {version}" if version else ""
            new = f"{m['prefix']}{q}{m['name']}@{ref}{q}{comment}{m['eol']}"
            if new != line:
                changes.append((line.rstrip("\r\n"), new.rstrip("\r\n")))
                line = new
        out.append(line)
    return "".join(out), changes


def update_action(repo_path: pathlib.Path, name: str, ref: str, version: str) -> int:
    """Rewrite name in all workflow files in repo_path, returning the number of changed lines."""
    count = 0
    for path in workflow_files(repo_path):
        text = path.read_text()
        new_text, changes = rewrite_uses(text, name, ref, version)
        if changes:
            print(f"changing {path.relative_to(repo_path)}:")
            for old, new in changes:
                print(f"  from: '{old.strip()}'")
                print(f"  to  : '{new.strip()}'")
            path.write_text(new_text)
            count += len(changes)
    return count


def fix_repo(org, repo_name, action, clone_dir):
    try:
        name, ref, version = resolve_target(org, action)
    except AllowlistError as e:
        sys.exit(f"FATAL: {e}")
    full_clone_dir = pathlib.PosixPath(clone_dir).expanduser()
    clone_path = ensure_clone(org, repo_name, full_clone_dir)
    count = update_action(clone_path, name, ref, version)
    print()
    print(f"Done, {count} lines changed. Review git diff in {clone_path}.")
