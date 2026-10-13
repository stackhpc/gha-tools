"""
Parsing of `uses:` references and related ref helpers.

Syntax reference:
https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstepsuses

    public action:            {owner}/{repo}@{ref}
    public action in subdir:  {owner}/{repo}/{path}@{ref}
    in same repo:             ./path/to/dir
    docker image:             docker://{image}:{tag}
    reusable workflow:        {owner}/{repo}/.github/workflows/{filename}@{ref}
                              ./.github/workflows/{filename}
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Optional

from packaging.version import InvalidVersion, Version

_GH_USES_RE = re.compile(
    r"^(?P<owner>[^/@]+)/(?P<repo>[^/@]+)(?:/(?P<path>[^@]+))?@(?P<ref>.+)$"
)
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class NodeIdentity:
    kind: str  # 'workflow_root' | 'reusable_workflow' | 'action' | 'docker' | 'local' | 'unresolved'
    owner: Optional[str]
    repo: Optional[str]
    path: str
    ref: Optional[str]
    raw: str  # original `uses:` string (or synthetic description for roots)

    @property
    def node_id(self) -> str:
        if self.kind == "docker":
            return f"docker:{self.raw}"
        if self.kind == "unresolved":
            return f"unresolved:{self.raw}"
        if self.kind == "local":
            return f"local:{self.raw}"
        if self.path:
            return f"{self.owner}/{self.repo}/{self.path}@{self.ref}"
        return f"{self.owner}/{self.repo}@{self.ref}"


def is_reusable_workflow_path(path: str) -> bool:
    return path.endswith((".yml", ".yaml")) and ".github/workflows/" in path


def resolve_uses(raw_uses: str, caller: Optional[NodeIdentity] = None) -> NodeIdentity:
    """Turn a raw `uses:` string (as seen inside `caller`) into a NodeIdentity.
    With no caller, local (./) references can't be resolved."""
    raw = raw_uses.strip()

    if raw.startswith("docker://"):
        return NodeIdentity("docker", None, None, "", None, raw)

    if is_local_uses(raw):
        if caller is None or not caller.owner or not caller.repo or caller.ref is None:
            return NodeIdentity("unresolved", None, None, raw, None, raw)
        # GitHub resolves local `uses:` paths relative to the repository
        # ROOT, regardless of where the referencing file itself lives --
        # NOT relative to the referencing file's own directory. A composite
        # action nested under some/deep/path/action.yml that says
        # `uses: ./.github/workflows/extra.yml` still means repo-root
        # .github/workflows/extra.yml.
        norm_path = posixpath.normpath(raw).lstrip("/")
        kind = "reusable_workflow" if is_reusable_workflow_path(norm_path) else "action"
        return NodeIdentity(kind, caller.owner, caller.repo, norm_path, caller.ref, raw)

    m = _GH_USES_RE.match(raw)
    if not m:
        return NodeIdentity("unresolved", None, None, raw, None, raw)

    owner, repo, path, ref = m.group("owner"), m.group("repo"), m.group("path") or "", m.group("ref")
    kind = "reusable_workflow" if is_reusable_workflow_path(path) else "action"
    return NodeIdentity(kind, owner, repo, path, ref, raw)


def local_identity(raw_uses: str) -> NodeIdentity:
    """A local (./) reference whose repository isn't known, e.g. from a
    composite action in another repo, as these resolve against the calling
    workflow's workspace rather than the action's own repo."""
    raw = raw_uses.strip()
    return NodeIdentity("local", None, None, raw, None, raw)


def is_local_uses(raw_uses: str) -> bool:
    return raw_uses.strip().startswith(("./", "../"))


def is_org_owned(owner: Optional[str], org: str) -> bool:
    return bool(owner) and owner.lower() == org.lower()


def root_identity(owner: str, repo: str, path: str, ref: str) -> NodeIdentity:
    return NodeIdentity("workflow_root", owner, repo, path, ref, f"{owner}/{repo}/{path}@{ref}")


def split_action_name(name: str) -> tuple[str, str, str]:
    """'owner/repo[/path]' (no @ref) -> (owner, repo, path), path '' if none."""
    owner, repo, *rest = name.split("/")
    return owner, repo, "/".join(rest)


def is_full_sha(ref: Optional[str]) -> bool:
    return bool(ref) and bool(_FULL_SHA_RE.match(ref))


def tag_specificity(tag_name: str) -> tuple:
    """Sort key: higher is more specific. "v1.2.3" ranks above a co-pointing
    "v1" because it has more numeric release components. packaging.version
    handles the optional 'v' prefix and normal version semantics for us
    (so "v1.2.3" and "1.2.3" are treated identically). Tags that aren't
    parseable as a version at all (e.g. "latest", "stable") fall back to
    counting dot-separated segments, ranked below any real version, with
    the tag name itself as a final deterministic tiebreak either way."""
    try:
        release = Version(tag_name).release
        return (1, len(release), release, tag_name)
    except InvalidVersion:
        segments = tag_name.split(".")
        return (0, len(segments), tuple(), tag_name)
