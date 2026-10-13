"""
Walk GitHub Actions workflows across an org and build the full call graph of
every action / reusable workflow they pull in, directly or transitively
(via composite actions and reusable-workflow chains).

Design
------
Two independent pieces of state, both persisted in one SQLite file so a run
can be killed and resumed without redoing API calls:

1. `nodes` table -- the *content* cache. Keyed by node identity
   (owner, repo, path, ref) -- i.e. exactly what appears after `uses:`.
   A node is fetched and parsed AT MOST ONCE, no matter how many places
   reference it. Its children are a property of its own content, not of
   who's calling it.

2. `edges` table -- the *call graph*. (caller_id, callee_id, call_site)
   rows, inserted idempotently (INSERT OR IGNORE). Re-encountering an
   already-`done` node just adds a new edge; it never triggers a re-fetch.

A third table, `ref_resolution`, caches ref -> commit SHA lookups keyed by
(owner, repo, ref) -- independent of node identity, since the same ref
(e.g. actions/checkout@v4) is referenced from many different call sites
across an org and should only be resolved once.

Node identity notes
--------------------
- Local actions (`./path`) are rewritten to `owner/repo/normalized_path@ref`
  using the *caller's* identity, then processed exactly like any other
  action reference -- no special-casing needed downstream. The exception
  is (when `org` is given) a local ref in a composite action from outside
  the org: GitHub resolves this against the calling workflow's workspace,
  not the action's repo, so it is unknowable here. It is recorded as a
  `local` leaf (always allowed) and not walked.
- `owner/repo/path@ref` where path ends in .yml/.yaml under
  .github/workflows/ -> reusable_workflow. Otherwise -> action (root or
  subdirectory; we try action.yml then action.yaml).
- `docker://...` -> leaf node, no children.
- Anything that doesn't parse, or a local ref from a caller with no
  owner/repo context, is recorded as an `unresolved` leaf with the raw
  string preserved, rather than raising -- so one bad `uses:` line
  doesn't kill an org-wide run.

Resumability
------------
- Every mutation is a normal SQLite transaction; nothing is held only in
  memory.
- Nodes are claimed into `in_progress` before processing; on startup any
  leftover `in_progress` rows (from a killed run) are reset to `pending`.
- Transient failures (network errors, 5xx, rate limit) leave a node
  `error` with a retry counter; `run()` retries these (up to a cap) at
  the start of each invocation. Permanent failures (404 / bad parse)
  become `unresolved` leaves and are not retried.

Usage
-----
    walker = Walker("graph.db", api=GitHubAPI(token))
    walker.add_root("myorg", "myrepo", ".github/workflows/ci.yml", "main")
    walker.add_action_root("foo/bar@v4")   # or start from any action/reusable workflow
    walker.run()

    # after run() completes (queue drained):
    for row in walker.export_nodes():
        print(row)

    walker.print_call_chains("actions/checkout")   # everywhere it's used, and how
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional

import yaml

from .github import GitHubAPI, NotFound, Transient
from .identity import (
    NodeIdentity, is_full_sha, is_local_uses, is_org_owned, local_identity, resolve_uses, root_identity,
    tag_specificity,
)

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# YAML parsing helpers
# --------------------------------------------------------------------------

def workflow_style_children(doc: dict) -> list[tuple[str, str]]:
    """For a plain workflow or a reusable workflow file: (call_site, raw_uses)."""
    out = []
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        return out
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if "uses" in job:
            out.append((f"job:{job_id}", str(job["uses"])))
            continue
        for i, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict) and "uses" in step:
                out.append((f"job:{job_id}/step:{i}", str(step["uses"])))
    return out


def composite_action_children(doc: dict) -> list[tuple[str, str]]:
    out = []
    runs = doc.get("runs") or {}
    if not isinstance(runs, dict) or runs.get("using") != "composite":
        return out
    for i, step in enumerate(runs.get("steps") or []):
        if isinstance(step, dict) and "uses" in step:
            out.append((f"step:{i}", str(step["uses"])))
    return out


# --------------------------------------------------------------------------
# Persistent walker
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    node_id      TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    owner        TEXT,
    repo         TEXT,
    path         TEXT,
    ref          TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending|in_progress|done|error|unresolved
    resolved_sha TEXT,
    ref_source   TEXT,  -- 'branch' | 'tag' | 'is_sha'
    ref_version  TEXT,  -- tag name currently pointing at resolved_sha, if any
    error        TEXT,
    retries      INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT
);

CREATE TABLE IF NOT EXISTS edges (
    caller_id TEXT NOT NULL,
    callee_id TEXT NOT NULL,
    call_site TEXT NOT NULL,
    PRIMARY KEY (caller_id, callee_id, call_site)
);

CREATE TABLE IF NOT EXISTS ref_resolution (
    owner       TEXT NOT NULL,
    repo        TEXT NOT NULL,
    ref         TEXT NOT NULL,
    sha         TEXT NOT NULL,
    resolved_at TEXT,
    PRIMARY KEY (owner, repo, ref)
);

CREATE TABLE IF NOT EXISTS repo_tags (
    owner      TEXT NOT NULL,
    repo       TEXT NOT NULL,
    tags_json  TEXT NOT NULL,  -- {tag_name: sha}, fetched once per repo
    resolved_at TEXT,
    PRIMARY KEY (owner, repo)
);

CREATE TABLE IF NOT EXISTS scanned_repos (
    repo       TEXT PRIMARY KEY,
    scanned_at TEXT
);
"""

MAX_RETRIES = 5


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Walker:
    def __init__(
        self,
        db_path: str,
        api: GitHubAPI,
        resume: bool = True,
        org: Optional[str] = None,
    ):
        """
        db_path: SQLite file, or ":memory:" for a throwaway walk.

        resume:
            True  (default) -- reuse an existing DB at db_path if present,
                  picking up wherever the last run left off.
            False -- delete any existing DB at db_path (and its WAL/SHM
                  sidecar files) before starting, so this is a full, fresh
                  crawl. This is the simplest way to avoid stale results
                  from a previous, differently-scoped set of roots: just
                  don't resume.

        org: the organisation being walked. If given, local (./) refs in
             composite actions from outside it become `local` leaves.
        """
        if not resume and db_path != ":memory:":
            for suffix in ("", "-wal", "-shm"):
                path = db_path + suffix
                if os.path.exists(path):
                    os.remove(path)
        self.db = sqlite3.connect(db_path)
        self.db.execute("PRAGMA journal_mode=WAL;")
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.api = api
        self.org = org

    # -- setup ------------------------------------------------------------

    def add_root(self, owner: str, repo: str, path: str, ref: Optional[str] = None) -> str:
        # ref=None means "the repo's default branch". Rather than resolving that
        # ourselves (an extra API call per repo), we store the sentinel "HEAD"
        # and let the GitHub endpoints we already call resolve it server-side,
        # since GitHub accepts "HEAD" as a ref in the contents and commits APIs.
        ident = root_identity(owner, repo, path, ref or "HEAD")
        self._upsert_node_if_absent(ident)
        self.db.commit()
        return ident.node_id

    def add_action_root(self, uses: str) -> str:
        """Start a walk from an arbitrary remote `uses:` reference, e.g.
        "foo/bar@v4" or "o/r/.github/workflows/w.yml@main", to find
        everything it depends on. Returns its node_id."""
        ident = resolve_uses(uses)
        if ident.kind not in ("action", "reusable_workflow"):
            raise ValueError(f"not a remote action or reusable workflow: {uses!r}")
        self._upsert_node_if_absent(ident)
        return ident.node_id

    # -- core loop ----------------------------------------------------------

    def run(self, batch_size: int = 25, sleep_between_batches: float = 0.0, retry_errors: bool = True) -> None:
        self._recover_in_progress()
        if retry_errors:
            self._requeue_retryable_errors()
        while True:
            batch = self._claim_batch(batch_size)
            if not batch:
                break
            for row in batch:
                self._process_node(row)
            if sleep_between_batches:
                time.sleep(sleep_between_batches)

    def pending_count(self) -> int:
        """How many nodes would actually be (re)processed by the next run().
        Safe to call any time -- read-only, no API calls."""
        cur = self.db.execute(
            "SELECT COUNT(*) FROM nodes WHERE status IN ('pending', 'in_progress')"
        )
        return cur.fetchone()[0]

    def list_errors(self) -> list[dict]:
        """Nodes currently sitting in 'error', with retry count and last error,
        so you can see what a retry_errors=True run() would touch."""
        self.db.row_factory = sqlite3.Row
        cur = self.db.execute(
            "SELECT node_id, retries, error, updated_at FROM nodes WHERE status='error' ORDER BY updated_at"
        )
        return [dict(r) for r in cur.fetchall()]

    def _recover_in_progress(self) -> None:
        self.db.execute("UPDATE nodes SET status='pending' WHERE status='in_progress'")
        self.db.commit()

    def _requeue_retryable_errors(self) -> None:
        self.db.execute(
            "UPDATE nodes SET status='pending' WHERE status='error' AND retries < ?",
            (MAX_RETRIES,),
        )
        self.db.commit()

    def _claim_batch(self, n: int) -> list[sqlite3.Row]:
        self.db.row_factory = sqlite3.Row
        cur = self.db.execute("SELECT * FROM nodes WHERE status='pending' LIMIT ?", (n,))
        rows = cur.fetchall()
        if rows:
            ids = [r["node_id"] for r in rows]
            self.db.executemany(
                "UPDATE nodes SET status='in_progress' WHERE node_id=?",
                [(i,) for i in ids],
            )
            self.db.commit()
        return rows

    def _process_node(self, row: sqlite3.Row) -> None:
        node_id = row["node_id"]
        kind = row["kind"]
        owner, repo, path, ref = row["owner"], row["repo"], row["path"], row["ref"]

        if kind in ("docker", "local", "unresolved"):
            self._mark_done(node_id, resolved_sha=None, ref_source=None, ref_version=None)
            return

        ident = NodeIdentity(kind, owner, repo, path, ref, node_id)

        try:
            sha = self._resolve_sha_cached(owner, repo, ref)
            ref_source, ref_version = self._classify_ref(owner, repo, ref, sha)
            children = self._fetch_and_parse(ident)
        except NotFound as e:
            self._mark_terminal(node_id, status="unresolved", error=str(e))
            return
        except Transient as e:
            self._mark_error(node_id, str(e))
            return
        except Exception as e:  # yaml parse errors etc. -- treat as permanent
            self._mark_terminal(node_id, status="unresolved", error=f"parse error: {e}")
            return

        for call_site, raw_uses in children:
            child = self._resolve_child(raw_uses, ident)
            self._upsert_node_if_absent(child)
            self._insert_edge(node_id, child.node_id, call_site)

        self._mark_done(node_id, resolved_sha=sha, ref_source=ref_source, ref_version=ref_version)

    def _resolve_child(self, raw_uses: str, caller: NodeIdentity) -> NodeIdentity:
        if (self.org and caller.kind == "action" and is_local_uses(raw_uses)
                and not is_org_owned(caller.owner, self.org)):
            log.warning(
                f"{caller.node_id} uses {raw_uses.strip()}: a local ref in an external composite action "
                "resolves against the calling workflow's repo, so is always allowed and is not walked"
            )
            return local_identity(raw_uses)
        return resolve_uses(raw_uses, caller)

    def _fetch_and_parse(self, ident: NodeIdentity) -> list[tuple[str, str]]:
        if ident.kind in ("workflow_root", "reusable_workflow"):
            text = self.api.get_file_text(ident.owner, ident.repo, ident.path, ident.ref)
            doc = yaml.safe_load(text) or {}
            return workflow_style_children(doc)

        if ident.kind == "action":
            path = ident.path
            if path.endswith((".yml", ".yaml")):
                candidates = [path]
            else:
                base = path.rstrip("/")
                candidates = [
                    f"{base}/action.yml".lstrip("/"),
                    f"{base}/action.yaml".lstrip("/"),
                ]
            last_err: Optional[Exception] = None
            for candidate in candidates:
                try:
                    text = self.api.get_file_text(ident.owner, ident.repo, candidate, ident.ref)
                    doc = yaml.safe_load(text) or {}
                    return composite_action_children(doc)
                except NotFound as e:
                    last_err = e
                    continue
            raise last_err or NotFound(f"no action.yml/yaml for {ident.node_id}")

        raise NotFound(f"unhandled kind {ident.kind} for {ident.node_id}")

    def _resolve_sha_cached(self, owner: Optional[str], repo: Optional[str], ref: Optional[str]) -> Optional[str]:
        if not owner or not repo or not ref:
            return None
        cur = self.db.execute(
            "SELECT sha FROM ref_resolution WHERE owner=? AND repo=? AND ref=?",
            (owner, repo, ref),
        )
        row = cur.fetchone()
        if row:
            return row[0]
        sha = self.api.resolve_ref_sha(owner, repo, ref)
        self.db.execute(
            "INSERT OR REPLACE INTO ref_resolution (owner, repo, ref, sha, resolved_at) VALUES (?,?,?,?,?)",
            (owner, repo, ref, sha, _now()),
        )
        self.db.commit()
        return sha

    def _classify_ref(
        self, owner: Optional[str], repo: Optional[str], ref: Optional[str], resolved_sha: Optional[str]
    ) -> tuple[Optional[str], Optional[str]]:
        """Returns (ref_source, ref_version).
        ref_source: 'is_sha' if the raw ref is already a full commit SHA;
                    'tag' if the raw ref is itself a known tag name;
                    'branch' otherwise (the default -- includes branch names
                    and the "HEAD" default-branch sentinel).
        ref_version: the MOST SPECIFIC tag currently pointing at resolved_sha
                     (e.g. prefers "v1.2.3" over a co-pointing "v1"), or ""
                     if no tag matches at all. Independent of ref_source,
                     since a branch can happen to sit exactly on a tagged
                     commit.
        Both come from ONE tags fetch per (owner, repo), cached and reused
        across every node in that repo regardless of how many different
        refs are seen.
        """
        if not owner or not repo:
            return None, None

        tags = self._get_repo_tags_cached(owner, repo)

        if is_full_sha(ref):
            ref_source = "is_sha"
        else:
            ref_source = "tag" if ref in tags else "branch"

        matching_tags = [tag_name for tag_name, tag_sha in tags.items() if resolved_sha and tag_sha == resolved_sha]
        ref_version = max(matching_tags, key=tag_specificity, default="")

        return ref_source, ref_version

    def _get_repo_tags_cached(self, owner: str, repo: str) -> dict[str, str]:
        """{tag_name: sha} for a repo, fetched once and reused for every node
        in that repo -- this is the "per repo, not per repo+ref" cost model."""
        cur = self.db.execute("SELECT tags_json FROM repo_tags WHERE owner=? AND repo=?", (owner, repo))
        row = cur.fetchone()
        if row is not None:
            return json.loads(row[0])
        tags = self.api.list_tags(owner, repo)
        self.db.execute(
            "INSERT OR REPLACE INTO repo_tags (owner, repo, tags_json, resolved_at) VALUES (?,?,?,?)",
            (owner, repo, json.dumps(tags), _now()),
        )
        self.db.commit()
        return tags

    # -- node/edge mutation --------------------------------------------------

    def _upsert_node_if_absent(self, ident: NodeIdentity) -> None:
        self.db.execute(
            """INSERT OR IGNORE INTO nodes
               (node_id, kind, owner, repo, path, ref, status, updated_at)
               VALUES (?,?,?,?,?,?, 'pending', ?)""",
            (ident.node_id, ident.kind, ident.owner, ident.repo, ident.path, ident.ref, _now()),
        )
        self.db.commit()

    def _insert_edge(self, caller_id: str, callee_id: str, call_site: str) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO edges (caller_id, callee_id, call_site) VALUES (?,?,?)",
            (caller_id, callee_id, call_site),
        )
        self.db.commit()

    def _mark_done(
        self, node_id: str, resolved_sha: Optional[str], ref_source: Optional[str], ref_version: Optional[str]
    ) -> None:
        self.db.execute(
            "UPDATE nodes SET status='done', resolved_sha=?, ref_source=?, ref_version=?, error=NULL, updated_at=? "
            "WHERE node_id=?",
            (resolved_sha, ref_source, ref_version, _now(), node_id),
        )
        self.db.commit()

    def _mark_error(self, node_id: str, error: str) -> None:
        self.db.execute(
            "UPDATE nodes SET status='error', error=?, retries=retries+1, updated_at=? WHERE node_id=?",
            (error, _now(), node_id),
        )
        self.db.commit()

    def _mark_terminal(self, node_id: str, status: str, error: str) -> None:
        self.db.execute(
            "UPDATE nodes SET status=?, error=?, updated_at=? WHERE node_id=?",
            (status, error, _now(), node_id),
        )
        self.db.commit()

    # -- queries --------------------------------------------------------------

    def export_nodes(self) -> list[dict]:
        self.db.row_factory = sqlite3.Row
        cur = self.db.execute("SELECT * FROM nodes ORDER BY node_id")
        return [dict(r) for r in cur.fetchall()]

    def export_edges(self) -> list[dict]:
        self.db.row_factory = sqlite3.Row
        cur = self.db.execute("SELECT * FROM edges ORDER BY caller_id, callee_id")
        return [dict(r) for r in cur.fetchall()]

    def find_nodes(self, substring: str) -> list[str]:
        cur = self.db.execute("SELECT node_id FROM nodes WHERE node_id LIKE ?", (f"%{substring}%",))
        return [r[0] for r in cur.fetchall()]

    def callers_of(self, node_id: str) -> list[str]:
        cur = self.db.execute("SELECT DISTINCT caller_id FROM edges WHERE callee_id=?", (node_id,))
        return [r[0] for r in cur.fetchall()]

    def call_chains_to(self, node_id: str) -> list[list[str]]:
        """All root-to-node paths (roots = nodes with no callers)."""
        chains: list[list[str]] = []

        def walk(current: str, trail: list[str], seen: set[str]):
            if current in seen:  # guard against accidental cycles
                chains.append([current, "...(cycle)"] + trail)
                return
            seen = seen | {current}
            callers = self.callers_of(current)
            if not callers:
                chains.append([current] + trail)
                return
            for c in callers:
                walk(c, [current] + trail, seen)

        walk(node_id, [], set())
        return chains

    def print_call_chains(self, substring: str) -> None:
        for node_id in self.find_nodes(substring):
            print(f"\n=== {node_id} ===")
            for chain in self.call_chains_to(node_id):
                print("  " + " -> ".join(chain))

    def summary(self) -> dict:
        cur = self.db.execute("SELECT status, COUNT(*) FROM nodes GROUP BY status")
        return dict(cur.fetchall())

    def is_repo_scanned(self, repo: str) -> bool:
        """Has add_root already been called for every workflow in this repo,
        with mark_repo_scanned() confirming it completed? Used to skip
        already-processed repos when resuming an interrupted root-finding
        pass, as distinct from resuming the graph walk itself."""
        cur = self.db.execute("SELECT 1 FROM scanned_repos WHERE repo=?", (repo,))
        return cur.fetchone() is not None

    def mark_repo_scanned(self, repo: str) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO scanned_repos (repo, scanned_at) VALUES (?, ?)",
            (repo, _now()),
        )
        self.db.commit()
