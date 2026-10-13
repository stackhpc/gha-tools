# gha-tools

The `gha` tool, for maintaining an allowlist of the GitHub Actions and reusable
workflows that a GitHub organisation's workflows may use, and updating repos to
match.

`gha` is used from a per-organisation repo, which holds the allowlist files and
pins a version of this package. Usage is documented in that repo's README; see
[`org-template/README.md`](./org-template/README.md). This README covers how
`gha` works and how to develop it.

## Commands

- `gha update ORG`: walk all dependencies of the entries in `ORG.actions.txt`,
  review the entries added since a git ref, then write `ORG.final.txt` (the
  allowlist) and `ORG.final.json` (provenance) if the review passes.
- `gha review ORG|ACTION@REF`: review allowlist entries (known vulnerabilities,
  weak refs, mutability, Zizmor findings).
- `gha fix ORG REPO ACTION[@REF]`: clone a repo and rewrite its `uses:` of an
  action to the allowlisted ref.
- `gha scan ORG`: find every action actually used by the active workflows in an
  org's repos.

All commands read and write `ORG.*` files in the current directory. `LOG_LEVEL`
sets the log level (default `INFO`).

## Setting up an organisation repo

TODO. In outline: copy [`org-template/`](./org-template/) to a new repo, replacing
`@ORG@` with the organisation name, write `ORG.actions.txt`, run `gha update ORG`,
and paste `ORG.final.txt` into the org's Actions settings.

## How it works

### Modules

Under `src/gha_tools/`:

- `cli.py`: argument parsing and dispatch to `commands/`.
- `github.py`: the single GitHub API client (REST and GraphQL). Errors are split into
  `NotFound` (any 4xx, permanent) and `Transient` (rate limiting, network, 5xx,
  worth retrying), which the walker relies on.
- `identity.py`: parsing `uses:` strings into a node identity
  (owner, repo, path, ref) and kind (action, reusable workflow, docker, local,
  unresolved), plus ref helpers.
- `walker.py`: the dependency graph walker - see below.
- `allowlist.py`: reading `ORG.actions.txt`, building and writing
  `ORG.final.{txt,json}`, and reading `ORG.final.txt` at a git ref.
- `discovery.py`: finding an org's repos and the workflows in them which are in
  use (`gha scan` only).
- `commands/{update,review,fix,scan}.py`: one module per subcommand.
- `zizmor.yml`: the Zizmor config used by `gha review`.

### The walker

`Walker` builds the call graph of actions and reusable workflows, starting from
roots: workflow files (`add_root`, used by `scan`) or `uses:` strings
(`add_action_root`, used by `update`). For each node it fetches the workflow,
`action.yml` or `action.yaml`, parses out the `uses:` of its steps/jobs, and adds
those as child nodes. Workflows can call actions and reusable workflows;
composite actions can call actions. The result is a DAG in which the same node
can be reached by many call chains.

State is kept in SQLite (a file for `scan`, `:memory:` for `update`):

- `nodes`: keyed by node identity, i.e. exactly what appears after `uses:`.
  Each node is fetched and parsed at most once, however many callers it has.
- `edges`: `(caller, callee, call_site)` rows. Meeting an already-processed node
  just adds an edge.
- `ref_resolution`: caches ref -> commit SHA lookups per `(owner, repo, ref)`,
  with the ref source (`is_sha`, `tag`, `branch`) and the most-specific tag on
  that SHA (the "version").

Local `uses: ./path` refs are rewritten to `owner/repo/path@ref` using the
caller's identity. The exception is a local ref in a composite action from
outside the org being walked: GitHub resolves this against the calling workflow's
workspace, not the action's repo, so it can't be known (e.g.
`pypa/gh-action-pypi-publish` generates the action it calls at runtime). As local
actions are always allowed, these become `local` leaves, with a warning.
`docker://` refs are leaves. Anything which can't be parsed or
fetched (a `NotFound`) becomes an `unresolved` leaf, rather than stopping the
walk. Transient errors leave the node in `error`, to be retried. Nodes are
claimed `in_progress` while being processed, so a killed `scan` can be resumed
with `--resume`.

### `gha update`

1. `allowlist.read_actions` parses `ORG.actions.txt`, rejecting entries with no
   ref or which aren't remote actions/reusable workflows, and warning about
   non-SHA refs on external entries.
2. Each entry is added as a walker root and the graph is walked, retrying
   transient errors. **Any node which is not `done` afterwards (e.g.
   `unresolved`) is fatal**, as the allowlist would be incomplete.
3. `check_versions` warns where a `# vX.Y.Z` comment doesn't match the tags on
   the entry's SHA.
4. `build_final` takes every action/reusable workflow node not owned by the org
   or GitHub (`actions/*`, `github/*`), at the literal ref it was called with, as
   that is what the allowlist matches. `ORG.final.json` adds each entry's SHA,
   version, ref source, whether it is a root, and the call chains to it from the
   nearest root.
5. Unless `--no-review`, it runs the org review against `--base`, defaulting to
   the merge-base of `HEAD` and `origin/main`. The base `ORG.final.txt` is read
   with `git show BASE:./ORG.final.txt`; if it doesn't exist there, every entry
   is treated as added.
   This reviews the new allowlist in memory, before anything is written. **If
   the review fails, `ORG.final.txt` and `ORG.final.json` are not written**, so
   a known-vulnerable entry never reaches them.
6. `write_final` writes `ORG.final.txt` and `ORG.final.json`.

### `gha review`

For each entry reviewed (all of `ORG.final.txt`, those added since `--base`, or a
single `ACTION@REF`):

- Warns about weak refs (tag or branch rather than SHA), missing releases and
  mutable (non-immutable) releases.
- Fetches the action's metadata and checks by type: for docker actions, that the
  image (or a Dockerfile's base image) is pinned by digest; for node actions,
  that the entrypoint is under `dist`, `lib` or `out`.
- Runs Zizmor, using `zizmor.yml`, both on the `uses:` itself (all entries in one
  batch, via a generated composite action) and on the action's metadata or
  reusable workflow file. `GITHUB_TOKEN` is passed through as `GH_TOKEN`.
  `ZIZMOR_OFFLINE` disables the online audits, with a warning.

The exit status is non-zero if any entry has a `known-vulnerable-actions`
finding. The review does not inspect docker images, node code or composite
action steps beyond the above; transitive dependencies are reviewed in their own
right because they are in `ORG.final.txt`.

### `gha fix`

Clones `git@github.com:ORG/REPO` and rewrites `uses: ACTION@<anything>` in
`.github/workflows/*` and any `action.y{a,}ml` to `uses: ACTION@REF # VERSION`,
where `REF` is the only ref for `ACTION` in `ORG.actions.txt` (unless given) and
`VERSION` comes from `ORG.final.json`. It refuses if `ACTION@REF` isn't in
`ORG.final.txt`. It never commits.

### `gha scan`

Lists all non-archived repos in the org, finds the workflows in use in each
(`discovery.py`), adds them as walker roots, walks, and writes `ORG.json` (every
external action and ref, the org repos calling it directly, SHA, source and
version) and `ORG.calls.json` (call chains to each). Finding the workflows
actually in use is subtle:

- The `/repos/ORG/REPO/actions/workflows` endpoint returns the workflow paths
  shown in the UI, but these must be ignored if the repo is archived, workflows
  are disabled on the repo (needs org admin or repo owner permissions to tell),
  the workflow is "dynamic" (created by GitHub, e.g. Dependabot or Pages), or
  the workflow is not "active".
- That endpoint only returns paths, but a workflow can exist on multiple
  branches with different contents. E.g. a `push`
  [event](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
  needs it on the relevant branch, and `workflow_dispatch` lets the user choose a
  branch. Evaluating every version is prohibitively slow, and what matters is
  which workflows *will* run: if `foo/bar@v2` is allowlisted and a default branch
  uses `foo/bar@v1`, that branch needs updating, and an old feature branch is
  fixed by updating it. So the default branch is checked for all paths; only
  paths not found there are looked for on other branches, taking the first
  branch on which each is found.
- Scanning a large org makes many API calls, so transient failures are likely;
  hence the persistent, resumable walker.

## Development

```shell
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
```

The tests in `tests/` are offline. `tests/cassette.py` can also record the
GitHub API traffic of a real `gha` run and replay it later, so changes can be
checked against a full org run without repeating it. Recordings may contain
private repository contents, so keep them under `tests/recordings/` (which is
gitignored):

```shell
mkdir -p tests/recordings/baseline && cd tests/recordings/baseline
# record (live, needs GITHUB_TOKEN):
python ../../cassette.py record stackhpc.jsonl -- scan stackhpc
# replay (offline; any request not in the recording is a hard failure):
python ../../cassette.py replay stackhpc.jsonl -- scan stackhpc
# replay, fetching live only what is missing from the recording:
python ../../cassette.py fill stackhpc.jsonl -- scan stackhpc
```

`pytest` also replays any recordings in `tests/recordings/` against the
outputs saved next to them - see `tests/test_regression.py`.

## TODO

- `gha review` and `gha update`/`gha scan` find an action's metadata file differently:
  `walker.py` tries `action.yml` then `action.yaml`, while `commands/review.py`
  lists the directory and requires exactly one file starting `action.y`, exiting
  otherwise. These should be unified.
- `discovery.find_workflows` checks other branches in the order the GitHub API
  returns them (alphabetical); shortest branch name first might be better.
