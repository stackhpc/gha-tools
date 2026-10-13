# @ORG@ GitHub Actions allowlist

The `@ORG@` GitHub organisation only allows workflows to use actions and reusable
workflows which are on an allowlist. This repository defines that allowlist, and
holds the tooling (`gha`, from [gha-tools](https://github.com/stackhpc/gha-tools))
to maintain it.

The files are:

- `@ORG@.actions.txt`: **hand-maintained**. Every action or reusable workflow
  called directly from `@ORG@` workflows. See [Actions file format](#actions-file-format).
- `@ORG@.final.txt`: **generated** by `gha update`. The allowlist itself: all
  non-GitHub external actions and reusable workflows, from `@ORG@.actions.txt`
  and their transitive dependencies, in the format required for pasting into the
  org's Actions settings. Transitive dependencies are listed at the literal ref
  their parent uses (e.g. `docker/login-action@v3`) as that is what the
  allowlist matches.
- `@ORG@.final.json`: **generated** by `gha update`. The provenance of each
  `@ORG@.final.txt` entry: its resolved SHA, version (most-specific tag on the
  SHA), ref source (`is_sha`, `tag` or `branch`), whether it is listed in
  `@ORG@.actions.txt` (`root`), and the call chains from `@ORG@.actions.txt`
  entries to it.
- `requirements.txt`: the version of `gha` to use.

## Setup

```shell
python3 -m venv venv
. venv/bin/activate
pip install -U pip
pip install -r requirements.txt
export GITHUB_TOKEN=$(gh auth token)
```

All `gha` commands below are run from the root of this repository. All except
`gha fix` need `GITHUB_TOKEN`.

## Adding or updating an action

1. Edit `@ORG@.actions.txt`.

2. Run:

    ```shell
    gha update @ORG@
    ```

    This walks all dependencies of the entries in `@ORG@.actions.txt` and rewrites
    `@ORG@.final.txt` and `@ORG@.final.json`. It fails if any entry has no ref, or
    if any dependency cannot be found (as the allowlist would then be incomplete).

    It then reviews the entries added to `@ORG@.final.txt` compared to the
    merge-base of `HEAD` and `origin/main`, i.e. what a PR will be compared against
    (use `--base GIT_REF` to change this, or `--no-review` to skip the review) - see
    [Reviewing](#reviewing). It **exits non-zero if any added entry is known to be
    vulnerable**. The files are written regardless, so you can see what changed.

3. Commit all three files and open a PR.

4. Once the PR is merged, an org admin pastes `@ORG@.final.txt` into the
   allowlist in the org's Actions settings, and deletes any entries the review
   listed as removed.

5. Update repos to use the new action/ref if necessary - see
   [Fixing actions in repos](#fixing-actions-in-repos).

## Actions file format

One `owner/repo[/path]@ref` per line, e.g.:

```text
# Needed for building docs
ConorMacBride/install-package@3e7ad059e07782ee54fa35f827df52aae0626f30, # v1.1.0
anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610
@ORG@/some-workflows/.github/workflows/multinode.yml@main
```

- Comments and blank lines are allowed; use them to say why an action is needed.
- A trailing comma is optional, so lines can be copied from the web UI format.
- Refs for external actions should be SHAs; `gha update` warns about tags or branches.
- An optional `# vX.Y.Z` comment documents the version; `gha update` warns if it
  does not match the tags on that SHA.
- GitHub-owned actions (`actions/*`, `github/*`) need not be listed, as they are
  allowed by the "Allow actions created by GitHub" setting.
- Although internal (`@ORG@`-owned) actions/workflows are always allowed, they
  should also be listed, at any ref (typically the default branch), so that their
  external dependencies are found - see below.

### Dependencies of internal actions

`gha update` only walks from what is listed in `@ORG@.actions.txt` and does not
scan the org's own repos. So if someone adds `uses: foo/bar@<sha>` to an internal
action `@ORG@/zob`, one of these must be true for `foo/bar@<sha>` to end up in
`@ORG@.final.txt`:

1. `@ORG@/zob@<ref>` is listed in `@ORG@.actions.txt`, so `gha update` walks it
   and finds `foo/bar@<sha>` as a transitive dependency. This is the recommended
   approach.
2. `foo/bar@<sha>` is listed in `@ORG@.actions.txt` directly.

If neither is listed then any run which tries to use `@ORG@/zob` will fail, with
the error showing why.

## Reviewing

```shell
gha review @ORG@                  # review every entry in @ORG@.final.txt
gha review @ORG@ --base GIT_REF   # review only entries added since GIT_REF
gha review foo/bar@ref            # review a single action
```

With `--base`, the entries added and removed since `GIT_REF` are also listed;
removed entries must be deleted from the allowlist in the web UI.

The review **fails** (exits non-zero) if any reviewed entry is known to be
vulnerable according to Zizmor's `known-vulnerable-actions` audit. This needs
network access and `GITHUB_TOKEN`; a warning is printed if it is disabled by
setting `ZIZMOR_OFFLINE`.

Note this **does not** review actions or their dependencies for malicious code.
What it also warns about is:

- Weak references, i.e. tags or branches rather than SHAs.
- Missing releases.
- Mutable releases.
- For docker based actions: docker image or base image in a Dockerfile not
  pinned to a SHA.
- For node based actions: entrypoint not bundled in `dist`, `lib` or `out`
  directories.
- Various Zizmor checks on the `action@ref` itself (e.g. SHA is from a fork),
  and on the action's `action.y{a,}ml` or the reusable workflow file.

As every transitive dependency is in `@ORG@.final.txt`, dependencies are
reviewed in their own right.

## Fixing actions in repos

```shell
gha fix @ORG@ docker-squid foo/bar
```

This clones the `docker-squid` repo from the `@ORG@` org (to `~`, or the existing
directory given by `-p`/`--path`), and rewrites every `uses: foo/bar@<anything>`
in its workflows and `action.y{a,}ml` files to `uses: foo/bar@<ref> # <version>`:

- `<ref>` is the only ref for `foo/bar` in `@ORG@.actions.txt`. If there is more
  than one, specify it as `foo/bar@<ref>`.
- `<version>` is taken from `@ORG@.final.json`; the comment is omitted if there
  is no version.

It fails if `foo/bar@<ref>` is not in `@ORG@.final.txt`, as it would be blocked
by the allowlist. Only `foo/bar` itself is changed, not e.g. `foo/bar/sub` or
`foo/bar-extra`. No GitHub token is needed, but cloning uses `git@github.com:`
so SSH access is.

It does not commit anything: review the changes, then branch, commit and open a
PR in the normal way.

## Scanning the org

```shell
gha scan @ORG@
```

This is not part of the normal workflow, but finds every action actually used,
directly or indirectly, by the active workflows in all non-archived `@ORG@`
repos. It can be used to find actions in use which are not covered by
`@ORG@.final.txt`. It takes a long time for a large org; if it fails part way,
rerun it with `--resume`.

It writes `@ORG@.json`, describing the actions from outside the org, e.g.:

```json
{
  "ConorMacBride/install-package": {
    "main": {
      "repos": ["atnorth-kayobe-config", "ecmwf-kayobe-config"],
      "sha": "3e7ad059e07782ee54fa35f827df52aae0626f30",
      "source": "branch",
      "version": "v1.1.0"
    }
  }
}
```

where `main` is the ref used, `repos` are the `@ORG@` repos which directly call
it at that ref (empty if it is only called indirectly), `sha` is what the ref
pointed to at scan time, `source` is `is_sha`, `branch` or `tag`, and `version`
is the most-specific tag on the SHA (or empty).

It also writes `@ORG@.calls.json` with the call chains to each action and ref,
and `@ORG@.db`, a cache used by `--resume` (gitignored).

## Updating gha

Change the ref in `requirements.txt`, then `pip install -r requirements.txt`.
