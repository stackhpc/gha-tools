# @ORG@ GitHub Actions allowlist

The `@ORG@` GitHub organisation only allows workflows to use actions and reusable
workflows which are either:
- From the `@ORG@` org
- From github (`github/`, `actions/`)
- On an allowlist

This repository defines the allowlist and uses the `gha` [tool](https://github.com/stackhpc/gha-tools)
to maintain it.

> [!IMPORTANT]
> The allowlist in GitHub settings must be manually updated by an organisation admin when the allowlist
> here is changed. The permissions to automate that are considered too critical to expose.

## Usage for modifying allowed actions

This can be carried out by anyone with access to this repo:

1. Install the `gh` cli tool

2. Clone this repo and cd inside it

3. Setup:

   ```shell
   python3 -m venv venv
   . venv/bin/activate
   pip install -U pip
   pip install -r requirements.txt
   export GITHUB_TOKEN=$(gh auth token)
   ```

4. Modify `@ORG@.actions.txt` as required. It should include **all** actions
   and reusable worfklows which are directly called by `@ORG@` workflows which
   should be able to run. Include actions and reusable workflows from both `@ORG@`
   itself and third parties. Actions from github itself (`actions/`, `github/`) are always
   allowed and should not be included.

   When specifying actions/workflows from outside the organisation these should always be specified
   at a sha, e.g. `super-linter/super-linter@61abc07d755095a68f4987d1c2c3d1d64408f1f9` rather
   than a version or branch, unless for specific reasons.
   
   For full details on the format see [Actions file format](https://github.com/stackhpc/gha-tools/blob/main/README.md#actions-file-format).

5. Update the final allowlist `@ORG@.final.txt` by running:

   ```shell
   gha update @ORG@
   ```

   This finds all dependencies of the actions in `@ORG@.actions.txt`, and
   reviews the resultant list for [known-vulnerable actions](https://docs.zizmor.sh/audits/#known-vulnerable-actions).

6. If this succeeds, commit the updated files (`@ORG@.actions.txt`, `@ORG@.final.txt`,
   and `@ORG@.final.json` containing a call graph) to a branch and create a PR.

7. Once the PR has been reviewed and merged, an organisation admin must copy the updated allowlist
   from `@ORG@.final.txt` into the organisation's [Actions settings](https://github.com/organizations/@ORG@/settings/actions).

The `gha fix` tool may also be useful to update repositories.

## Usage for organisation maintenance

A workflow runs nightly to check all allowlisted external actions/workflows
for any which are known-vulerable. An alert is sent to the Slack channel
`github-actions-alerts` if this fails.

For other operations see the [Commands section of stackhpc/gha-tools README.md](https://github.com/stackhpc/gha-tools/blob/main/README.md#commands).
