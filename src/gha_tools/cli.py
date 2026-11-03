#!/usr/bin/env python3
"""
Tools to define an allowlist of GitHub Actions for an organisation, and update repos to match.

See the README.md for details.
"""

import logging
import os
import sys
from argparse import ArgumentParser

from .commands.blocked import blocked
from .commands.fix import fix_repo
from .allowlist import AllowlistError
from .commands.review import review_org, review_single
from .commands.scan import scan
from .commands.update import update
from .github import GitHubAPI, Transient


def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(levelname)s: %(message)s",
    )

    parser = ArgumentParser()
    subparsers = parser.add_subparsers(help='subcommand help', required=True)

    parser_scan = subparsers.add_parser(
        'scan', help='scan an org for used actions',
        description="Find every action used by the active workflows in an org's repos.")
    parser_scan.set_defaults(task="scan", needs_token=True)
    parser_scan.add_argument('org', help="name of GitHub organisation")
    parser_scan.add_argument('--repo', help="name of repository (for dev)")
    parser_scan.add_argument('--resume', action='store_true', help="restart failed scan")

    parser_blocked = subparsers.add_parser(
        'blocked', help='report workflows from the last scan which are not allowed by ORG.final.txt',
        description='Report workflows from the last scan which are not allowed by ORG.final.txt.')
    parser_blocked.set_defaults(task="blocked", needs_token=False)
    parser_blocked.add_argument('org', help="name of GitHub organisation")

    parser_update = subparsers.add_parser(
        'update', help='regenerate ORG.final.{txt,json} from ORG.actions.txt and review additions',
        description='Walk all dependencies of the entries in ORG.actions.txt, review the entries which '
                    'have no review in ORG.review.txt yet (recording the results there), then update the '
                    'allowlist ORG.final.txt and the provenance information in ORG.final.json if the review passes.')
    parser_update.set_defaults(task="update", needs_token=True)
    parser_update.add_argument('org', help="name of GitHub organisation")
    parser_update.add_argument('--no-review', action='store_true', help="don't review entries or update ORG.review.txt")

    parser_fix = subparsers.add_parser(
        'fix', help='fix a repo to use an allowlisted action ref',
        description='Clone a repo and rewrite its `uses:` of an action to the allowlisted ref.')
    parser_fix.set_defaults(task="fix", needs_token=False)
    parser_fix.add_argument('org', help="name of GitHub organisation")
    parser_fix.add_argument('repo', help="name of repo to fix")
    parser_fix.add_argument(
        'action', help="ACTION[@REF]; REF defaults to the only one for ACTION in ORG.actions.txt")
    parser_fix.add_argument('--path', '-p', default="~", help="path to clone repo to, defaults to ~")

    parser_review = subparsers.add_parser(
        'review', help='review ORG.final.txt, or a selected action',
        description='Review the entries in ORG.final.txt which have no review in ORG.review.txt yet, '
                    'recording the results there, or a specific action@ref (which is only printed). '
                    'Transitive dependencies are included. '
                    'Also AI-reviews the source of pinned entries unless --no-ai is given.')
    parser_review.set_defaults(task="review", needs_token=True)
    parser_review.add_argument('target', help="name of GitHub organisation, or action@ref")

    parser_review.add_argument(
        '--no-ai', action='store_true',
        help="skip the AI review of each (pinned) action's source, which is otherwise done and needs the claude CLI")
    parser_review.add_argument(
        '--force', action='store_true', help="review all entries again, replacing their blocks in ORG.review.txt "
                                             "(including any overrides in them)")

    args = parser.parse_args()
    api = None
    if args.needs_token:
        github_token = os.getenv('GITHUB_TOKEN')
        if github_token is None:
            sys.exit('FATAL: Must set GITHUB_TOKEN')
        api = GitHubAPI(github_token)

    try:
        if args.task == "scan":
            scan(api, args.org, args.repo, args.resume)

        elif args.task == "blocked":
            sys.exit(blocked(args.org))

        elif args.task == "update":
            sys.exit(update(api, args.org, not args.no_review))

        elif args.task == "fix":
            fix_repo(args.org, args.repo, args.action, args.path)

        elif args.task == "review":
            if args.force and "@" in args.target:
                parser.error("--force is only valid when reviewing an organisation")
            if "@" in args.target:
                sys.exit(review_single(api, args.target, not args.no_ai))
            sys.exit(review_org(api, args.target, not args.no_ai, args.force))
    except (Transient, AllowlistError) as e:
        sys.exit(f"FATAL: {e}")


if __name__ == "__main__":
    main()
