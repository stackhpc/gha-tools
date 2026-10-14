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

    parser_scan = subparsers.add_parser('scan', help='scan an org for used actions')
    parser_scan.set_defaults(task="scan", needs_token=True)
    parser_scan.add_argument('org', help="name of GitHub organisation")
    parser_scan.add_argument('--repo', help="name of repository (for dev)")
    parser_scan.add_argument('--resume', action='store_true', help="restart failed scan")

    parser_blocked = subparsers.add_parser(
        'blocked', help='report workflows from the last scan which are not allowed by ORG.final.txt')
    parser_blocked.set_defaults(task="blocked", needs_token=False)
    parser_blocked.add_argument('org', help="name of GitHub organisation")

    parser_update = subparsers.add_parser(
        'update', help='regenerate ORG.final.{txt,json} from ORG.actions.txt and review additions')
    parser_update.set_defaults(task="update", needs_token=True)
    parser_update.add_argument('org', help="name of GitHub organisation")
    parser_update.add_argument(
        '--base', help="git ref to review changes against, default: merge-base of HEAD and origin/main")
    parser_update.add_argument('--no-review', action='store_true', help="don't review added entries")

    parser_fix = subparsers.add_parser('fix', help='fix a repo to use an allowlisted action ref')
    parser_fix.set_defaults(task="fix", needs_token=False)
    parser_fix.add_argument('org', help="name of GitHub organisation")
    parser_fix.add_argument('repo', help="name of repo to fix")
    parser_fix.add_argument(
        'action', help="ACTION[@REF]; REF defaults to the only one for ACTION in ORG.actions.txt")
    parser_fix.add_argument('--path', '-p', default="~", help="path to clone repo to, defaults to ~")

    parser_review = subparsers.add_parser('review', help='review ORG.final.txt, or a selected action')
    parser_review.set_defaults(task="review", needs_token=True)
    parser_review.add_argument('target', help="name of GitHub organisation, or action@ref")
    parser_review.add_argument('--base', help="git ref: only review entries added to ORG.final.txt since this")

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
            sys.exit(update(api, args.org, args.base, not args.no_review))

        elif args.task == "fix":
            fix_repo(args.org, args.repo, args.action, args.path)

        elif args.task == "review":
            if "@" in args.target:
                if args.base:
                    parser.error("--base is only valid when reviewing an organisation")
                sys.exit(review_single(api, args.target))
            sys.exit(review_org(api, args.target, args.base))
    except (Transient, AllowlistError) as e:
        sys.exit(f"FATAL: {e}")


if __name__ == "__main__":
    main()
