"""`gha update`: regenerate <org>.final.{txt,json} from <org>.actions.txt, reviewing entries with no recorded review."""

from __future__ import annotations

import logging

from ..allowlist import build_final, check_versions, final_json_path, final_txt_path, read_actions, walk, write_final
from ..github import GitHubAPI
from ..walker import Walker
from .review import review_and_record

log = logging.getLogger(__name__)


def update(api: GitHubAPI, org: str, do_review: bool = True) -> int:
    """Returns an exit status: non-zero if the review fails, in which case
    ORG.final.{txt,json} are not written."""
    entries = read_actions(org)
    log.info(f"Walking dependencies of {len(entries)} entries ...")
    walker = Walker(":memory:", api=api, org=org)
    walk(walker, entries)
    check_versions(walker, entries)

    final = build_final(walker, entries, org)
    if do_review:
        status = review_and_record(api, org, final)
        if status != 0:
            log.error(f"Review failed: NOT writing {final_txt_path(org)} or {final_json_path(org)}")
            return status

    write_final(org, final)
    log.info(f"Wrote {len(final)} entries to {final_txt_path(org)} and {final_json_path(org)}")
    return 0
