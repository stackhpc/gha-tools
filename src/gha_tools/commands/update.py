"""`gha update`: regenerate <org>.final.{txt,json} from <org>.actions.txt, then review what was added."""

from __future__ import annotations

import logging
from typing import Optional

from ..allowlist import (
    build_final, check_versions, default_base, final_json_path, final_txt_path, read_actions, walk, write_final,
)
from ..github import GitHubAPI
from ..walker import Walker
from .review import review_org

log = logging.getLogger(__name__)


def update(api: GitHubAPI, org: str, base: Optional[str] = None, do_review: bool = True) -> int:
    """Returns an exit status: non-zero if the review fails."""
    entries = read_actions(org)
    log.info(f"Walking dependencies of {len(entries)} entries ...")
    walker = Walker(":memory:", api=api, org=org)
    walk(walker, entries)
    check_versions(walker, entries)

    final = build_final(walker, entries, org)
    write_final(org, final)
    log.info(f"Wrote {len(final)} entries to {final_txt_path(org)} and {final_json_path(org)}")

    if not do_review:
        return 0
    return review_org(api, org, base or default_base())
