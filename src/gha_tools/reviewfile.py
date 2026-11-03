"""ORG.review.txt: the committed record of the review of each pinned entry in ORG.final.txt.

The file is a sequence of the review blocks which `gha review` prints, e.g.:

    softprops/turnstyle@e565d2d86403c5d23533937e95980570545e5586:
      WARNING no version specified
      using: node24
      AI review: CLEAN
        examined:    src/*.ts, action.yml, package.json
        limitations: dist/index.js is minified and was only grepped

A block starts with an unindented `ENTRY:` or `ENTRY (VERSION):` line and continues over the
indented lines after it. Anything else in the file is not part of a block and is ignored (and so
is not kept when the file is rewritten).

A `SUSPICIOUS` AI review can be overridden by a person who has checked it, by adding a line
with exactly four spaces of indent to its block:

        override: CLEAN - reason goes here

Only the first word after `override:` is used, and only `CLEAN` has any effect. Four spaces is
required as the tool's own output (which can include text influenced by the code being
reviewed) never produces a line like this.
"""

from __future__ import annotations

import os
import re
from typing import Optional

from .aireview import CLEAN, ERROR, SUSPICIOUS
from .allowlist import AllowlistError, review_txt_path

_HEADER_RE = re.compile(r"^(\S+?)(?: \(.*\))?:$")
_AI_RE = re.compile(r"^ {2}AI review: (\w+)")
_OVERRIDE_RE = re.compile(r"^ {4}override:\s*(\S+)")


def parse_review_txt(text: str) -> dict[str, list[str]]:
    """{entry: lines of its block (starting with the header)}"""
    blocks: dict[str, list[str]] = {}
    current: Optional[str] = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            current = None
        elif not line.startswith(" "):
            current = None
            if m := _HEADER_RE.match(line):
                current = m.group(1)
                if current in blocks:
                    raise AllowlistError(f"duplicate review block for {current}")
                blocks[current] = [line]
        elif current is not None:
            blocks[current].append(line)
    return blocks


def format_review_txt(blocks: dict[str, list[str]]) -> str:
    return "".join("\n".join(blocks[uses]) + "\n\n" for uses in sorted(blocks)).rstrip("\n") + (
        "\n" if blocks else "")


def read_review(org: str) -> dict[str, list[str]]:
    """The blocks in ORG.review.txt, or none if it does not exist yet."""
    try:
        with open(review_txt_path(org)) as f:
            return parse_review_txt(f.read())
    except FileNotFoundError:
        return {}


def write_review(org: str, blocks: dict[str, list[str]]) -> None:
    with open(review_txt_path(org), "w") as f:
        f.write(format_review_txt(blocks))


def effective_ai_outcome(lines: list[str]) -> Optional[str]:
    """The AI review outcome recorded in a block after any override, None if it has none."""
    outcome = None
    for line in lines:
        if m := _AI_RE.match(line):
            outcome = m.group(1)
            break
    for line in lines:
        if (m := _OVERRIDE_RE.match(line)) and m.group(1).upper() == CLEAN:
            return CLEAN
    return outcome


def has_ai_review(lines: list[str]) -> bool:
    """Whether a block records an AI review outcome. One made with `--no-ai` doesn't."""
    return any(_AI_RE.match(line) for line in lines)


def is_blocking(lines: list[str]) -> bool:
    """Whether a stored block fails the review: an AI review which was not clean and not overridden."""
    return effective_ai_outcome(lines) in (SUSPICIOUS, ERROR)
