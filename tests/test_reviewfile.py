import pytest

from gha_tools.allowlist import AllowlistError
from gha_tools.reviewfile import (
    effective_ai_outcome, format_review_txt, is_blocking, parse_review_txt, read_review, write_review,
)

SHA = "a" * 40

TEXT = f"""\
softprops/turnstyle@{SHA} (v1.0):
  WARNING no version specified
  using: node24
  AI review: CLEAN
    examined:    src/*.ts, action.yml
    limitations: dist/index.js is minified and was only grepped

a/b@{SHA}:
  using: composite
  AI review: SKIPPED: unpinned
"""


def test_parse():
    blocks = parse_review_txt(TEXT)
    assert list(blocks) == [f"softprops/turnstyle@{SHA}", f"a/b@{SHA}"]
    assert blocks[f"softprops/turnstyle@{SHA}"][0] == f"softprops/turnstyle@{SHA} (v1.0):"
    assert len(blocks[f"softprops/turnstyle@{SHA}"]) == 6
    assert blocks[f"a/b@{SHA}"][-1] == "  AI review: SKIPPED: unpinned"


def test_format_is_sorted_and_roundtrips():
    blocks = parse_review_txt(TEXT)
    out = format_review_txt(blocks)
    assert out.index(f"a/b@{SHA}") < out.index("softprops")  # sorted
    assert parse_review_txt(out) == blocks
    assert format_review_txt(parse_review_txt(out)) == out  # stable
    assert out.endswith("\n") and not out.endswith("\n\n")


def test_format_empty():
    assert format_review_txt({}) == ""


def test_text_outside_blocks_is_ignored():
    blocks = parse_review_txt(f"# comment\n\nnot a header\n  indented, but no block yet\n\nx/y@{SHA}:\n  using: composite\n\nstray\n  also stray\n")
    assert blocks == {f"x/y@{SHA}": [f"x/y@{SHA}:", "  using: composite"]}


def test_duplicate_block_is_an_error():
    with pytest.raises(AllowlistError, match="duplicate review block"):
        parse_review_txt(f"x/y@{SHA}:\n  a\n\nx/y@{SHA} (v1):\n  b\n")


def test_read_write(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert read_review("org") == {}
    blocks = parse_review_txt(TEXT)
    write_review("org", blocks)
    assert read_review("org") == blocks
    assert (tmp_path / "org.review.txt").read_text() == format_review_txt(blocks)


def block(*extra, outcome="SUSPICIOUS"):
    return [f"x/y@{SHA}:", f"  AI review: {outcome}", "    examined:    src/", *extra]


@pytest.mark.parametrize("lines, outcome, blocking", [
    (block(outcome="CLEAN"), "CLEAN", False),
    (block(outcome="SKIPPED: unpinned"), "SKIPPED", False),
    (block(), "SUSPICIOUS", True),
    (block(outcome="ERROR"), "ERROR", True),
    (block("    override: CLEAN - checked it"), "CLEAN", False),
    (block("    override: clean - lowercase is fine"), "CLEAN", False),
    (block("    override: CLEAN"), "CLEAN", False),
    (block("    override: OK - not a verdict"), "SUSPICIOUS", True),
    (block("    override: SUSPICIOUS"), "SUSPICIOUS", True),
    (block("    override: NOT CLEAN"), "SUSPICIOUS", True),  # only the first word counts
    (block("    override: CLEAN-ish"), "SUSPICIOUS", True),
    (block("      override: CLEAN - indented as if it were finding text"), "SUSPICIOUS", True),
    (block("  override: CLEAN - wrong indent"), "SUSPICIOUS", True),
    ([f"x/y@{SHA}:", "  using: composite"], None, False),  # no AI review recorded
])
def test_effective_outcome_and_blocking(lines, outcome, blocking):
    assert effective_ai_outcome(lines) == outcome
    assert is_blocking(lines) is blocking
