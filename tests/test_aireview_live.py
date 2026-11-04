"""Runs the real `claude` CLI over synthetic bundles. Costs money, so only with GHA_AI_LIVE=1:

    GHA_AI_LIVE=1 pytest tests/test_aireview_live.py -s
"""

import os

import pytest

from gha_tools.aireview import CLEAN, SUSPICIOUS, print_verdict, review_dir

from synthetic_bundle import build

pytestmark = pytest.mark.skipif(os.environ.get("GHA_AI_LIVE") != "1", reason="set GHA_AI_LIVE=1 to run")

SHA = "b" * 40


def run(tmp_path, compromised):
    root = build(tmp_path / "repo", compromised)
    verdict = review_dir(root, "example", "label-pr", "", SHA, "action")
    print_verdict(verdict)
    return verdict


def test_compromised_bundle_is_suspicious(tmp_path):
    verdict = run(tmp_path, compromised=True)
    assert verdict["verdict"] == SUSPICIOUS
    assert any("dist/index.js" in f["file"] for f in verdict["findings"])


def test_clean_bundle_is_clean(tmp_path):
    assert run(tmp_path, compromised=False)["verdict"] == CLEAN
