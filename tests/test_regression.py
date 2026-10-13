"""
Replay recorded real-org runs and compare against their saved outputs.

Each directory under tests/recordings/ (gitignored -- recordings can contain
private repo contents) with a regression.json manifest is one test:

    {
      "cassette": "stackhpc.jsonl",         # recorded with tests/cassette.py
      "args": ["scan", "stackhpc"],         # gha arguments
      "inputs": ["stackhpc.pinned.json"],   # optional: copied into the run dir
      "exit": 0,                            # optional: expected exit status
      "expected": {                         # files in expected/ to compare;
        "stackhpc.json": "stackhpc.json",   #   "<stdout>" for captured stdout
        "<stdout>": "review.out"
      }
    }

Skipped entirely if there are no recordings.
"""

import json
import os
import pathlib
import shutil
import sys

import pytest

from cassette import Cassette
from gha_tools import cli

RECORDINGS = pathlib.Path(__file__).parent / "recordings"
MANIFESTS = sorted(RECORDINGS.glob("*/regression.json"))


@pytest.mark.skipif(not MANIFESTS, reason="no recordings in tests/recordings/")
@pytest.mark.parametrize("manifest_path", MANIFESTS, ids=[m.parent.name for m in MANIFESTS])
def test_replay(manifest_path, tmp_path, monkeypatch, capsys):
    rec_dir = manifest_path.parent
    manifest = json.loads(manifest_path.read_text())

    for name in manifest.get("inputs", []):
        shutil.copy(rec_dir / name, tmp_path / name)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_TOKEN", "replay-dummy-token")
    monkeypatch.setenv("ZIZMOR_OFFLINE", "true")
    # zizmor is installed alongside this interpreter:
    monkeypatch.setenv("PATH", f"{pathlib.Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(sys, "argv", ["gha"] + manifest["args"])

    cassette = Cassette(str(rec_dir / manifest["cassette"]), "replay")
    code = 0
    with cassette.active():
        try:
            cli.main()
        except SystemExit as e:
            code = e.code or 0
    assert code == manifest.get("exit", 0)
    stdout = capsys.readouterr().out
    assert cassette.misses == []

    for produced, expected in manifest["expected"].items():
        want = (rec_dir / "expected" / expected).read_text()
        got = stdout if produced == "<stdout>" else (tmp_path / produced).read_text()
        assert got == want, f"{produced} differs from expected/{expected}"
