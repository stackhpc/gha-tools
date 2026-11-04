import io
import json
import tarfile

import pytest

from gha_tools import aireview
from gha_tools.aireview import AIReviewError, ai_review, parse_verdict
from gha_tools.commands import review

SHA = "a" * 40


def claude_json(verdict="CLEAN", **extra):
    return json.dumps({
        "is_error": False, "total_cost_usd": 0.12,
        "structured_output": {"verdict": verdict, "examined": "src/", "findings": [], **extra},
    })


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def iter_content(self, chunk_size):
        yield self.data


class FakeAPI:
    def __init__(self, files=None):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, content in (files or {"action.yml": b"name: x"}).items():
                info = tarfile.TarInfo(f"owner-repo-{SHA[:7]}/{name}")
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))
        self.tarball = buf.getvalue()
        self.requested = []

    def _request(self, method, url, **kwargs):
        self.requested.append(url)
        return FakeResponse(self.tarball)


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    """A `claude` which prints $FAKE_CLAUDE_OUT and records its args and cwd."""
    script = tmp_path / "claude"
    script.write_text(
        "#!/bin/sh\n"
        'echo "$@" > "$FAKE_CLAUDE_ARGS"\n'
        'pwd > "$FAKE_CLAUDE_CWD"\n'
        'ls >> "$FAKE_CLAUDE_CWD"\n'
        'printf "%s" "$FAKE_CLAUDE_OUT"\n'
        'exit ${FAKE_CLAUDE_STATUS:-0}\n'
    )
    script.chmod(0o755)
    monkeypatch.setenv("GHA_AI_CLAUDE", str(script))
    monkeypatch.setenv("FAKE_CLAUDE_ARGS", str(tmp_path / "args"))
    monkeypatch.setenv("FAKE_CLAUDE_CWD", str(tmp_path / "cwd"))
    monkeypatch.setenv("FAKE_CLAUDE_OUT", claude_json())
    return tmp_path


def test_parse_verdict():
    v = parse_verdict(claude_json("SUSPICIOUS"))
    assert v["verdict"] == "SUSPICIOUS"
    assert v["cost_usd"] == 0.12


@pytest.mark.parametrize("out", [
    "not json",
    json.dumps({"is_error": True, "result": "boom"}),
    json.dumps({"is_error": False, "result": "no structured output"}),
    json.dumps({"is_error": False, "structured_output": {"verdict": "maybe", "examined": "", "findings": []}}),
])
def test_parse_verdict_rejects_bad_output(out):
    with pytest.raises(AIReviewError):
        parse_verdict(out)


def test_ai_review_runs_readonly_claude_in_source_dir(fake_claude):
    api = FakeAPI()
    verdict = ai_review(api, "owner", "repo", "sub/dir", SHA, "action")
    assert verdict["verdict"] == "CLEAN"
    assert api.requested == [f"repos/owner/repo/tarball/{SHA}"]
    args = (fake_claude / "args").read_text()
    assert "--tools Read,Grep,Glob" in args
    assert "Bash" not in args
    assert "owner/repo/sub/dir at commit " + SHA in args
    cwd = (fake_claude / "cwd").read_text().split("\n")
    assert "action.yml" in cwd
    assert not (fake_claude / "args").read_text().startswith("/")


def test_ai_review_cleans_up(fake_claude, tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    ai_review(FakeAPI(), "owner", "repo", "", SHA, "action", workdir=work)
    assert list(work.iterdir()) == []


def test_ai_review_claude_failure(fake_claude, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_STATUS", "3")
    with pytest.raises(AIReviewError, match="exited 3"):
        ai_review(FakeAPI(), "owner", "repo", "", SHA, "action")


def test_ai_review_missing_claude(monkeypatch):
    monkeypatch.setenv("GHA_AI_CLAUDE", "/nonexistent/claude")
    with pytest.raises(AIReviewError, match="not found"):
        ai_review(FakeAPI(), "owner", "repo", "", SHA, "action")


def test_fetch_rejects_path_traversal(tmp_path):
    api = FakeAPI()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("top/../../escape")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    api.tarball = buf.getvalue()
    with pytest.raises(tarfile.TarError):
        aireview.fetch_source(api, "o", "r", SHA, tmp_path)
    assert not (tmp_path.parent / "escape").exists()


@pytest.fixture
def entry_stubs(monkeypatch):
    monkeypatch.setattr(review, "get_action_metadata", lambda *a: "name: x\nruns:\n  using: composite\n  steps: []")
    monkeypatch.setattr(review, "run_zizmor", lambda content, config=None: [])
    monkeypatch.setattr(review, "_zizmor_disabled_rules", lambda: set())


class GetReleaseAPI:
    def get_release(self, *a):
        return {"immutable": True}


def run_entry(uses, ai=True, info=None):
    return review.review_entry(GetReleaseAPI(), uses, info or {"version": "v1"}, [], set(), ai)


def test_review_entry_ai_suspicious_fails(entry_stubs, monkeypatch, capsys):
    monkeypatch.setattr(review, "ai_review", lambda *a: {"verdict": "SUSPICIOUS", "examined": "src/", "findings": []})
    result = run_entry(f"o/r@{SHA}")
    assert result.ai == "SUSPICIOUS" and result.failed
    assert "  AI review: SUSPICIOUS\n    examined:    src/\n" in capsys.readouterr().out


def test_review_entry_ai_clean(entry_stubs, monkeypatch):
    monkeypatch.setattr(review, "ai_review", lambda *a: {"verdict": "CLEAN", "examined": "src/", "findings": []})
    result = run_entry(f"o/r@{SHA}")
    assert result.ai == "CLEAN" and not result.failed and not result.vulnerable


def test_review_entry_ai_error_fails(entry_stubs, monkeypatch, capsys):
    def boom(*a):
        raise AIReviewError("no claude\nsecond line")
    monkeypatch.setattr(review, "ai_review", boom)
    result = run_entry(f"o/r@{SHA}")
    assert result.ai == "ERROR" and result.failed
    assert "  AI review: ERROR: no claude second line\n" in capsys.readouterr().out


def test_review_entry_unpinned_is_not_ai_reviewed(entry_stubs, monkeypatch, capsys):
    def fail(*a):
        raise AssertionError("must not be called")
    monkeypatch.setattr(review, "ai_review", fail)
    result = run_entry("o/r@master")
    assert result.ai == "SKIPPED" and not result.failed
    assert "  AI review: SKIPPED: unpinned\n" in capsys.readouterr().out


def test_review_entry_unpinned_is_not_ai_reviewed_even_if_resolved_to_a_sha(entry_stubs, monkeypatch):
    """final.json records the sha a mutable ref resolved to, but it's still mutable."""
    def fail(*a):
        raise AssertionError("must not be called")
    monkeypatch.setattr(review, "ai_review", fail)
    assert run_entry("o/r@master", info={"version": "v1", "sha": SHA}).ai == "SKIPPED"


def test_review_entry_no_ai_by_default(entry_stubs, monkeypatch):
    def fail(*a):
        raise AssertionError("must not be called")
    monkeypatch.setattr(review, "ai_review", fail)
    result = review.review_entry(GetReleaseAPI(), f"o/r@{SHA}", {"version": "v1"}, [], set())
    assert result.ai is None and not result.failed


def test_review_entry_missing_metadata_raises_entry_error(monkeypatch):
    from gha_tools.github import NotFound

    def missing(*a):
        raise NotFound("404")
    monkeypatch.setattr(review, "get_action_metadata", missing)
    with pytest.raises(review.EntryError, match="no action metadata file found for o/r/@"):
        run_entry(f"o/r@{SHA}", ai=False)


def test_print_verdict_layout(capsys):
    aireview.print_verdict({
        "verdict": "SUSPICIOUS", "examined": "src/ and dist/", "limitations": "dist/ is minified " * 10,
        "notes": "", "findings": [{"file": "dist/index.js", "concern": "eval of base64", "evidence": "eval(x)"}],
    })
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "  AI review: SUSPICIOUS"
    assert lines[1] == "    examined:    src/ and dist/"
    assert lines[2].startswith("    limitations: dist/ is minified")
    assert lines[3].startswith(" " * 17) and not lines[3].startswith(" " * 18)  # hanging indent
    assert all(len(line) <= 100 for line in lines)
    assert not any("notes" in line for line in lines)
    assert lines[-3:] == ["    findings:", "      dist/index.js: eval of base64", "        > eval(x)"]


def test_ai_review_failure_reason_from_json(fake_claude, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_STATUS", "1")
    monkeypatch.setenv("FAKE_CLAUDE_OUT", json.dumps({"terminal_reason": "api_error", "usage": {}}))
    with pytest.raises(AIReviewError, match="exited 1: api_error$"):
        ai_review(FakeAPI(), "owner", "repo", "", SHA, "action")
