"""
Record / replay GitHub HTTP traffic for regression testing.

Patches requests.sessions.Session.request, which every requests call in
gha_tools goes through (requests.get/head/post and explicit Sessions).

Cassettes are JSONL, one interaction per line, appended as they happen so a
killed recording keeps what it has. Only the request method/URL/body and the
response status, body and a few response headers (Link, Content-Type) are
stored -- never request headers, so the token is never written.

Modes:
    record  -- always hit the network, append every interaction
    replay  -- serve from the cassette only; a miss is fatal
    fill    -- serve hits from the cassette, hit the network on a miss and
               append it (for topping up after code changes)

Usage as a runner:
    python tests/cassette.py MODE CASSETTE -- <gha args...>
e.g.
    GITHUB_TOKEN=... python tests/cassette.py record stackhpc.jsonl -- scan stackhpc
"""

import contextlib
import json
import re
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

KEPT_RESPONSE_HEADERS = ("Link", "Content-Type")


# Batched existence checks, as built by find_workflows():
#   query { repository(owner: "o", name: "r") { a0: object(expression: "branch:path") { oid } ... } }
# The batch order/size isn't stable (built from a set), so these are also
# stored per-expression and reassembled on replay.
_GQL_REPO_RE = re.compile(r'^query \{ repository\(owner: "([^"]+)", name: "([^"]+)"\) \{ (.*) \} \}$', re.S)
_GQL_OBJ_RE = re.compile(r'(\w+): object\(expression: "([^"]*)"\) \{ oid \}')


def _gql_objects(json_body):
    """[(alias, 'owner/repo expression')] for a batched object query, else None."""
    if not isinstance(json_body, dict) or set(json_body) != {"query"}:
        return None
    m = _GQL_REPO_RE.match(json_body["query"])
    if not m:
        return None
    owner, repo, fields = m.groups()
    objs = _GQL_OBJ_RE.findall(fields)
    if not objs or _GQL_OBJ_RE.sub("", fields).strip():
        return None
    return [(alias, f"GQLOBJ {owner}/{repo} {expr}") for alias, expr in objs]


class CassetteMiss(BaseException):
    """Raised on a replay miss. Deliberately NOT an Exception subclass, so
    broad `except Exception` handlers in the code under test can't swallow
    it and silently turn a miss into e.g. an 'unresolved' node."""


def _normalise_url(url):
    """Sorted, de-duplicated query, ignoring paging params that don't change
    the response here: gha_tools always pages with per_page=100 (so per_page
    is noise -- and the old code sent it even to non-list endpoints) and
    page=1 is GitHub's default."""
    parts = urlsplit(url)
    params = {
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k != "per_page" and (k, v) != ("page", "1")
    }
    query = urlencode(sorted(params))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _renormalise_key(key):
    """Re-apply _normalise_url to a stored key, so cassettes recorded under an
    older normalisation still match."""
    if key.startswith("GQLOBJ "):
        return key
    method, url, body = key.split(" ", 2)
    return f"{method} {_normalise_url(url)} {body}"


def _key(method, url, params=None, data=None, json_body=None):
    prepared = requests.Request(method.upper(), url, params=params, data=data, json=json_body).prepare()
    body = prepared.body
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    return f"{prepared.method} {_normalise_url(prepared.url)} {body or ''}"


def _build_response(entry, request):
    r = requests.Response()
    r.status_code = entry["status"]
    r._content = entry["body"].encode("utf-8")
    r.headers = requests.structures.CaseInsensitiveDict(entry["headers"])
    r.url = entry["url"]
    r.encoding = "utf-8"
    r.request = request
    r.reason = entry.get("reason", "")
    return r


class Cassette:
    def __init__(self, path, mode):
        if mode not in ("record", "replay", "fill"):
            raise ValueError(mode)
        self.path = path
        self.mode = mode
        self.entries = {}
        self.misses = []
        self.hits = 0
        self.recorded = 0
        if mode != "record":
            self._load()

    def _load(self):
        with open(self.path) as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    self.entries[_renormalise_key(entry["key"])] = entry

    def _append(self, key, response):
        entry = {
            "key": key,
            "url": response.url,
            "status": response.status_code,
            "reason": response.reason,
            "headers": {h: response.headers[h] for h in KEPT_RESPONSE_HEADERS if h in response.headers},
            "body": response.content.decode("utf-8", errors="replace"),
        }
        self._write(entry)
        self.recorded += 1

    def _write(self, entry):
        self.entries[entry["key"]] = entry
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def _append_gql(self, gql, response):
        repo_data = (response.json().get("data") or {}).get("repository")
        if repo_data is None:
            return
        for alias, obj_key in gql:
            if alias in repo_data:
                self._write({"key": obj_key, "value": repo_data[alias]})

    def _assemble_gql(self, gql, url):
        if not gql or not all(obj_key in self.entries for _, obj_key in gql):
            return None
        data = {"data": {"repository": {alias: self.entries[obj_key]["value"] for alias, obj_key in gql}}}
        return {"url": url, "status": 200, "reason": "OK",
                "headers": {"Content-Type": "application/json"}, "body": json.dumps(data)}

    @contextlib.contextmanager
    def active(self):
        original = requests.sessions.Session.request
        cassette = self

        def patched(session, method, url, params=None, data=None, json=None, **kwargs):
            key = _key(method, url, params, data, json)
            gql = _gql_objects(json)
            if cassette.mode != "record":
                entry = cassette.entries.get(key) or cassette._assemble_gql(gql, url)
                if entry is not None:
                    cassette.hits += 1
                    request = requests.Request(method.upper(), url, params=params, data=data, json=json).prepare()
                    return _build_response(entry, request)
            if cassette.mode == "replay":
                cassette.misses.append(key)
                raise CassetteMiss(key[:300])
            response = original(session, method, url, params=params, data=data, json=json, **kwargs)
            cassette._append(key, response)
            if gql and response.ok:
                cassette._append_gql(gql, response)
            return response

        requests.sessions.Session.request = patched
        try:
            yield self
        finally:
            requests.sessions.Session.request = original


def run_gha(cassette_path, mode, gha_args):
    """Run the gha CLI with HTTP traffic recorded/replayed via a cassette."""
    from gha_tools import cli

    cassette = Cassette(cassette_path, mode)
    argv = sys.argv
    sys.argv = ["gha"] + list(gha_args)
    try:
        with cassette.active():
            cli.main()
    finally:
        sys.argv = argv
    return cassette


def _main():
    import os

    args = sys.argv[1:]
    if len(args) < 4 or args[2] != "--":
        sys.exit(__doc__)
    mode, path, gha_args = args[0], args[1], args[3:]
    # zizmor (run by `review`) talks to GitHub itself, invisibly to us:
    os.environ["ZIZMOR_OFFLINE"] = "true"
    if mode == "replay":
        os.environ.setdefault("GITHUB_TOKEN", "replay-dummy-token")
    from gha_tools import cli

    cassette = Cassette(path, mode)
    sys.argv = ["gha"] + gha_args
    try:
        with cassette.active():
            cli.main()
    finally:
        print(
            f"cassette: mode={mode} hits={cassette.hits} recorded={cassette.recorded} misses={len(cassette.misses)}",
            file=sys.stderr,
        )
        for miss in cassette.misses:
            print(f"  MISS {miss[:300]}", file=sys.stderr)


if __name__ == "__main__":
    _main()
