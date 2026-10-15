"""The shared GitHub client: error classification, pagination, helpers."""

import base64
import json

import pytest
import requests

from gha_tools.github import GitHubAPI, GitHubAPIError, NotFound, Transient, get_action_metadata


def response(status=200, body=None, headers=None, url="https://api.github.com/x"):
    r = requests.Response()
    r.status_code = status
    r._content = json.dumps(body).encode() if not isinstance(body, str) else body.encode()
    r.headers.update(headers or {})
    r.url = url
    return r


class FakeSession(requests.Session):
    """Serves queued responses by URL (absolute), recording requests."""

    def __init__(self, routes):
        super().__init__()
        self.routes = routes
        self.requests = []

    def request(self, method, url, params=None, json=None, timeout=None, **kw):
        self.requests.append((method, url, params, json))
        result = self.routes[(method, url)]
        if isinstance(result, Exception):
            raise result
        return result


def api_with(routes):
    session = FakeSession(routes)
    return GitHubAPI("tok", session=session), session


def test_auth_headers():
    api, session = api_with({})
    assert session.headers["Authorization"] == "Bearer tok"
    assert session.headers["Accept"] == "application/vnd.github+json"


@pytest.mark.parametrize(
    "status, body, headers, exc, exc_status",
    [
        (404, {"message": "Not Found"}, {}, NotFound, 404),
        (403, {"message": "Resource not accessible"}, {}, NotFound, 403),
        (401, {"message": "Bad credentials"}, {}, NotFound, 401),
        (403, {"message": "API rate limit exceeded"}, {"X-RateLimit-Reset": "123"}, Transient, 403),
        (429, {"message": "slow down"}, {}, Transient, 429),
        (502, "bad gateway", {}, Transient, 502),
    ],
)
def test_error_classification(status, body, headers, exc, exc_status):
    api, _ = api_with({("GET", "https://api.github.com/repos/o/r"): response(status, body, headers)})
    with pytest.raises(exc) as e:
        api.get("repos/o/r")
    assert e.value.status == exc_status


def test_network_error_is_transient():
    api, _ = api_with({("GET", "https://api.github.com/repos/o/r"): requests.ConnectionError("boom")})
    with pytest.raises(Transient):
        api.get("repos/o/r")


def test_get_relative_and_absolute_urls():
    ok = response(200, {"a": 1})
    api, session = api_with({("GET", "https://api.github.com/repos/o/r"): ok})
    assert api.get("repos/o/r") == {"a": 1}
    assert api.get("/repos/o/r") == {"a": 1}
    assert api.get("https://api.github.com/repos/o/r", ref="x") == {"a": 1}
    assert session.requests[-1][2] == {"ref": "x"}


def test_get_paginated_follows_links():
    p2 = "https://api.github.com/repositories/1/tags?per_page=100&page=2"
    api, session = api_with({
        ("GET", "https://api.github.com/repos/o/r/tags"): response(
            200, [{"name": "v1", "commit": {"sha": "a"}}], {"Link": f'<{p2}>; rel="next"'}),
        ("GET", p2): response(200, [{"name": "v2", "commit": {"sha": "b"}}]),
    })
    assert api.list_tags("o", "r") == {"v1": "a", "v2": "b"}
    assert [(r[1], r[2]) for r in session.requests] == [
        ("https://api.github.com/repos/o/r/tags", {"per_page": 100}),
        (p2, {}),
    ]


def test_get_paginated_rejects_non_list():
    api, _ = api_with({("GET", "https://api.github.com/x"): response(200, {"not": "a list"})})
    with pytest.raises(GitHubAPIError):
        api.get_paginated("x")


def test_get_file_text():
    content = base64.b64encode("hello: world\n".encode()).decode()
    url = "https://api.github.com/repos/o/r/contents/a/action.yml"
    api, session = api_with({("GET", url): response(200, {"encoding": "base64", "content": content})})
    assert api.get_file_text("o", "r", "a/action.yml", "HEAD") == "hello: world\n"
    assert session.requests[0][2] == {"ref": "HEAD"}


def test_get_file_text_directory_is_not_found():
    url = "https://api.github.com/repos/o/r/contents/a"
    api, _ = api_with({("GET", url): response(200, [{"name": "action.yml"}])})
    with pytest.raises(NotFound):
        api.get_file_text("o", "r", "a", "v1")


def test_list_dir_root_and_subdir():
    listing = [{"name": "action.yml"}]
    api, _ = api_with({
        ("GET", "https://api.github.com/repos/o/r/contents"): response(200, listing),
        ("GET", "https://api.github.com/repos/o/r/contents/sub"): response(200, listing),
    })
    assert api.list_dir("o", "r", "", "v1") == listing
    assert api.list_dir("o", "r", "sub", "v1") == listing


def test_get_release_missing_is_none():
    base = "https://api.github.com/repos/o/r/releases/tags/"
    api, _ = api_with({
        ("GET", base + "v1"): response(200, {"immutable": True}),
        ("GET", base + "v2"): response(404, {"message": "Not Found"}),
        ("GET", base + "v3"): response(403, {"message": "Forbidden"}),
    })
    assert api.get_release("o", "r", "v1") == {"immutable": True}
    assert api.get_release("o", "r", "v2") is None
    with pytest.raises(NotFound):
        api.get_release("o", "r", "v3")


def test_graphql_errors_raise():
    url = "https://api.github.com/graphql"
    api, _ = api_with({("POST", url): response(200, {"errors": [{"message": "bad"}]})})
    with pytest.raises(GitHubAPIError):
        api.graphql("query { x }")


def _file(text):
    return response(200, {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()})


def _notfound():
    return response(404, {"message": "Not Found"})


def test_get_action_metadata_prefers_yml_then_yaml():
    base = "https://api.github.com/repos/o/r/contents/sub/"
    api, session = api_with({("GET", base + "action.yml"): _file("yml"), ("GET", base + "action.yaml"): _file("yaml")})
    assert get_action_metadata(api, "o", "r", "sub", "v1") == "yml"
    assert len(session.requests) == 1  # no directory listing, no second fetch

    api, _ = api_with({("GET", base + "action.yml"): _notfound(), ("GET", base + "action.yaml"): _file("yaml")})
    assert get_action_metadata(api, "o", "r", "sub/", "v1") == "yaml"


def test_get_action_metadata_root_explicit_file_and_missing():
    root = "https://api.github.com/repos/o/r/contents/"
    api, _ = api_with({("GET", root + "action.yml"): _file("root")})
    assert get_action_metadata(api, "o", "r", "", "v1") == "root"

    api, _ = api_with({("GET", root + "x/action.yaml"): _file("direct")})
    assert get_action_metadata(api, "o", "r", "x/action.yaml", "v1") == "direct"

    api, _ = api_with({("GET", root + "action.yml"): _notfound(), ("GET", root + "action.yaml"): _notfound()})
    with pytest.raises(NotFound):
        get_action_metadata(api, "o", "r", "", "v1")
