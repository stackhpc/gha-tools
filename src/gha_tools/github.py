"""
The single GitHub API client used throughout gha_tools.

Errors are split by whether retrying could help, which the graph walker
relies on for its resume/retry behaviour:

- NotFound:  permanent for this request -- 404, or any other 4xx such as a
             403 permission error. `.status` holds the HTTP status code.
- Transient: rate limiting, network errors and 5xx. Worth retrying later.
"""

from __future__ import annotations

import base64
from typing import Optional

import requests

BASE_URL = "https://api.github.com"
PER_PAGE = 100


class GitHubAPIError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class NotFound(GitHubAPIError):
    """Permanent failure: file/ref doesn't exist, or no permission. Do not retry."""


class Transient(GitHubAPIError):
    """Rate limit / network / 5xx. Retry later."""


class GitHubAPI:
    def __init__(self, token: Optional[str] = None, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    # -- low level ------------------------------------------------------------

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        if not url.startswith("https://"):
            url = f"{BASE_URL}/{url.lstrip('/')}"
        try:
            r = self.session.request(method, url, timeout=30, **kwargs)
        except requests.RequestException as e:
            raise Transient(str(e)) from e
        if r.status_code == 429 or (r.status_code == 403 and "rate limit" in r.text.lower()):
            reset = r.headers.get("X-RateLimit-Reset")
            raise Transient(f"rate limited (resets at unix time {reset}): {url}", r.status_code)
        if r.status_code >= 500:
            raise Transient(f"{r.status_code} from {url}", r.status_code)
        if not r.ok:
            raise NotFound(f"{r.status_code} from {url}: {r.text[:200]}", r.status_code)
        return r

    def get(self, url: str, **params):
        """GET a single (unpaginated) JSON response. `url` may be absolute
        or relative to the API root."""
        return self._request("GET", url, params=params).json()

    def get_paginated(self, url: str, **params) -> list:
        """GET every page of a list endpoint, following Link headers."""
        params = {"per_page": PER_PAGE, **params}
        data = []
        next_url: Optional[str] = url
        while next_url:
            r = self._request("GET", next_url, params=params)
            page = r.json()
            if not isinstance(page, list):
                raise GitHubAPIError(f"{next_url} returned {type(page).__name__}, not a list")
            data.extend(page)
            next_url = r.links.get("next", {}).get("url")
            params = {}  # the Link URL already carries them
        return data

    def exists(self, url: str) -> bool:
        """HEAD a URL; True only for a 200."""
        if not url.startswith("https://"):
            url = f"{BASE_URL}/{url.lstrip('/')}"
        try:
            return self.session.head(url, timeout=30).status_code == 200
        except requests.RequestException as e:
            raise Transient(str(e)) from e

    def graphql(self, query: str) -> dict:
        r = self._request("POST", f"{BASE_URL}/graphql", json={"query": query})
        data = r.json()
        if "errors" in data:
            raise GitHubAPIError(f"graphql errors: {data['errors']}")
        return data["data"]

    # -- helpers --------------------------------------------------------------

    def get_file_text(self, owner: str, repo: str, path: str, ref: str) -> str:
        """Decoded contents of a file. ref may be "HEAD" for the default branch."""
        data = self.get(f"repos/{owner}/{repo}/contents/{path}", ref=ref)
        if isinstance(data, list):
            raise NotFound(f"{owner}/{repo}/{path}@{ref} is a directory")
        if data.get("encoding") != "base64":
            raise Transient(f"unexpected encoding for {owner}/{repo}/{path}@{ref}")
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")

    def list_dir(self, owner: str, repo: str, path: str, ref: str) -> list[dict]:
        """Directory listing (one entry per file/subdir) at path ('' for root)."""
        data = self.get(f"repos/{owner}/{repo}/contents/{path}".rstrip("/"), ref=ref)
        if not isinstance(data, list):
            raise NotFound(f"{owner}/{repo}/{path}@{ref} is not a directory")
        return data

    def resolve_ref_sha(self, owner: str, repo: str, ref: str) -> str:
        return self.get(f"repos/{owner}/{repo}/commits/{ref}")["sha"]

    def list_tags(self, owner: str, repo: str) -> dict[str, str]:
        """{tag_name: commit_sha} for every tag in the repo."""
        return {t["name"]: t["commit"]["sha"] for t in self.get_paginated(f"repos/{owner}/{repo}/tags")}

    def get_release(self, owner: str, repo: str, tag: str) -> Optional[dict]:
        """The release for a tag, or None if there isn't one."""
        try:
            return self.get(f"repos/{owner}/{repo}/releases/tags/{tag}")
        except NotFound as e:
            if e.status == 404:
                return None
            raise
