"""Bounded source collectors; completion cursors are promoted by the worker transaction."""

import base64
import hashlib
import io
import os
import re
import subprocess
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx
from . import fingerprints, remediation
from .artifacts import MAX_SET, MAX_FILE, MAX_SOURCE_FILES
from .cves import compare_versions, cpe_identity
from .models import now, utc
from .schemas import safe_path
from .security import DomainError, retry_delay

TAG_PAGES = 4  # Bounded newest-first tag catalog; vendor release histories are far shorter.
MIRROR_SECONDS = 300

# Binary media is not source evidence; omitting it keeps CMS-sized snapshots within bounds.
MEDIA_SUFFIXES = frozenset(
    ".avif .bmp .eot .flac .gif .ico .jpeg .jpg .m4a .mov .mp3 .mp4 .ogg .otf .png .psd"
    " .tif .tiff .ttf .wav .webm .webp .woff .woff2".split()
)


def media(path):
    return Path(path).suffix.lower() in MEDIA_SUFFIXES


def github_token_required():
    return DomainError(
        "github_token_required",
        "Add a GitHub read token (Contents and Metadata) under Settings, Accounts. "
        "GitHub repositories are not polled without it.",
        422,
    )


def github_write_token_required():
    return DomainError(
        "github_write_token_required",
        "Add a GitHub write token (fine-grained; Contents and Pull requests: read and write; Own "
        "repositories only) under Settings, Integrations. Remediation PRs are not opened without it.",
        422,
    )


def release_branch_candidates(version):
    """The branch names that may carry the release line of `version`, in matching order."""
    match = re.match(r"v?(\d+)(?:\.(\d+))?", version)
    if not match:
        return []
    major, minor = match.groups()
    return [f"{major}.x", *([f"{major}.{minor}"] if minor else []), f"release-{major}", f"v{major}"]


def feed_json(response, kind=dict):
    """The JSON body of an advisory feed's answer, which must be a `kind`: feed data is untrusted."""
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, kind):
        raise DomainError("invalid_source_response",
                          f"{response.request.url.host} did not answer with a JSON {kind.__name__}", 502)
    return body


def github_parents(data):
    parents = data.get("parents") if isinstance(data, dict) else None
    if not isinstance(parents, list) or any(not isinstance(p, dict) or not isinstance(p.get("sha"), str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", p["sha"]) for p in parents):
        raise DomainError("invalid_source_response", "Source omitted valid immutable parent revisions", 502)
    return [p["sha"] for p in parents]


class Sources:
    def __init__(self, config, github_key=None, nvd_key=None, heartbeat=lambda: None):
        self.config, self.heartbeat = config, heartbeat
        self.github_key, self.nvd_key = github_key, nvd_key
        self.client = httpx.Client(timeout=30, follow_redirects=False)
        self.github = (
            os.getenv("NUMEN_GITHUB_API_URL", "https://api.github.com")
            if config.test_mode
            else "https://api.github.com"
        )
        # Where github_mirror clones from.
        self.git = (
            os.getenv("NUMEN_GITHUB_GIT_URL", "https://github.com").rstrip("/")
            if config.test_mode
            else "https://github.com"
        )
        self.nvd = (
            os.getenv("NUMEN_NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
            if config.test_mode
            else "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
        self.npm = (
            os.getenv("NUMEN_NPM_REGISTRY_URL", "https://registry.npmjs.org")
            if config.test_mode
            else "https://registry.npmjs.org"
        )
        self.packagist = (
            os.getenv("NUMEN_PACKAGIST_URL", "https://repo.packagist.org")
            if config.test_mode
            else "https://repo.packagist.org"
        )
        self.osv = os.getenv("NUMEN_OSV_URL", "https://api.osv.dev") if config.test_mode else "https://api.osv.dev"

    def close(self):
        self.client.close()

    def get(self, url, params=None, headers=None, limit=MAX_SET, json=None):
        """GET `url`, or POST the `json` body. A 304 is an answer like any other below 400."""
        self.heartbeat()
        method = "GET" if json is None else "POST"
        for attempt in range(4):
            try:
                with self.client.stream(method, url, params=params, headers=headers, json=json) as stream:
                    content = bytearray()
                    for chunk in stream.iter_bytes(chunk_size=256 * 1024):
                        self.heartbeat()
                        content.extend(chunk)
                        if len(content) > limit:
                            raise DomainError(
                                "source_response_limit",
                                "Upstream response exceeds the bounded source size",
                                413,
                            )
                    # iter_bytes() already decoded any Content-Encoding; do not decode it again.
                    response_headers = httpx.Headers(stream.headers)
                    for name in ("content-encoding", "content-length"):
                        response_headers.pop(name, None)
                    response = httpx.Response(
                        stream.status_code,
                        headers=response_headers,
                        content=bytes(content),
                        request=stream.request,
                    )
            except httpx.HTTPError as exc:
                raise DomainError(
                    "source_unavailable",
                    "Upstream network request failed; its completion cursor was retained",
                    502,
                    retryable=True,
                ) from exc
            if response.status_code == 429 or response.status_code in (502, 503, 504):
                delay = retry_delay(response.headers.get("Retry-After"), 2**attempt, 30)
                time.sleep(delay)
                self.heartbeat()
                continue
            if response.status_code >= 400:
                raise DomainError(
                    "upstream_error",
                    f"Source returned HTTP {response.status_code}",
                    502,
                    retryable=response.status_code >= 500,
                )
            return response
        raise DomainError(
            "upstream_rate_limited",
            "Source rate limit or temporary outage prevented a complete sync",
            503,
            retryable=True,
        )

    def find(self, url, params=None, headers=None):
        """get(), or None when the source answers 404."""
        try:
            return self.get(url, params, headers)
        except DomainError as exc:
            if exc.code == "upstream_error" and "404" in exc.message:
                return None
            raise

    def github_file(self, repository, path, ref):
        """The text of `path` under the repository's source_path at `ref`, or None without it."""
        repo = repository.source_url.removeprefix("https://github.com/")
        if repository.source_path:
            path = repository.source_path.rstrip("/") + "/" + path
        response = self.find(
            f"{self.github}/repos/{repo}/contents/{quote(path)}",
            {"ref": ref},
            {**self.github_headers(), "Accept": "application/vnd.github.raw+json"},
        )
        return None if response is None else response.text

    def send(self, method, url, body):
        """One GitHub write request (A08), never retried: a lost answer is found again by its
        branch name. Returns GitHub's JSON answer."""
        self.heartbeat()
        try:
            response = self.client.request(method, url, json=body, headers=self.github_headers())
        except httpx.HTTPError as exc:
            raise DomainError("github_unavailable", "GitHub could not be reached; approve again to retry", 502,
                              retryable=True) from exc
        if response.status_code >= 400:
            try:
                detail = str(response.json().get("message") or "")[:300]
            except (ValueError, AttributeError):
                detail = ""
            raise DomainError("github_write_failed", f"GitHub answered {method} {url.removeprefix(self.github)} "
                              f"with HTTP {response.status_code}: {detail}", 502, retryable=response.status_code >= 500)
        return response.json()

    def npm_version(self, name, version):
        """The npm registry's metadata of `version` (the latest without one), or None when the
        registry does not have it."""
        response = self.find(f"{self.npm}/{quote(name, safe='@')}/{quote(version or 'latest', safe='')}")
        return None if response is None else response.json()

    def npm_tarball(self, dist):
        """The bytes of the npm tarball that `dist` (a version's registry dist) names, at most MAX_FILE:
        only from the registry Asset Monitor reads, and only when they match dist.integrity's sha512."""
        url = str((dist or {}).get("tarball") or "")
        if not url.startswith(self.npm.rstrip("/") + "/"):
            raise DomainError("package_untrusted", f"The tarball {url[:200]!r} is not on the npm registry {self.npm}", 422)
        expected = next((h.removeprefix("sha512-") for h in str((dist or {}).get("integrity") or "").split()
                         if h.startswith("sha512-")), None)
        if not expected:
            raise DomainError("package_untrusted", f"The tarball {url[:200]!r} has no sha512 integrity", 422)
        data = self.get(url, limit=MAX_FILE).content
        if base64.b64encode(hashlib.sha512(data).digest()).decode() != expected:
            raise DomainError("package_untrusted", f"The tarball {url[:200]!r} does not match its registry integrity", 422)
        return data

    def npm_repository(self, name, version):
        """The repository field of the npm metadata of `version` (the latest without one), ""
        when it has none, or None when the registry does not have it."""
        data = self.npm_version(name, version)
        return None if data is None else data.get("repository") or ""

    def packagist_repository(self, name, version):
        """source.url of the Packagist entry for `version` (else the newest), "" when it has none,
        or None when Packagist does not have the package."""
        response = self.find(f"{self.packagist}/p2/{quote(name)}.json")
        if response is None:
            return None
        entries, entry = [], {}
        for item in (response.json().get("packages") or {}).get(name) or []:
            entry = {**entry, **item}  # p2 metadata is minified: each entry lists what changed
            entries.append(entry)
        match = next(
            (e for e in entries if str(e.get("version", "")).lstrip("v") == (version or "").lstrip("v")),
            entries[0] if entries else {},
        )
        source = match.get("source")
        return (source.get("url") or "") if isinstance(source, dict) else ""

    def github_headers(self):
        """Headers for every GitHub request. A GitHub repository is never read without a token."""
        if not self.github_key:
            raise github_token_required()
        return {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {self.github_key}",
        }

    def github_branch(self, repository, name):
        """Whether the branch exists."""
        repo = repository.source_url.removeprefix("https://github.com/")
        try:
            response = self.get(
                f"{self.github}/repos/{repo}/branches/{quote(name, safe='')}",
                headers=self.github_headers(),
            )
        except DomainError as exc:
            if exc.code == "upstream_error" and "404" in exc.message:
                return False
            raise
        if response.status_code != 200:
            raise DomainError("upstream_error", f"Source returned HTTP {response.status_code}", 502)
        return True

    def github_commits(self, repository, branch=None, cursor=None, etag=None):
        """(head, new commits oldest first, ETag) of `branch` since `cursor`, by default the
        default branch since the repository's cursor. A branch's first check only sets its
        Baseline at the head; a 304 for its ETag returns before any other request."""
        if branch is None:
            branch, cursor, etag = repository.source_ref or "HEAD", repository.cursor, repository.etag
        repo = repository.source_url.removeprefix("https://github.com/")
        headers = self.github_headers()
        params = {"per_page": 100, "sha": branch}
        response = self.get(
            f"{self.github}/repos/{repo}/commits",
            {**params, "page": 1},
            {**headers, "If-None-Match": etag} if etag else headers,
        )
        if response.status_code == 304:
            return cursor, [], etag
        etag = response.headers.get("etag")
        first = response.json()
        if not isinstance(first, list):
            raise DomainError("invalid_source_response", "GitHub did not return a commit list", 502)
        head = first[0]["sha"] if first else cursor
        if head and not re.fullmatch(r"[0-9a-fA-F]{40,64}", head):
            raise DomainError(
                "invalid_source_revision", "GitHub returned an invalid immutable revision", 502
            )
        if cursor is None or head == cursor:
            return head, [], etag
        found, history_rewritten = [], False
        comparison = None
        try:
            comparison = self.get(
                f"{self.github}/repos/{repo}/compare/{cursor}...{head}",
                {"per_page": 100, "page": 1},
                headers,
            ).json()
        except DomainError as exc:
            if exc.code != "upstream_error" or "404" not in exc.message:
                raise
            history_rewritten = True
        if comparison and comparison.get("status") in ("ahead", "identical"):
            found = list(comparison.get("commits", []))
            total = comparison.get("total_commits")
            if not isinstance(total, int) or total < len(found):
                raise DomainError(
                    "invalid_source_response",
                    "GitHub compare omitted the complete commit count",
                    502,
                )
            page = 2
            while len(found) < total:
                extra = (
                    self.get(
                        f"{self.github}/repos/{repo}/compare/{cursor}...{head}",
                        {"per_page": 100, "page": page},
                        headers,
                    )
                    .json()
                    .get("commits", [])
                )
                if not extra or page > 1000:
                    raise DomainError(
                        "incomplete_source_page",
                        "Compare pagination did not return every unseen revision; cursor retained",
                        502,
                    )
                found.extend(extra)
                page += 1
            found.reverse()  # Compare order is chronological; common processing order below reverses again.
        else:
            # The cursor is no longer an ancestor of the head: history was rewritten.
            history_rewritten = True
            found = list(first)
            if len(first) == 100:
                for page in range(2, 1001):
                    items = self.get(
                        f"{self.github}/repos/{repo}/commits", {**params, "page": page}, headers
                    ).json()
                    if not isinstance(items, list):
                        raise DomainError(
                            "invalid_source_response", "GitHub did not return a commit list", 502
                        )
                    found.extend(items)
                    if len(items) < 100:
                        break
                else:
                    raise DomainError(
                        "source_history_limit",
                        "Source history exceeds one bounded sync; no cursor was advanced",
                        422,
                    )
        records = [self.github_record(repository, item, history_rewritten) for item in reversed(found)]
        return head, [record for record in records if record], etag

    def github_backfill(self, repository, count):
        """The last `count` commits up to and including the Baseline, oldest first."""
        repo = repository.source_url.removeprefix("https://github.com/")
        items = self.get(
            f"{self.github}/repos/{repo}/commits",
            {"sha": repository.baseline_revision, "per_page": count},
            self.github_headers(),
        ).json()
        if not isinstance(items, list):
            raise DomainError("invalid_source_response", "GitHub did not return a commit list", 502)
        records = [self.github_record(repository, item) for item in reversed(items[:count])]
        return [record for record in records if record]

    def github_record(self, repository, item, history_rewritten=False):
        """One commit with its capped diff, or None when it changes nothing under source_path."""
        repo = repository.source_url.removeprefix("https://github.com/")
        headers = self.github_headers()
        revision = item["sha"]
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", revision):
            raise DomainError(
                "invalid_source_revision", "GitHub returned an invalid commit revision", 502
            )
        detail = self.get(
            f"{self.github}/repos/{repo}/commits/{revision}", {"per_page": 100}, headers
        ).json()
        files = list(detail.get("files", []))
        # Commit endpoint paginates changed files independently of history.
        if len(files) == 100:
            for page in range(2, 31):
                extra = (
                    self.get(
                        f"{self.github}/repos/{repo}/commits/{revision}",
                        {"per_page": 100, "page": page},
                        headers,
                    )
                    .json()
                    .get("files", [])
                )
                files.extend(extra)
                if len(extra) < 100:
                    break
            else:
                raise DomainError(
                    "source_diff_limit", "Commit file pagination exceeded the bounded sync", 422
                )
        if repository.source_path:
            prefix = repository.source_path.rstrip("/")
            files = [
                f
                for f in files
                if f.get("filename") == prefix
                or f.get("filename", "").startswith(prefix + "/")
                or f.get("previous_filename") == prefix
                or f.get("previous_filename", "").startswith(prefix + "/")
            ]
            if not files:
                return None
        data = detail.get("commit", item.get("commit", {}))
        diffs = []
        complete = bool(files)
        for f in files:
            patch = f.get("patch")
            if patch is None:
                complete = False
            else:
                diffs.append(
                    f"--- {f.get('previous_filename', f['filename'])}\n+++ {f['filename']}\n{patch}"
                )
                if len(patch) > 60000:
                    complete = False
        diff = "\n".join(diffs)
        if len(diff.encode()) > 2 * 1024 * 1024:
            diff, complete = diff[: 2 * 1024 * 1024], False
        return {
            "revision": revision,
            "message": data.get("message", ""),
            "author": data.get("author", {}).get("name", ""),
            "committed_at": data.get("committer", {}).get("date"),
            "url": f"{repository.source_url}/commit/{revision}",
            "files": [
                {
                    "path": f["filename"],
                    "status": f.get("status"),
                    "previous_path": f.get("previous_filename"),
                }
                for f in files
            ],
            "diff": diff,
            "diff_complete": complete,
            "history_rewritten": history_rewritten,
            **({"parent_revisions": github_parents(detail)} if "parents" in detail else {}),
        }

    def snapshot_github(self, repository, revision):
        repo = repository.source_url.removeprefix("https://github.com/")
        headers = self.github_headers()
        response = self.get(
            f"{self.github}/repos/{repo}/tarball/{quote(revision, safe='')}", headers=headers
        )
        # Only GitHub's canonical codeload host may receive a redirect; never forward credentials.
        if response.status_code in (301, 302, 307, 308):
            destination = response.headers.get("location", "")
            if not destination.startswith("https://codeload.github.com/"):
                raise DomainError("unsafe_source_redirect", "Unexpected archive redirect", 502)
            response = self.get(destination)
        if len(response.content) > MAX_SET:
            raise DomainError("source_snapshot_limit", "Source archive exceeds its size limit", 422)
        files, total = {}, 0
        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                relative = member.name.split("/", 1)[-1]
                safe_path(relative)
                if (
                    repository.source_path
                    and not relative.startswith(repository.source_path.rstrip("/") + "/")
                    and relative != repository.source_path
                ) or media(relative):
                    continue
                total += member.size
                if member.size > MAX_FILE or total > MAX_SET or len(files) >= MAX_SOURCE_FILES:
                    raise DomainError(
                        "source_snapshot_limit", "Expanded source exceeds the bounded snapshot", 422
                    )
                files[relative] = archive.extractfile(member).read()
        return files

    def github_tags(self, repository):
        """Bounded newest-first tag catalog with each tag's immutable commit."""
        repo = repository.source_url.removeprefix("https://github.com/")
        headers = self.github_headers()
        tags = []
        for page in range(1, TAG_PAGES + 1):
            batch = self.get(
                f"{self.github}/repos/{repo}/tags", {"per_page": 100, "page": page}, headers
            ).json()
            if not isinstance(batch, list):
                raise DomainError("invalid_source_response", "GitHub did not return a tag list", 502)
            tags += [
                (tag["name"], tag["commit"]["sha"])
                for tag in batch
                if tag.get("name") and (tag.get("commit") or {}).get("sha")
            ]
            if len(batch) < 100:
                break
        return tags

    @contextmanager
    def github_mirror(self, repository):
        """A blobless bare clone of the GitHub repository, read-only (A05): yields run(*args,
        stdin=None), git's stdout in it. Nothing is ever checked out, so no hook, filter or
        checkout script runs. The read token reaches git only through its environment, scoped to
        the GitHub base, never its arguments, and lazy blob fetches use it too."""
        # ponytail: a fresh blobless clone per job; keep a fetched mirror per repository if large
        # Upstream clones get slow
        scheme = urlparse(self.git).scheme
        env = {"GIT_ALLOW_PROTOCOL": scheme if self.config.test_mode else "https"}
        if self.github_key:
            basic = base64.b64encode(f"x-access-token:{self.github_key}".encode()).decode()
            env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0=f"http.{self.git}/.extraheader",
                       GIT_CONFIG_VALUE_0=f"Authorization: Basic {basic}")
        elif scheme == "https":
            raise github_token_required()
        repo = repository.source_url.removeprefix("https://github.com/")
        with tempfile.TemporaryDirectory(prefix="asset-monitor-mirror-") as directory:
            root = Path(directory, "mirror.git")
            root.mkdir()
            self.heartbeat()
            try:
                remediation.git(root, "clone", "--bare", "--filter=blob:none", "--quiet",
                                f"{self.git}/{repo}.git", ".", env=env, timeout=MIRROR_SECONDS)
            except DomainError as exc:
                raise DomainError("mirror_unavailable", f"{repo} could not be cloned: {exc.message}", 502) from exc

            def run(*args, stdin=None):
                self.heartbeat()
                return remediation.git(root, *args, stdin=stdin, env=env, timeout=MIRROR_SECONDS)

            yield run

    def vulnerable_tag(self, repository, bound, inclusive, scheme):
        """Newest release tag a record still reports as affected, pinned to its own commit."""
        best = None
        for name, sha in self.github_tags(repository):
            compared = compare_versions(name, bound, scheme)
            if compared is None or compared > 0 or (compared == 0 and not inclusive):
                continue
            if best is None or (compare_versions(name, best["version"], scheme) or 0) > 0:
                best = {"version": name, "source_ref": sha}
        return best

    def commit_ref(self, repository, ref):
        """Resolve a tag, branch or abbreviated revision to its immutable commit."""
        repo = repository.source_url.removeprefix("https://github.com/")
        headers = self.github_headers()
        try:
            data = self.get(
                f"{self.github}/repos/{repo}/commits/{quote(ref, safe='/')}", headers=headers
            ).json()
        except DomainError as exc:
            if exc.code == "upstream_error" and "404" in exc.message:
                raise DomainError(
                    "unknown_source_ref", f"Source has no revision {ref}", 422
                ) from exc
            raise
        sha = data.get("sha") if isinstance(data, dict) else None
        if not sha:
            raise DomainError("invalid_source_response", "GitHub did not return a commit", 502)
        return sha

    def commit_parents(self, repository, revision):
        repo = repository.source_url.removeprefix("https://github.com/")
        headers = self.github_headers()
        data = self.get(f"{self.github}/repos/{repo}/commits/{quote(revision, safe='')}", headers=headers).json()
        if not isinstance(data, dict) or data.get("sha") != revision:
            raise DomainError("invalid_source_response", "Source returned a different commit while resolving its parents", 502)
        return github_parents(data)

    def svn(self, *args):
        self.heartbeat()
        try:
            proc = subprocess.run(
                [os.getenv("NUMEN_SVN", "svn"), *args, "--non-interactive"],
                capture_output=True,
                timeout=90,
                check=True,
            )
            return proc.stdout
        except FileNotFoundError as exc:
            raise DomainError(
                "svn_unavailable", "WordPress monitoring requires the bundled SVN client", 503
            ) from exc
        except subprocess.SubprocessError as exc:
            raise DomainError(
                "svn_error",
                "WordPress SVN request failed; its completion cursor was retained",
                502,
                retryable=True,
            ) from exc

    def svn_root(self, repository):
        """The plugin's SVN root, holding trunk and tags."""
        if self.config.test_mode and os.getenv("NUMEN_WORDPRESS_SVN_URL"):
            return os.environ["NUMEN_WORDPRESS_SVN_URL"].rstrip("/") + "/" + repository.plugin_slug
        return repository.source_url

    def svn_url(self, repository):
        path = repository.source_ref or "trunk"
        if repository.source_path:
            path += "/" + repository.source_path
        return self.svn_root(repository) + "/" + path

    def svn_tags(self, repository):
        """{tag: revision} of the plugin's tags/ (A05): a tag copied from trunk counts at the
        revision it was copied from, and one added without a copy at the revision that added it."""
        log = ET.fromstring(self.svn("log", "-v", "--xml", self.svn_root(repository) + "/tags"))
        tags = {}
        for entry in reversed(log.findall("logentry")):  # oldest first, so a later copy wins
            for path in entry.findall("paths/path"):
                match = re.search(r"/tags/([^/]+)$", path.text or "")
                if not match:
                    continue
                if path.attrib.get("action") == "D":
                    tags.pop(match.group(1), None)
                elif path.attrib.get("action") in ("A", "R"):
                    tags[match.group(1)] = int(path.attrib.get("copyfrom-rev") or entry.attrib["revision"])
        return tags

    def wordpress_commits(self, repository):
        """(head, new revisions oldest first, None). The first check only sets the Baseline."""
        url = self.svn_url(repository)
        info = ET.fromstring(self.svn("info", "--xml", url))
        head = info.find("entry").attrib["revision"]
        if repository.cursor is None or int(repository.cursor) >= int(head):
            return head, [], None
        log = ET.fromstring(
            self.svn("log", "--xml", "-v", "-r", f"{int(repository.cursor) + 1}:{head}", url)
        )
        entries = list(log.findall("logentry"))
        if len(entries) > 10000:
            raise DomainError(
                "source_history_limit", "WordPress history exceeds the bounded sync", 422
            )
        return head, [self.svn_record(repository, url, entry) for entry in entries], None

    def wordpress_backfill(self, repository, count):
        """The last `count` revisions up to and including the Baseline, oldest first."""
        url = self.svn_url(repository)
        log = ET.fromstring(self.svn(
            "log", "--xml", "-v", "-l", str(count), "-r", f"{repository.baseline_revision}:1", url
        ))
        return [self.svn_record(repository, url, entry) for entry in reversed(log.findall("logentry"))]

    def svn_record(self, repository, url, entry):
        rev = entry.attrib["revision"]
        try:
            diff = self.svn("diff", "-c", rev, url).decode(errors="replace")
            complete = len(diff.encode()) <= 2 * 1024 * 1024
        except DomainError:
            diff, complete = "", False
        return {
            "revision": rev,
            "message": entry.findtext("msg", ""),
            "author": entry.findtext("author", ""),
            "committed_at": entry.findtext("date"),
            "url": f"https://plugins.trac.wordpress.org/changeset/{rev}/{repository.plugin_slug}",
            "files": [
                {"path": p.text, "status": p.attrib.get("action")}
                for p in entry.findall("paths/path")
            ],
            "diff": diff[: 2 * 1024 * 1024],
            "diff_complete": complete,
        }

    def snapshot_wordpress(self, repository, revision):
        with tempfile.TemporaryDirectory(prefix="numen-svn-") as directory:
            dest = Path(directory) / "source"
            self.svn("export", "-r", revision, self.svn_url(repository), str(dest))
            files, total = {}, 0
            for file in dest.rglob("*"):
                if file.is_symlink():
                    raise DomainError("unsafe_source_path", "SVN snapshot contains a symlink", 422)
                if not file.is_file() or media(file.name):
                    continue
                total += file.stat().st_size
                if (
                    file.stat().st_size > MAX_FILE
                    or total > MAX_SET
                    or len(files) >= MAX_SOURCE_FILES
                ):
                    raise DomainError(
                        "source_snapshot_limit", "SVN snapshot exceeds its size limit", 422
                    )
                files[str(file.relative_to(dest))] = file.read_bytes()
            return files

    def collect_cves(self, selectors, cursor):
        results = {}
        finished = now()
        headers = {"apiKey": self.nvd_key} if self.nvd_key else {}
        last = cursor.get("completed_at")
        windows = [(None, None)]
        if last:
            from datetime import datetime

            start = utc(datetime.fromisoformat(last)) - timedelta(hours=1)
            windows = []
            while start < finished:
                end = min(start + timedelta(days=119), finished)
                windows.append((start, end))
                start = end
        request_count = 0
        for selector in selectors:
            if selector["type"] == "cpe":
                # Product-wide query; NVD rejects wildcard cpeName and versions are checked later.
                params = {"virtualMatchString": cpe_identity(selector["value"]) + ":*" * 8}
            else:
                params = {"keywordSearch": selector["value"]}
            params["resultsPerPage"] = 2000
            for start, end in windows:
                dated = (
                    {}
                    if start is None
                    else {
                        "lastModStartDate": start.isoformat(timespec="milliseconds"),
                        "lastModEndDate": end.isoformat(timespec="milliseconds"),
                    }
                )
                index = 0
                while True:
                    if request_count and not self.config.test_mode:
                        time.sleep(0.7 if self.nvd_key else 6.1)
                    request_count += 1
                    payload = self.get(
                        self.nvd, {**params, **dated, "startIndex": index}, headers
                    ).json()
                    entries = payload.get("vulnerabilities", [])
                    if not isinstance(entries, list) or (
                        not entries and index < payload.get("totalResults", 0)
                    ):
                        raise DomainError(
                            "incomplete_cve_page",
                            "CVE source returned an incomplete page",
                            502,
                            retryable=True,
                        )
                    for entry in entries:
                        raw = entry.get("cve", {})
                        if not raw.get("id"):
                            raise DomainError(
                                "invalid_cve_record", "CVE record is missing its identifier", 502
                            )
                        results[raw["id"]] = raw
                    index += len(entries)
                    if index >= payload.get("totalResults", 0):
                        break
                    if request_count > 1000:
                        raise DomainError(
                            "cve_sync_limit",
                            "CVE synchronization exceeded its bounded paging limit",
                            422,
                        )
        return list(results.values()), finished.isoformat()

    def osv_query(self, queries):
        """[[{id, modified}]] of OSV's querybatch, one list per query in order: at most 1000 queries a
        request, each followed through its next_page_token for at most 10 pages."""
        results = []
        for start in range(0, len(queries), 1000):
            batch = queries[start:start + 1000]
            found, pending = [[] for _ in batch], dict.fromkeys(range(len(batch)))
            for _ in range(10):
                body = {"queries": [{**batch[i], **({"page_token": token} if token else {})}
                                    for i, token in pending.items()]}
                items = feed_json(self.get(f"{self.osv}/v1/querybatch", json=body)).get("results")
                if not isinstance(items, list) or len(items) != len(pending):
                    raise DomainError("invalid_source_response", "OSV did not answer every query", 502)
                asked, pending = pending, {}
                for i, item in zip(asked, items):
                    item = item if isinstance(item, dict) else {}
                    found[i] += [{"id": v["id"], "modified": str(v.get("modified") or "")[:64]}
                                 for v in item.get("vulns") or [] if isinstance(v, dict) and isinstance(v.get("id"), str)]
                    if isinstance(item.get("next_page_token"), str) and item["next_page_token"]:
                        pending[i] = item["next_page_token"]
                if not pending:
                    break
            else:
                raise DomainError("source_history_limit", "OSV answered more than 10 pages for a query", 422)
            results += found
        return results

    def osv_vuln(self, ident):
        """OSV's record of `ident`."""
        return feed_json(self.get(f"{self.osv}/v1/vulns/{quote(ident, safe='')}"))

    def ghsa_advisories(self, params, etag=None):
        """(ETag, advisories) of GitHub's advisory database for `params`, with the read token,
        following the Link header's next page for at most 10 pages; None when `etag` still holds."""
        headers = self.github_headers()
        # ponytail: only the first page's ETag is kept, so a change past page one waits until page
        # one changes too; keep each page's ETag if a 100-package request ever answers more than 100
        response = self.get(f"{self.github}/advisories", {**params, "per_page": 100},
                            {**headers, "If-None-Match": etag} if etag else headers)
        if response.status_code == 304:
            return None
        etag, items = response.headers.get("etag"), []
        for _ in range(10):
            items += [item for item in feed_json(response, list) if isinstance(item, dict)]
            url = response.links.get("next", {}).get("url")
            if not url:
                return etag, items
            if not url.startswith(self.github + "/"):  # the read token goes to GitHub only
                raise DomainError("unsafe_source_redirect", "GitHub's next page is on another host", 502)
            response = self.get(url, headers=headers)
        raise DomainError("source_history_limit", "GitHub answered more than 10 pages of advisories", 422)

    def nvd_cpe(self, cpe_name):
        """The raw CVE records NVD lists for `cpe_name`, every page, with the NVD key when there is one."""
        headers = {"apiKey": self.nvd_key} if self.nvd_key else {}
        records, index = [], 0
        for _ in range(10):
            if not self.config.test_mode:
                time.sleep(0.7 if self.nvd_key else 6.1)  # NVD's rolling 30-second window
            payload = feed_json(self.get(self.nvd, {"cpeName": cpe_name, "startIndex": index}, headers))
            entries, total = payload.get("vulnerabilities"), payload.get("totalResults")
            if not isinstance(entries, list) or not isinstance(total, int) or (not entries and index < total):
                raise DomainError("incomplete_cve_page", "CVE source returned an incomplete page", 502, retryable=True)
            records += [entry["cve"] for entry in entries if isinstance(entry, dict) and isinstance(entry.get("cve"), dict)]
            index += len(entries)
            if index >= total:
                return records
        raise DomainError("cve_sync_limit", "NVD answered more than 10 pages for a CPE", 422)

    def release_corpus(self, repository):
        """Pin a bounded release corpus, retaining exactly which distributed bytes were available."""
        import hashlib
        from copy import copy

        corpus = {
            "schema_version": 1,
            "releases": [],
            "fingerprints": {},
            "limitations": [],
            "source_generation": repository.source_generation,
            "normalization": "none; exact bytes",
            "complete": False,
        }
        source_releases = []
        if repository.source_kind == "github":
            repo = repository.source_url.removeprefix("https://github.com/")
            headers = self.github_headers()
            try:
                releases = self.get(
                    f"{self.github}/repos/{repo}/releases", {"per_page": 12}, headers
                ).json()
                if not isinstance(releases, list):
                    raise DomainError(
                        "invalid_source_response", "Release catalog is not a list", 502
                    )
                for release in releases:
                    if not release.get("draft") and release.get("tag_name"):
                        source_releases.append((release["tag_name"], release.get("assets", [])))
                if not source_releases:
                    tags = self.get(
                        f"{self.github}/repos/{repo}/tags", {"per_page": 12}, headers
                    ).json()
                    for tag in tags:
                        source_releases.append((tag["name"], []))
            except DomainError as exc:
                corpus["limitations"].append("Release catalog unavailable: " + exc.code)
        else:
            try:
                catalog = ET.fromstring(
                    self.svn("list", "--xml", "-r", repository.cursor, self.svn_root(repository) + "/tags")
                )
                tags = [
                    entry.findtext("name")
                    for entry in catalog.findall("list/entry")
                    if entry.attrib.get("kind") == "dir"
                ]
                # Numeric ordering is unknown across vendor conventions; record the selected catalog order.
                source_releases = [(tag, []) for tag in sorted(tags, reverse=True)[:12]]
            except DomainError as exc:
                corpus["limitations"].append("WordPress release tags unavailable: " + exc.code)
        for version, assets in source_releases[:12]:
            self.heartbeat()
            release = {
                "version": version,
                "source_ref": version,
                "distributed": False,
                "asset_count": 0,
            }
            files = {}
            try:
                if repository.source_kind == "wordpress":
                    release_repository = copy(repository)
                    release_repository.source_ref, release_repository.source_path = (
                        "tags/" + version,
                        None,
                    )
                    files = self.snapshot_wordpress(release_repository, repository.cursor)
                    release.update(
                        source_ref=repository.cursor, source_path="tags/" + version, distributed=True
                    )
                else:
                    # Uploaded release packages are actual distribution bytes; source archives are
                    # retained as a separate method with an explicit transformation limitation.
                    # One installable package per release: an updater or patch package
                    # holds a subset of the same files under another folder.
                    packages = sorted(
                        (
                            asset
                            for asset in assets
                            if asset.get("name", "").endswith((".zip", ".tar.gz", ".tgz"))
                        ),
                        key=lambda asset: any(
                            word in asset["name"].lower() for word in ("updater", "update", "patch")
                        ),
                    )[:3]
                    for asset in packages:
                        if files:
                            break
                        url = asset.get("url", "")
                        if not url.startswith("https://api.github.com/repos/"):
                            continue
                        # An oversized or unreadable package falls back to the source archive below
                        # instead of dropping the release from the corpus.
                        if asset.get("size", 0) > MAX_SET:
                            corpus["limitations"].append(
                                f"{version}: package {asset['name']} exceeds the download bound"
                            )
                            continue
                        try:
                            response = self.get(
                                url, headers={**headers, "Accept": "application/octet-stream"}
                            )
                            if response.status_code in (301, 302, 307, 308):
                                from urllib.parse import urlparse

                                dest = response.headers.get("location", "")
                                host = urlparse(dest).hostname
                                if urlparse(dest).scheme != "https" or host not in (
                                    "release-assets.githubusercontent.com",
                                    "objects.githubusercontent.com",
                                    "github.com",
                                ):
                                    raise DomainError(
                                        "unsafe_source_redirect",
                                        "Unexpected release asset redirect",
                                        502,
                                    )
                                response = self.get(dest)
                            distributed = fingerprints.strip_root(
                                self.distribution_files(response.content, asset["name"])
                            )
                        except (DomainError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
                            code = getattr(exc, "code", type(exc).__name__)
                            corpus["limitations"].append(
                                f"{version}: package {asset['name']} unavailable ({code})"
                            )
                            continue
                        files.update(distributed)
                        release.setdefault("archives", []).append(
                            {
                                "name": asset["name"],
                                "sha256": hashlib.sha256(response.content).hexdigest(),
                                "id": asset.get("id"),
                            }
                        )
                    if files:
                        release["distributed"] = True
                    else:
                        files = self.snapshot_github(repository, version)
                        corpus["limitations"].append(
                            f"{version}: source archive only; installed/minified/distributed assets may differ"
                        )
                for path, content in files.items():
                    # Only assets a site publishes as-is can be compared remotely.
                    if not fingerprints.published(path):
                        continue
                    digest = hashlib.sha256(content).hexdigest()
                    record = (
                        corpus["fingerprints"]
                        .setdefault(path, {})
                        .setdefault(
                            digest,
                            {"versions": [], "size": len(content), "distributed_versions": []},
                        )
                    )
                    if version not in record["versions"]:
                        record["versions"].append(version)
                    if release["distributed"]:
                        record["distributed_versions"].append(version)
                    release["asset_count"] += 1
                corpus["releases"].append(release)
            except (DomainError, ValueError, tarfile.TarError) as exc:
                corpus["limitations"].append(
                    f"{version}: release capture failed ({getattr(exc, 'code', type(exc).__name__)})"
                )
        corpus["limitations"].append(
            "Corpus is bounded to at most 12 available releases; matching bytes identify candidates within this corpus, not an exhaustive installed version"
        )
        if not corpus["releases"]:
            corpus["limitations"].append(
                "No release fingerprints are available; use disclosures/manual evidence or return unknown"
            )
        corpus.update(fingerprints.plan(corpus))
        return corpus

    def distribution_files(self, content, name):
        from .artifacts import unpack_zip

        if len(content) > MAX_SET:
            raise DomainError(
                "source_snapshot_limit", "Release package exceeds its size limit", 422
            )
        if name.endswith(".zip"):
            return unpack_zip(content)
        files, total = {}, 0
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                path = safe_path(member.name)
                total += member.size
                if member.size > MAX_FILE or total > MAX_SET or len(files) >= 4000:
                    raise DomainError(
                        "source_snapshot_limit", "Release package expansion exceeds its limit", 422
                    )
                files[path] = archive.extractfile(member).read()
        return files
