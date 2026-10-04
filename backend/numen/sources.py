"""Bounded source collectors; completion cursors are promoted by the worker transaction."""

import io
import os
import re
import subprocess
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

import httpx
from .artifacts import MAX_SET, MAX_FILE, MAX_SOURCE_FILES
from .cves import cpe_identity
from .models import now, utc
from .schemas import safe_path
from .security import DomainError, retry_delay

# Binary media is not source evidence; omitting it keeps CMS-sized snapshots within bounds.
MEDIA_SUFFIXES = frozenset(
    ".avif .bmp .eot .flac .gif .ico .jpeg .jpg .m4a .mov .mp3 .mp4 .ogg .otf .png .psd"
    " .tif .tiff .ttf .wav .webm .webp .woff .woff2".split()
)


def media(path):
    return Path(path).suffix.lower() in MEDIA_SUFFIXES


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
        self.nvd = (
            os.getenv("NUMEN_NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
            if config.test_mode
            else "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )

    def close(self):
        self.client.close()

    def get(self, url, params=None, headers=None):
        self.heartbeat()
        for attempt in range(4):
            try:
                with self.client.stream("GET", url, params=params, headers=headers) as stream:
                    content = bytearray()
                    for chunk in stream.iter_bytes(chunk_size=256 * 1024):
                        self.heartbeat()
                        content.extend(chunk)
                        if len(content) > MAX_SET:
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

    def github_commits(self, program):
        repo = program.source_url.removeprefix("https://github.com/")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.github_key:
            headers["Authorization"] = f"Bearer {self.github_key}"
        params = {"per_page": 100, "sha": program.source_ref or "HEAD"}
        first = self.get(
            f"{self.github}/repos/{repo}/commits", {**params, "page": 1}, headers
        ).json()
        if not isinstance(first, list):
            raise DomainError("invalid_source_response", "GitHub did not return a commit list", 502)
        head = first[0]["sha"] if first else program.cursor
        if head and not re.fullmatch(r"[0-9a-fA-F]{40,64}", head):
            raise DomainError(
                "invalid_source_revision", "GitHub returned an invalid immutable revision", 502
            )
        if program.cursor and head == program.cursor:
            return head, []
        found, history_rewritten = [], False
        comparison = None
        if program.cursor and head:
            try:
                comparison = self.get(
                    f"{self.github}/repos/{repo}/compare/{program.cursor}...{head}",
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
                        f"{self.github}/repos/{repo}/compare/{program.cursor}...{head}",
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
            history_rewritten = history_rewritten or bool(program.cursor)
            found = list(first)
            # A baseline displays the newest page; later checks import every unseen revision.
            if program.cursor and len(first) == 100:
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
        commits = []
        for item in reversed(found):
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
            if program.source_path:
                prefix = program.source_path.rstrip("/")
                files = [
                    f
                    for f in files
                    if f.get("filename") == prefix
                    or f.get("filename", "").startswith(prefix + "/")
                    or f.get("previous_filename") == prefix
                    or f.get("previous_filename", "").startswith(prefix + "/")
                ]
                if not files:
                    continue
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
            commits.append(
                {
                    "revision": revision,
                    "message": data.get("message", ""),
                    "author": data.get("author", {}).get("name", ""),
                    "committed_at": data.get("committer", {}).get("date"),
                    "url": f"{program.source_url}/commit/{revision}",
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
                }
            )
        return head or program.cursor, commits

    def snapshot_github(self, program, revision):
        repo = program.source_url.removeprefix("https://github.com/")
        headers = {"Authorization": f"Bearer {self.github_key}"} if self.github_key else {}
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
                    program.source_path
                    and not relative.startswith(program.source_path.rstrip("/") + "/")
                    and relative != program.source_path
                ) or media(relative):
                    continue
                total += member.size
                if member.size > MAX_FILE or total > MAX_SET or len(files) >= MAX_SOURCE_FILES:
                    raise DomainError(
                        "source_snapshot_limit", "Expanded source exceeds the bounded snapshot", 422
                    )
                files[relative] = archive.extractfile(member).read()
        return files

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

    def wordpress_commits(self, program):
        base = program.source_url
        if self.config.test_mode and os.getenv("NUMEN_WORDPRESS_SVN_URL"):
            base = os.environ["NUMEN_WORDPRESS_SVN_URL"].rstrip("/") + "/" + program.plugin_slug
        path = program.source_ref or "trunk"
        if program.source_path:
            path += "/" + program.source_path
        url = base + "/" + path
        info = ET.fromstring(self.svn("info", "--xml", url))
        head = info.find("entry").attrib["revision"]
        start = int(program.cursor) + 1 if program.cursor else 1
        if start > int(head):
            return head, []
        log = ET.fromstring(self.svn("log", "--xml", "-v", "-r", f"{start}:{head}", url))
        entries = list(log.findall("logentry"))
        if len(entries) > 10000:
            raise DomainError(
                "source_history_limit", "WordPress history exceeds the bounded sync", 422
            )
        commits = []
        for entry in entries:
            rev = entry.attrib["revision"]
            try:
                diff = self.svn("diff", "-c", rev, url).decode(errors="replace")
                complete = len(diff.encode()) <= 2 * 1024 * 1024
            except DomainError:
                diff, complete = "", False
            commits.append(
                {
                    "revision": rev,
                    "message": entry.findtext("msg", ""),
                    "author": entry.findtext("author", ""),
                    "committed_at": entry.findtext("date"),
                    "url": f"https://plugins.trac.wordpress.org/changeset/{rev}/{program.plugin_slug}",
                    "files": [
                        {"path": p.text, "status": p.attrib.get("action")}
                        for p in entry.findall("paths/path")
                    ],
                    "diff": diff[: 2 * 1024 * 1024],
                    "diff_complete": complete,
                }
            )
        return head, commits

    def snapshot_wordpress(self, program, revision):
        base = program.source_url
        if self.config.test_mode and os.getenv("NUMEN_WORDPRESS_SVN_URL"):
            base = os.environ["NUMEN_WORDPRESS_SVN_URL"].rstrip("/") + "/" + program.plugin_slug
        path = program.source_ref or "trunk"
        if program.source_path:
            path += "/" + program.source_path
        with tempfile.TemporaryDirectory(prefix="numen-svn-") as directory:
            dest = Path(directory) / "source"
            self.svn("export", "-r", revision, base + "/" + path, str(dest))
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

    def release_corpus(self, program):
        """Pin a bounded release corpus, retaining exactly which distributed bytes were available."""
        import hashlib
        from copy import copy

        corpus = {
            "schema_version": 1,
            "releases": [],
            "fingerprints": {},
            "limitations": [],
            "source_generation": program.source_generation,
            "normalization": "none; exact bytes",
            "complete": False,
        }
        source_releases = []
        if program.source_kind == "github":
            repo = program.source_url.removeprefix("https://github.com/")
            headers = {"Authorization": f"Bearer {self.github_key}"} if self.github_key else {}
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
            base = program.source_url
            if self.config.test_mode and os.getenv("NUMEN_WORDPRESS_SVN_URL"):
                base = os.environ["NUMEN_WORDPRESS_SVN_URL"].rstrip("/") + "/" + program.plugin_slug
            try:
                catalog = ET.fromstring(
                    self.svn("list", "--xml", "-r", program.cursor, base + "/tags")
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
                if program.source_kind == "wordpress":
                    release_program = copy(program)
                    release_program.source_ref, release_program.source_path = (
                        "tags/" + version,
                        None,
                    )
                    files = self.snapshot_wordpress(release_program, program.cursor)
                    release.update(
                        source_ref=program.cursor, source_path="tags/" + version, distributed=True
                    )
                else:
                    # Uploaded release packages are actual distribution bytes; source archives are
                    # retained as a separate method with an explicit transformation limitation.
                    packages = [
                        asset
                        for asset in assets
                        if asset.get("name", "").endswith((".zip", ".tar.gz", ".tgz"))
                    ][:3]
                    for asset in packages:
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
                            distributed = self.distribution_files(
                                response.content, asset["name"]
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
                        files = self.snapshot_github(program, version)
                        corpus["limitations"].append(
                            f"{version}: source archive only; installed/minified/distributed assets may differ"
                        )
                for path, content in files.items():
                    if not path.endswith((".js", ".css", ".php", ".json", ".txt")) and Path(
                        path
                    ).name not in ("VERSION", "version"):
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
