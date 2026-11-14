"""Asset Monitor's Served-content check (A10), staged as recipe.py like fingerprint_probe.py.

It fetches one Watched page through the gateway as each user agent of the fixed pair, and the
scripts the page links to (same-origin and external, at most max_scripts) as that same user
agent. It never runs a script and requests nothing else: no link, no image, and no URL that a
script names. It uses only the standard library and the gateway's fetch, so it runs in the same
sandbox as a version recipe, and writes each response's bytes to /workspace/outputs/<sha256>.
"""
import base64
import hashlib
import json
import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

HIDDEN = {"script", "style", "noscript", "template"}  # elements whose text is not visible
TOKEN_META = {"csrf-token", "csrf_token", "_csrf"}
TOKEN_INPUT = re.compile(r"csrf|_token|authenticity_token|nonce", re.I)
# The URLs a browser follows from a page (FOLLOWS) or loads into it (LOADS), apart from a script's src.
FOLLOWS = {"a": "href", "area": "href", "form": "action"}
LOADS = {"iframe": "src", "frame": "src", "link": "href", "object": "data", "embed": "src"}
REFRESH_RE = re.compile(r"[;,]\s*(?:url\s*=\s*)?['\"]?([^'\"]+)", re.I)  # a meta refresh's URL
FIELDS = ("url", "final_url", "status", "sha256", "content_type", "error")


class Page(HTMLParser):
    """What a Content fingerprint reads of a page: its script srcs in order, its inline scripts,
    the URLs it follows (link hrefs, form actions, a meta refresh) and loads (frames, stylesheets
    and other link hrefs, objects and embeds), its first <base href>, its visible text and the
    token values that rotate on every request (CSRF tokens and nonces in a meta tag or a hidden
    input, and every nonce attribute)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.srcs, self.inline, self.hrefs, self.loads, self.text, self.tokens = [], [], [], [], [], set()
        self.base = None  # the first <base href>, which every relative URL resolves against
        self.hidden = 0  # depth inside elements whose text is not visible
        self.script = None  # the inline script being read

    def handle_starttag(self, tag, attrs):
        self.tokens.update(value for name, value in attrs if name == "nonce" and value)
        attrs = dict(reversed(attrs))  # As a browser reads them: the first of a repeated attribute wins.
        if tag == "base" and self.base is None and attrs.get("href") is not None:
            self.base = attrs["href"]
        if tag == "meta" and (attrs.get("name") or "").lower() in TOKEN_META:
            self.tokens.add(attrs.get("content") or "")
        if tag == "meta" and (attrs.get("http-equiv") or "").lower() == "refresh":
            refresh = REFRESH_RE.search(attrs.get("content") or "")
            if refresh:
                self.hrefs.append(refresh.group(1))
        if tag == "input" and (attrs.get("type") or "").lower() == "hidden" and TOKEN_INPUT.search(attrs.get("name") or ""):
            self.tokens.add(attrs.get("value") or "")
        if attrs.get(FOLLOWS.get(tag)) is not None:
            self.hrefs.append(attrs[FOLLOWS[tag]])
        if attrs.get(LOADS.get(tag)) is not None:
            self.loads.append(attrs[LOADS[tag]])
        if tag == "script":
            if attrs.get("src") is not None:
                self.srcs.append(attrs["src"])
            else:
                self.script = []
        if tag in HIDDEN:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in HIDDEN and self.hidden:
            self.hidden -= 1
        if tag == "script" and self.script is not None:
            self.inline.append("".join(self.script))
            self.script = None

    def handle_data(self, data):
        if self.script is not None:
            self.script.append(data)
        elif not self.hidden:
            self.text.append(data)

    def base_url(self, final_url):
        """The URL the page's relative URLs resolve against, as a browser reads it: its first
        <base href> resolved against final_url, else final_url."""
        return (join(final_url, self.base) if self.base is not None else None) or final_url


def parse(data):
    page = Page()
    page.feed(data.decode("utf-8", "replace"))
    page.close()
    return page


def join(base, ref):
    """ref resolved against base, or None when the page's text is no valid URL."""
    try:
        url = urljoin(base, ref.strip())
        urlsplit(url)
    except ValueError:
        return None
    return url


def script_urls(page, final_url):
    """The page's script srcs resolved against its base URL: http(s) only, each once, in order."""
    base, urls = page.base_url(final_url), []
    for src in page.srcs:
        url = join(base, src) if src.strip() else None
        if url and urlsplit(url).scheme in ("http", "https") and url not in urls:
            urls.append(url)
    return urls


def collect(fetch, target):
    """Each user agent's fetch of target["url"] and of the scripts it links to, and the bytes
    fetched, by sha256. A script past max_scripts is listed with status "skipped" and error
    "limit". Each user agent has an equal share of max_bytes, so one user agent's scripts never
    starve the other's page: a response whose new bytes would take its user agent's past that
    share is dropped and listed as skipped with error "budget", and that user agent fetches no
    further script. A failed request is listed with its exception's type name as its error, as
    fingerprint_probe does."""
    files = {}
    share, spent = target["max_bytes"] // len(target["user_agents"]), dict.fromkeys(target["user_agents"], 0)

    def get(url, agent):
        record = {**dict.fromkeys(FIELDS), "url": url}
        try:
            response = fetch(url, method="GET", user_agent=agent)
        except Exception as exc:  # A denied or unreachable request ends nothing else.
            return {**record, "error": type(exc).__name__}
        data = base64.b64decode(response.get("content_base64") or "")
        digest = hashlib.sha256(data).hexdigest()
        if digest not in files:  # bytes another fetch stored already cost nothing more
            if spent[agent] + len(data) > share:
                return {**record, "status": "skipped", "error": "budget"}
            spent[agent] += len(data)
            files[digest] = data
        return {**record, "final_url": response.get("url"), "status": response.get("status"), "sha256": digest,
                "content_type": (response.get("headers") or {}).get("content-type")}

    fetches = {}
    for agent in target["user_agents"]:
        page = fetches[agent] = {**get(target["url"], agent), "scripts": []}
        if page["status"] != 200:
            continue
        full = False
        for index, url in enumerate(script_urls(parse(files[page["sha256"]]), page["final_url"])):
            if index >= target["max_scripts"] or full:
                script = {**dict.fromkeys(FIELDS), "url": url, "status": "skipped", "error": "limit" if index >= target["max_scripts"] else "budget"}
            else:
                script = get(url, agent)
                full = script["error"] == "budget"
            page["scripts"].append(script)
    return {"fetches": fetches}, files


def main():
    target = json.loads(Path(os.environ["NUMEN_TARGET_INPUT"]).read_text())
    from numen_runner.fetch import fetch

    result, files = collect(fetch, target)
    for digest, data in files.items():
        (Path("/workspace/outputs") / digest).write_bytes(data)
    print(json.dumps(result))


if __name__ == "__main__":
    sys.exit(main())
