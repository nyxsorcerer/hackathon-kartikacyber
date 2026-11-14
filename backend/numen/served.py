"""Content fingerprints of Watched pages (A10): the comparable summary of what a page serves to one
user agent, built so that injected content changes it and routine changes do not.

- A script URL is read as its Script family, with a bundler's hash tokens replaced by *, as
  hekata's monitor/gather.py family() reads it.
- A script's content is read as jsdiff.py's normalised token stream: spaces and comments go, and
  a minifier's renamed short identifiers and module ids compare equal.
- Token values that rotate on every request (CSRF tokens and nonces) are masked wherever the page
  repeats them: in its inline scripts, its links and its text.
- The external script hosts, the links and their hosts, and the visible words are kept, so an
  added script host, or gambling links shown only to Googlebot, change it. The links are every
  URL the page follows or loads (hrefs, form actions, a meta refresh, frames, stylesheets,
  objects and embeds), resolved against its <base href> as a browser resolves them.

Ported from hekata, never imported; standard library only.
"""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from .served_probe import join, parse, script_urls

PROBE = Path(__file__).with_name("served_probe.py")
TOKEN_MIN = 8  # characters of the shortest token value masked, so a short one cannot blank out words
# ponytail: a page's words are kept to the first WORD_CAP in sorted order, so words added to a page
# that already has more may not change its fingerprint; hash the whole set beside them if that matters.
WORD_CAP = 5000
WORD_RE = re.compile(r"[^\W_]{3,}")
# A token value an inline script names by a key like nonce, token or csrf (a WordPress nonce in
# localized script data, window.csrfToken = "..."): masked like a meta or hidden-input token.
KEYED_TOKEN_RE = re.compile(r"""[\w$]*(?:nonce|token|csrf)[\w$]*["']?\s*[:=]\s*(["'])([\w+/=-]+)\1""", re.I)


# --- Script families: hekata monitor/gather.py --------------------------------------------------
def bare(url):
    """A URL without its query and fragment."""
    return url.split("#", 1)[0].split("?", 1)[0]


HEX_RE = re.compile(r"[0-9a-f]{8,}")
BUILD_RE = re.compile(r"[A-Za-z0-9_-]{16,}")
HASH_RE = re.compile(r"[A-Za-z0-9_-]{8,}")


def _hashlike(part):
    return HASH_RE.fullmatch(part) is not None and any(c.isupper() or c.isdigit() or c == "_" for c in part)


def family(url):
    """A script's identity across deploys: its host, lowercased, with a port that is not its
    scheme's default, and its path with the hash-like tokens of a bundler's names replaced by *.
    A folder that is a build id goes whole: [0-9a-f]{8,}, or [A-Za-z0-9_-]{16,} with a digit or
    an uppercase letter. Of the file name's parts at each dot, each but the extension goes when it
    is [0-9a-f]{8,}, or, past the first part, a hash-like [A-Za-z0-9_-]{8,} (with an uppercase
    letter, a digit or _); otherwise what follows its rightmost - with 8 characters or more after
    it goes when that is hash-like."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return bare(url)
    host = (parts.hostname or "") + ("" if port is None or port == {"http": 80, "https": 443}.get(parts.scheme)
                                     else f":{port}")
    *folders, name = parts.path.split("/")
    folders = ["*" if HEX_RE.fullmatch(folder) or (BUILD_RE.fullmatch(folder) and any(
        c.isupper() or c.isdigit() for c in folder)) else folder for folder in folders]
    *stems, extension = name.split(".")
    for index, stem in enumerate(stems):
        if HEX_RE.fullmatch(stem) or (index and _hashlike(stem)):
            stems[index] = "*"
            continue
        dash = next((at for at in range(len(stem) - 9, -1, -1) if stem[at] == "-"), None)
        if dash is not None and _hashlike(stem[dash + 1:]):
            stems[index] = stem[:dash + 1] + "*"
    return host + "/".join([*folders, ".".join([*stems, extension])])


# --- Normalised scripts: hekata monitor/jsdiff.py -----------------------------------------------
REGEX_BUDGET = 1_000_000  # characters regex-literal scans may read in a script; then every / divides
# JavaScript's reserved words, and of, get, set, async and await: never read as a minifier's name
KEYWORDS = frozenset("""await break case catch class const continue debugger default delete do else enum export extends
false finally for function if implements import in instanceof interface let new null package private protected public
return static super switch this throw true try typeof var void while with yield of get set async""".split())
# the identifiers after which a / opens a regex literal; after any other it divides
REGEX_AFTER = frozenset("return typeof case do else in of new delete void throw instanceof yield await".split())
BREAK = r"\r\n?|[\n  ]"  # JavaScript's line terminators
BREAK_RE = re.compile(BREAK)
# One code token at a time. Every repeat is possessive, so no scan ever backtracks.
TOKEN_RE = re.compile("|".join((
    f"(?P<brk>{BREAK})",
    r"(?P<sp>(?:[^\S\r\n  ]|﻿)++)",
    r"(?P<lc>//[^\r\n  ]*+)",
    r"(?P<bc>/\*)",
    r"(?P<sl>/)",
    r"(?P<str>'(?:[^'\\\r\n  ]++|\\.)*+'?|\"(?:[^\"\\\r\n  ]++|\\.)*+\"?)",
    r"(?P<tpl>`)",
    r"(?P<num>(?:0[xXoObB][0-9a-fA-F_]++|(?:[0-9][0-9_]*+(?:\.[0-9_]*+)?|\.[0-9][0-9_]*+)(?:[eE][+-]?[0-9]++)?)n?)",
    r"(?P<word>(?:[\w$]|[^\x00-\x7f\s])++)",
    r"(?P<punct>>>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|\?\?=|&&=|\|\|=|=>|==|!=|<=|>=|&&|\|\||\?\?|\?\.(?![0-9])"
    r"|\+\+|--|\+=|-=|\*=|%=|&=|\|=|\^=|\*\*|<<|>>|.)",
)), re.S)
# A regex literal: a backslash escapes, a [...] class holds a / that closes nothing; it ends at the line's end
REGEX_RE = re.compile(r"/(?:[^\\/\[\r\n  ]++|\\[^\r\n  ]|\[(?:[^\\\]\r\n  ]++"
                      r"|\\[^\r\n  ])*+\]?)*+/[A-Za-z]*+")
TEMPLATE_RE = re.compile(r"(?:[^`\\$]++|\\.|\$(?!\{))*+", re.S)  # a template literal's text, up to ` or ${


def normalise_js(text):
    """A script's normalised token stream, read in one linear pass as jsdiff.py's _read reads it:
    spaces and comments are dropped, an identifier of 1-3 characters (no keyword, not after . or
    ?.) reads as _, and a number after _( (a bundler's module id) as 0. Strings, template text and
    regex literals stay as written."""
    out, i, n = [], 0, len(text)
    value = False  # the last significant token ends a value: a / after it divides
    subs, depth = [], 0  # the brace depth at which each open template substitution began
    budget = REGEX_BUDGET
    before = last = ""  # the last two normalised code tokens
    template = False  # reading a template literal's text
    while i < n:
        if template:
            j = TEMPLATE_RE.match(text, i).end()
            out.append(text[i:j])
            if j == n:
                break
            if text[j] == "`":
                out.append("`")
                template, value, i = False, True, j + 1
            elif text.startswith("${", j):
                out.append("${")
                subs.append(depth)
                template, value, i = False, False, j + 2
                before, last = last, "${"
            else:  # a backslash ending the text
                out.append("\\")
                i = j + 1
            continue
        token = TOKEN_RE.match(text, i)
        kind, word = token.lastgroup, token.group()
        i = token.end()
        if kind in ("brk", "sp", "lc"):
            continue
        if kind == "bc":
            end = text.find("*/", i)
            i = n if end < 0 else end + 2
        elif kind == "str":
            out.append(word)
            value, before, last = True, last, word
        elif kind == "tpl":
            out.append("`")
            template = True
        elif kind == "num":
            norm = "0" if (before, last) == ("_", "(") else word
            out.append(norm)
            value, before, last = True, last, norm
        elif kind == "word":
            norm = "_" if len(word) <= 3 and word not in KEYWORDS and last not in (".", "?.") else word
            out.append(norm)
            value, before, last = word not in REGEX_AFTER, last, norm
        else:
            if kind == "sl" and not value and budget > 0:
                window = min(n, token.start() + budget)
                literal = REGEX_RE.match(text, token.start(), window)
                if literal:
                    budget -= literal.end() - token.start()
                    out.append(literal.group())
                    value, i, before, last = True, literal.end(), last, literal.group()
                    continue
                stop = BREAK_RE.search(text, token.start(), window)
                budget -= (stop.start() if stop else window) - token.start()
            if word == "}" and subs and subs[-1] == depth:  # back to the template's text
                subs.pop()
                template = True
            elif word == "{":
                depth += 1
            elif word == "}":
                depth = max(depth - 1, 0)
            out.append(word)
            value, before, last = word in (")", "]"), last, word
    return " ".join(out)


# --- Content fingerprints -----------------------------------------------------------------------
def digest(text):
    return hashlib.sha256(normalise_js(text).encode()).hexdigest()


def host(url):
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def summary(html_bytes, final_url, scripts):
    """The comparable summary of a page as one user agent was served it. scripts are the page's
    fetched scripts, [(url, bytes or None, status label)], as served_probe.collect lists them.
    Every value is a sorted list, so the summary is canonical."""
    page = parse(html_bytes)
    page.tokens.update(match.group(2) for text in page.inline for match in KEYED_TOKEN_RE.finditer(text))
    tokens = sorted({t for t in page.tokens if len(t) >= TOKEN_MIN}, key=len, reverse=True)

    def mask(text):
        for token in tokens:
            text = text.replace(token, "*")
        return text

    def loaded(ref):
        """A URL the page loads, read as a Script family is, so a bundler's renamed stylesheet is not a change."""
        url = join(base, mask(ref))
        return f"{urlsplit(url).scheme}://{family(url)}" if url else mask(ref)

    base, web = page.base_url(final_url), set(script_urls(page, final_url))
    # A src that is no http(s) URL (a data: URL, or no valid URL) is never fetched: it is read as inline code.
    inline = page.inline + [src for src in page.srcs if src.strip() and join(base, src) not in web]
    links = {bare(join(base, mask(href)) or mask(href)) for href in page.hrefs} | {loaded(ref) for ref in page.loads}
    words = sorted(set(WORD_RE.findall(re.sub(r"\d+", "0", mask(" ".join(page.text)).lower()))))
    return {
        "script_hosts": sorted({host(url) for url, _, _ in scripts} - {host(final_url), None}),
        "scripts": sorted({family(url) + (f"#{digest(content.decode('utf-8', 'replace'))}" if content is not None
                                          else f"!{label}") for url, content, label in scripts}),
        # A server's timestamps (10 digits or more) in an inline script change on every request too.
        "inline_scripts": sorted({digest(re.sub(r"\d{10,}", "0", mask(text))) for text in inline}),
        "links": sorted(links),
        "link_hosts": sorted({host(link) for link in links} - {None}),
        "words": words[:WORD_CAP],
    }


def summaries(result, files):
    """Each user agent's summary of a served_probe.collect result, or None for a user agent that
    was not served the page (any status but 200)."""
    out = {}
    for agent, fetched in result["fetches"].items():
        if fetched["status"] != 200:
            out[agent] = None
            continue
        scripts = [(s["url"], files[s["sha256"]] if s["status"] == 200 else None,
                    s["status"] if s["status"] is not None else s["error"]) for s in fetched["scripts"]]
        out[agent] = summary(files[fetched["sha256"]], fetched["final_url"], scripts)
    return out


def fingerprint(summary):
    """The Content fingerprint: the sha256 of the summary's canonical JSON."""
    return hashlib.sha256(json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode()).hexdigest()


def diff(before, after):
    """What changed from one summary to the next, for each key that differs: {added, removed}.
    With no before, everything after holds is added."""
    changes = {}
    for key, values in after.items():
        old, new = set((before or {}).get(key, ())), set(values)
        if old != new:
            changes[key] = {"added": sorted(new - old), "removed": sorted(old - new)}
    return changes


def check_indicators(changed, baseline, indicators):
    """A served-content Malicious change's indicators as application code checked them, in
    detection.check_indicators' shape: a file must be one of the changed fetch's stored files
    ({path: bytes}) that the Baseline fetch did not serve, hashed here, and a host, URL or command
    must occur in the changed fetch's bytes and in none of the Baseline fetch's. Everything else is
    listed in rejected, with the reason."""
    checked = {"files": [], "hosts": [], "urls": [], "commands": [], "rejected": []}
    for path in dict.fromkeys(indicators["files"]):
        reason = ("Not a file of the changed fetch" if path not in changed
                  else "The Baseline fetch served these bytes too" if changed[path] in baseline.values() else None)
        if reason:
            checked["rejected"].append({"kind": "file", "value": path, "reason": reason})
        else:
            checked["files"].append({"path": path, "sha256": hashlib.sha256(changed[path]).hexdigest()})
    for key in ("hosts", "urls", "commands"):
        for value in dict.fromkeys(indicators[key]):
            data = value.encode()
            reason = ("Not in the changed fetch's bytes" if not value or not any(data in b for b in changed.values())
                      else "Also in the Baseline fetch's bytes" if any(data in b for b in baseline.values()) else None)
            if reason:
                checked["rejected"].append({"kind": key[:-1], "value": value, "reason": reason})
            else:
                checked[key].append(value)
    return checked
