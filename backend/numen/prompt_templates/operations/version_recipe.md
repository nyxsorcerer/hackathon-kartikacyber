{% include "rules" %}

## Task

Version recipe requires determine_version.py (reusable Python), recipe.json and fixtures/ cases with expected results. Numen adds fingerprints.json holding the release-corpus.json fingerprint map under fingerprints; do not write it or invent release hashes.

release-corpus.json fingerprints only front-end files a site publishes as-is (scripts, styles, SVG, static HTML, readme and changelog files), keyed by their path inside the release without the package's top folder; manifests, lock files and configuration are excluded because deployments do not publish them. Its probes list the files whose bytes differ between releases.

After your script runs, Numen itself fetches those distinguishing files from the target and narrows the result to the releases whose exact bytes match, so your script should concentrate on what Numen cannot see: version disclosures (generator tags, headers, readme or changelog files, versioned asset URLs, API metadata), product identification, and where the release's files are served. If they are not served from the asset URL itself (for example a WordPress plugin directory or a subfolder install), set "asset_base" in recipe.json to that URL or path; otherwise omit it.

Report a version as detected only from an explicit disclosure; report candidates when evidence fits several releases.

## Running the recipe

Numen runs the script as `python -I recipe.py` beside all your output files (locate them from Path(__file__).parent); NUMEN_TARGET_INPUT is the path of a JSON file, the exit code must be 0 and stdout must be exactly one JSON object.

Observe mode input {"mode":"observe","asset_url":...}: request the target only with numen_runner.fetch.fetch(url, method="GET"), which returns {url,status,headers,content_base64,sha256} and raises when the gateway denies a request, then print one observation with status detected|ambiguous|unknown|error, version, candidates, method, evidence, confidence and limitations.

Validate mode input {"mode":"validate","fixtures":true}: make no network requests, run every fixture case offline through the same detection logic, and print {"status":"validated","fixtures_passed":true|false,"checks":[...]}.
