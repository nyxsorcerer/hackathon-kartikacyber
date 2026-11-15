# Demo repositories

The prepared content of the Asset Monitor demo (A16). Everything here is an inert local stand-in:
no real shop, no React code and no exploit code.

`fixture_server.py`, in demo mode (`NUMEN_FIXTURE_DEMO=1`), builds the demo Own repository
`asset-monitor-demo/shop` from `shop/base/` and the stand-in React Upstream repository
`asset-monitor-demo/react` from its `STAND_IN`, as bare git repositories behind its GitHub API
stand-in. `POST /admin/demo/push {"repository": "shop", "commit": "<directory>"}` commits one prepared
commit directory onto main. A commit directory holds a `MESSAGE` file and the complete files that the
commit adds or changes.

- `shop/base/`: the storefront (the Baseline), plus the vendored stand-in
  `react-server-dom-webpack-19.0.0.tgz` and the `package-lock.json` that the fixture server writes.
- `shop/1-invoice-download/`: a Vulnerability introduced. `GET /invoices/<name>` joins the decoded
  name onto `invoices/` with no containment check, so a path traversal reads any file the process
  can read (in a Lab, `/etc/passwd` of its own container).
- `shop/3-install-telemetry/`: a Malicious change. A `postinstall` hook runs an obfuscated loader
  whose decoded payload would only write the marker file `/tmp/.demo-shop-telemetry`, naming
  `NPM_TOKEN`, `GITHUB_TOKEN` and a `.test` collection host as strings. It reads no secret, makes no
  request, and nothing ever runs it: Labs install with scripts disabled and refuse a tree that
  holds a Malicious change.

This README is never committed into a stand-in repository.
