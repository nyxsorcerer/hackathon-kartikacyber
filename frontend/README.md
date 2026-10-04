# Numen frontend

React and TypeScript dashboard, built with Vite. Production assets are served by the authenticated FastAPI application; the browser accesses `/api` on its own origin.

```sh
npm ci
npm run dev
```

The development server binds to `127.0.0.1:5173` and proxies `/api` to `http://127.0.0.1:8000`. Set `NUMEN_API_PROXY=http://127.0.0.1:8787` to review a Compose deployment through Vite. Use the Node version declared in the root Dockerfile. No credential belongs in a Vite environment variable or browser storage.

```sh
npm run typecheck
npm run lint
npm test
npm run build
npm run format:check
```

Focused tests isolate the API boundary and exercise authentication/CSRF, explicit analysis submission with native runtime capabilities, WordPress insertion and retained validation input, truthful error states, safe report rendering, and artifact-revision navigation. Deployment, durable backend state, actual provider compatibility, and browser layout are verified by the root integration journey.

Native subscription connections support a write-only JSON file import from Accounts. Claude accepts its native `.credentials.json` file (or `credentials_json` wrapper); Codex accepts native `auth.json` (or `auth_json` wrapper) and retains the device-login flow. Files are bounded to 1 MiB, never previewed, and cleared from the file selector after import. Import leaves access unchecked; run Check separately to validate eligibility and discover models.
