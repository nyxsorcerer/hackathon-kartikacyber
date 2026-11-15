import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { setCsrfToken } from "../api";
import { ApplicationDetail } from "./ApplicationDetail";

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken(undefined);
});

const application = {
  id: "app-1",
  asset_name: "Toko Batik Sari",
  asset_url: "https://shop.example.test/",
  product_kind: "app",
  product_name: "Shop",
  monitor_interval_seconds: 300,
  monitor_enabled: true,
  archived: false,
  source_generation: 1,
  last_check_at: null,
  next_check_at: null,
  repositories: [],
  unresolved_dependencies: [],
  version: null,
  latest_version_check: null,
  config: {
    triage_mode: "disabled",
    profiles: {},
    cve_selectors: [],
    cve_versions: [],
  },
};
const at = "2026-11-15T09:00:00Z";
const FINGERPRINT = "sha256:" + "5".repeat(64);
const agent = (overrides: object) => ({
  id: "agent-1",
  name: "web-1",
  url: "https://127.0.0.1:8792",
  status: "pending",
  fingerprint: FINGERPRINT,
  key_id: null,
  allowed_paths: ["/var/www/html"],
  watched_roots: [],
  version: "0.1.0",
  os: "linux",
  arch: "amd64",
  last_seen_at: null,
  last_refusal: { at, route: "enroll", reason: "enrollment_refused" },
  configuration: null,
  commands: [],
  ...overrides,
});
const COMMAND =
  "asset-monitor-agent enroll --url https://127.0.0.1:8792 --tls-pin " +
  "ab".repeat(32) +
  " --dashboard-key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc= --key-id dk-1 --agent-id agent-2 --allow /var/www/html";
type Call = { method: string; url: string; body?: unknown; csrf?: string };
function serve(
  items = [
    agent({}),
    agent({
      id: "agent-3",
      name: "web-3",
      status: "revoked",
      fingerprint: null,
    }),
  ],
) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method || "GET";
      calls.push({
        method,
        url,
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
        csrf: new Headers(init?.headers).get("X-CSRF-Token") || undefined,
      });
      if (method === "POST" && url === "/api/applications/app-1/agents")
        return new Response(
          JSON.stringify({
            agent: agent({
              id: "agent-2",
              status: "awaiting_enrollment",
              fingerprint: null,
            }),
            enrollment: {
              code: "0011223344556677.ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
              command: COMMAND,
              url: "https://127.0.0.1:8792",
              tls_pin: "ab".repeat(32),
              dashboard_key: "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=",
              key_id: "dk-1",
              agent_id: "agent-2",
              expires_at: at,
            },
          }),
          { status: 201 },
        );
      if (method === "POST")
        return new Response(JSON.stringify(agent({ status: "enrolled" })));
      const body =
        url === "/api/applications/app-1"
          ? application
          : url === "/api/applications/app-1/agents"
            ? {
                agent_url: "https://127.0.0.1:8792",
                items,
              }
            : { items: [], next_cursor: null };
      return new Response(JSON.stringify(body));
    }),
  );
  return calls;
}
async function open() {
  render(
    <MemoryRouter initialEntries={["/applications/app-1?tab=server"]}>
      <Routes>
        <Route path="/applications/:id" element={<ApplicationDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  const region = await screen.findByRole("region", {
    name: "On-server agents",
  });
  return within(region).findAllByRole("row");
}

it("adds an agent and shows the enroll command and code only once", async () => {
  const calls = serve();
  setCsrfToken("fixture-csrf");
  await open();
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Agent name"), "web-2");
  // The listener URL is prefilled from NUMEN_AGENT_URL.
  expect(
    screen.getByLabelText("Agent listener URL as the server sees it"),
  ).toHaveValue("https://127.0.0.1:8792");
  await user.click(screen.getByRole("button", { name: "Add agent" }));
  const dialog = await screen.findByRole("dialog");
  expect(dialog).toHaveTextContent(COMMAND);
  expect(dialog).toHaveTextContent(
    "0011223344556677.ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  );
  expect(dialog).toHaveTextContent("shown only now");
  expect(calls).toContainEqual({
    method: "POST",
    url: "/api/applications/app-1/agents",
    body: { name: "web-2", url: "https://127.0.0.1:8792" },
    csrf: "fixture-csrf",
  });
  await user.click(within(dialog).getByRole("button", { name: "Done" }));
  expect(screen.queryByText(COMMAND)).toBeNull();
  expect(screen.queryByText(/ABCDEFGHIJKLMNOPQRSTUVWXYZ234567/)).toBeNull();
});

it("lists pending agents with their fingerprint, and Confirm fingerprint posts it", async () => {
  const calls = serve();
  const [, pending, revoked] = await open();
  expect(pending).toHaveTextContent("web-1");
  expect(pending).toHaveTextContent("Pending: confirm the fingerprint");
  expect(pending).toHaveTextContent(FINGERPRINT);
  expect(pending).toHaveTextContent("/var/www/html");
  expect(pending).toHaveTextContent("0.1.0 · linux/amd64");
  expect(pending).toHaveTextContent("enrollment_refused");
  expect(
    within(pending).queryByRole("button", { name: "Check now" }),
  ).toBeNull();
  expect(revoked).toHaveTextContent("Revoked");
  expect(within(revoked).queryByRole("button")).toBeNull();
  const user = userEvent.setup();
  // The first click arms the button; the second confirms.
  await user.click(
    within(pending).getByRole("button", { name: "Confirm fingerprint" }),
  );
  await user.click(
    within(pending).getByRole("button", { name: "It matches: enroll" }),
  );
  await vi.waitFor(() =>
    expect(calls).toContainEqual(
      expect.objectContaining({
        method: "POST",
        url: "/api/agents/agent-1/confirmations",
        body: { fingerprint: FINGERPRINT },
      }),
    ),
  );
});

const SHELL_SHA = "c".repeat(64);
const entry = (path: string, sha256: string | null, extra = {}) => ({
  root: "/var/www/html",
  path,
  type: "file",
  sha256,
  size: 120,
  mode: 420,
  uid: 33,
  gid: 33,
  mtime: 1763100000,
  ...extra,
});
it("shows Server changes as text and Accept Baseline posts the manifest and its SHA-256", async () => {
  const manifest = {
    id: "m-2",
    sequence: 2,
    sha256: "d".repeat(64),
    status: "complete",
    file_count: 4,
    incomplete: [],
    created_at: at,
  };
  const calls = serve([
    agent({
      status: "enrolled",
      baseline: { manifest_id: "m-1", sha256: "e".repeat(64), accepted_at: at },
      latest_manifest: manifest,
      accept_allowed: true,
      changes: [
        {
          id: "change-1",
          agent_id: "agent-1",
          fingerprint: "f".repeat(64),
          manifest_id: "m-2",
          baseline_manifest_id: "m-1",
          diff: {
            added: [entry("wp-content/uploads/cache.php", SHELL_SHA)],
            modified: [],
            removed: [entry("old.php", "a".repeat(64))],
          },
          incomplete: [{ reason: "secret", root: "/var/www/html", path: ".env" }],
          triage_status: "disabled",
          triage_result: null,
          review_decision: "pending",
          verdict: "Insufficient context",
          analysis_state: { status: "completed" },
          held: [SHELL_SHA],
          finding_id: null,
          created_at: at,
        },
      ],
    }),
  ]);
  setCsrfToken("fixture-csrf");
  await open();
  const region = await screen.findByRole("region", {
    name: "Server changes · web-1",
  });
  expect(region).toHaveTextContent(
    "+ /var/www/html/wp-content/uploads/cache.php · cccccccccccc · mode 644 · 33:33 · bytes held",
  );
  expect(region).toHaveTextContent("- /var/www/html/old.php");
  expect(region).toHaveTextContent("secret: .env");
  expect(region).toHaveTextContent("Waiting for your review");
  const user = userEvent.setup();
  await user.click(within(region).getByRole("button", { name: "Accept Baseline" }));
  await vi.waitFor(() =>
    expect(calls).toContainEqual({
      method: "POST",
      url: "/api/agents/agent-1/baselines",
      body: { manifest_id: "m-2", manifest_sha256: "d".repeat(64) },
      csrf: "fixture-csrf",
    }),
  );
  await user.click(within(region).getByRole("button", { name: "Dismiss" }));
  await vi.waitFor(() =>
    expect(calls).toContainEqual(
      expect.objectContaining({
        method: "POST",
        url: "/api/server-changes/change-1/review",
        body: { decision: "dismissed" },
      }),
    ),
  );
});
