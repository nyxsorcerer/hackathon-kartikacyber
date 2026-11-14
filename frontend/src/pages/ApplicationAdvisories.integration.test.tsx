import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { ApplicationDetail } from "./ApplicationDetail";

afterEach(() => vi.unstubAllGlobals());

const application = {
  id: "app-1",
  asset_name: "Customer portal",
  asset_url: "https://portal.example.test",
  product_kind: "app",
  product_name: "Portal",
  monitor_interval_seconds: 300,
  monitor_enabled: true,
  archived: false,
  source_generation: 1,
  last_check_at: null,
  next_check_at: null,
  repositories: [
    {
      repository_id: "repo-own",
      role: "own",
      enabled: true,
      removed_at: null,
      locked_version: null,
      locked_version_source: null,
      release_branch: null,
      release_branch_status: null,
      packages: [],
      source_kind: "github",
      source_url: "https://github.com/acme/portal",
      plugin_slug: null,
      source_ref: null,
      source_path: null,
      cursor: "c".repeat(40),
      baseline_revision: "c".repeat(40),
      last_check_at: "2026-11-12T10:00:00Z",
      last_error: null,
    },
  ],
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
const CVE = "CVE-2026-111497";
const range = [
  [">=", "20.0.0"],
  ["<", "20.19.5"],
];
// GET /applications/{id}/advisories: what the last Advisory check collected and matched (A09).
const advisories = {
  repository_id: "repo-own",
  revision: "c".repeat(40),
  collected_at: "2026-11-13T09:00:00Z",
  feeds: {
    osv: { records: 1 },
    nvd: { records: 1 },
    ghsa: {
      error: {
        code: "github_token_required",
        message: "Add a GitHub read token",
      },
    },
  },
  runtimes: [
    {
      name: "node",
      version: "20.11.1",
      field: "dockerfile",
      source: "Dockerfile",
      image: "node",
      tag: "20.11.1-alpine",
      reason: null,
      exposure: "exposed",
    },
    {
      name: "node",
      version: null,
      field: "dockerfile",
      source: "deploy/Dockerfile",
      image: "node",
      tag: "lts",
      reason: "a moving tag",
      exposure: "unknown",
    },
  ],
  packages: [
    {
      ecosystem: "npm",
      name: "react-server-dom-webpack",
      version: "19.0.0",
      source: "package-lock.json",
      direct: true,
      reason: null,
      exposure: "not_exposed",
    },
    {
      ecosystem: "npm",
      name: "left-pad",
      version: null,
      source: "package.json",
      direct: true,
      reason: "no lockfile entry",
      exposure: "unknown",
    },
  ],
  matches: [
    {
      id: "match-1",
      vulnerability: CVE,
      aliases: ["BIT-node-2026-111497", CVE, "GHSA-9c4w-m7v2-x5qh"],
      state: "exposed",
      finding_id: "finding-1",
      summary: "<script>alert('feed')</script> Node.js request smuggling",
      severity: "high",
      feeds: ["nvd", "osv"],
      references: [],
      pins: [
        {
          kind: "runtime",
          ecosystem: null,
          name: "node",
          version: "20.11.1",
          sources: ["Dockerfile"],
          ranges: { osv: [range], nvd: [range] },
          state: "exposed",
        },
      ],
      updated_at: "2026-11-13T09:00:00Z",
    },
  ],
};
type Call = { method: string; url: string };
function serve() {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method || "GET";
      calls.push({ method, url });
      if (method === "POST")
        return new Response(
          JSON.stringify({ job_id: "job-1", status_url: "/api/jobs/job-1" }),
          { status: 202 },
        );
      const body =
        url === "/api/applications/app-1"
          ? application
          : url === "/api/applications/app-1/advisories"
            ? advisories
            : { items: [], next_cursor: null };
      return new Response(JSON.stringify(body));
    }),
  );
  return calls;
}
function open() {
  return render(
    <MemoryRouter initialEntries={["/applications/app-1?tab=advisories"]}>
      <Routes>
        <Route path="/applications/:id" element={<ApplicationDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

it("lists runtime and package pins with their source and unknown state", async () => {
  const calls = serve();
  const { container } = open();
  const runtimes = await screen.findByRole("region", { name: "Runtimes" });
  const [exposed, moving] = within(runtimes).getAllByRole("row").slice(1);
  expect(exposed).toHaveTextContent("node");
  expect(exposed).toHaveTextContent("20.11.1");
  expect(exposed).toHaveTextContent("node:20.11.1-alpine");
  expect(exposed).toHaveTextContent("Dockerfile");
  expect(exposed).toHaveTextContent("Exposed");
  // AC-A09: a version that cannot be read is unknown, which counts as exposed, never Not exposed.
  expect(moving).toHaveTextContent("node:lts");
  expect(moving).toHaveTextContent(/Unknown.*a moving tag/);
  expect(moving).toHaveTextContent("counts as exposed");
  expect(moving).not.toHaveTextContent("Not exposed");

  const packages = screen.getByRole("region", { name: "Packages" });
  const [locked, unlocked] = within(packages).getAllByRole("row").slice(1);
  expect(locked).toHaveTextContent("npm");
  expect(locked).toHaveTextContent("react-server-dom-webpack");
  expect(locked).toHaveTextContent("19.0.0");
  expect(locked).toHaveTextContent("package-lock.json");
  expect(locked).toHaveTextContent("Not exposed");
  expect(unlocked).toHaveTextContent(/Unknown.*no lockfile entry/);
  expect(unlocked).toHaveTextContent("counts as exposed");
  expect(unlocked).not.toHaveTextContent("Not exposed");

  // Each feed's state, and a failed feed's reason.
  const check = screen.getByRole("region", { name: "Advisory check" });
  expect(check).toHaveTextContent("OSV1 record");
  expect(check).toHaveTextContent("GHSAFailed: Add a GitHub read token");

  // Feed text is shown as text: the <script> in a summary is never markup.
  const matches = screen.getByRole("region", { name: "Matches" });
  expect(matches).toHaveTextContent(
    "<script>alert('feed')</script> Node.js request smuggling",
  );
  expect(container.querySelector("script")).toBeNull();
  expect(within(matches).getByText("GHSA-9c4w-m7v2-x5qh")).toBeInTheDocument();
  expect(within(matches).getByRole("link", { name: CVE })).toHaveAttribute(
    "href",
    "/findings/finding-1",
  );

  await userEvent
    .setup()
    .click(screen.getByRole("button", { name: "Run Advisory check" }));
  expect(calls).toContainEqual({
    method: "POST",
    url: "/api/applications/app-1/advisory-checks",
  });
});
