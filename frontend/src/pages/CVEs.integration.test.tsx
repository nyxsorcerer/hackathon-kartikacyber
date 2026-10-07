import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { CVEList } from "./CVEs";
import type { CVE, Program } from "../types";

const scrollTo = HTMLElement.prototype.scrollTo;
beforeEach(() => {
  HTMLElement.prototype.scrollTo = vi.fn();
});
afterEach(() => {
  HTMLElement.prototype.scrollTo = scrollTo;
  vi.unstubAllGlobals();
});
const profile = {
  agent: "codex" as const,
  connection_id: "account",
  model_id: "fixture-model",
  reasoning_effort: "high",
};
const program: Program = {
  id: "program",
  asset_name: "Customer portal",
  asset_url: "https://example.test",
  product_kind: "cms",
  product_name: "Example CMS",
  source_kind: "github",
  source_url: "https://github.com/example/cms",
  source_ref: "main",
  monitor_interval_days: 7,
  monitor_enabled: true,
  archived: false,
  source_generation: 1,
  last_check_at: null,
  next_check_at: null,
  last_error: null,
  version: null,
  config: {
    profiles: {},
    triage_mode: "disabled",
    cve_selectors: [],
    cve_min_score: 7,
    cve_versions: ["3.1"],
    cve_auto_analyze: false,
    audit_auto_refresh: false,
  },
};
const cve: CVE = {
  id: "CVE-2026-12345",
  program_id: "program",
  title: "Stored XSS in account settings",
  description: "A stored value executes in the administrator's browser.",
  scores: [
    {
      version: "3.1",
      base_score: 9.6,
      source: "nvd@nist.gov",
      vector: "CVSS:3.1/AV:N",
    },
  ],
  qualifying_score: {
    version: "3.1",
    base_score: 9.6,
    source: "nvd@nist.gov",
    vector: "CVSS:3.1/AV:N",
  },
  match_status: "confirmed",
  eligible: true,
  applicability: "unknown",
  affected_versions: ["1.0.0"],
  fixed_versions: ["1.0.1"],
  references: [],
  analyses: [
    {
      id: "latest",
      job_id: "latest-job",
      created_at: "2026-10-06T00:00:00Z",
      profile,
      result: {
        summary: "The issue is reproducible in the pinned source.",
        applicability: "unknown",
        confidence: {
          level: "high",
          basis: "Pinned source and local reproduction",
        },
        open_questions: ["The deployed version still needs confirmation."],
        affected_versions: [
          { product: "Example CMS", range: ">= 1.0.0, < 1.0.1" },
        ],
        fixed_versions: [{ product: "Example CMS", version: "1.0.1" }],
        finding_id: "finding",
      },
      artifacts: [
        {
          id: "latest-report",
          path: "report.md",
          size: 80,
          sha256: "a".repeat(64),
        },
      ],
    },
    {
      id: "earlier",
      job_id: "earlier-job",
      created_at: "2026-10-05T00:00:00Z",
      result: { summary: "Earlier investigation retained partial evidence." },
      artifacts: [
        {
          id: "earlier-report",
          path: "report.md",
          size: 70,
          sha256: "b".repeat(64),
        },
      ],
    },
  ],
};
function setup(url: string, record = cve) {
  const submissions: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === "POST" && url.endsWith("/analyses")) {
        submissions.push(JSON.parse(String(init.body)));
        return new Response(
          JSON.stringify({
            job_id: "queued-job",
            status_url: "/api/jobs/queued-job",
          }),
        );
      }
      if (url.includes("/api/artifacts/"))
        return new Response(
          url.includes("earlier") ? "# Earlier report" : "# Latest report",
        );
      if (url.startsWith("/api/jobs/"))
        return new Response(
          JSON.stringify({
            id: url.split("/").at(-1),
            kind: "cve_analysis",
            status: url.includes("earlier") ? "failed" : "succeeded",
            progress: {},
            created_at: "2026-10-06T00:00:00Z",
            error: url.includes("earlier")
              ? { message: "Missing Python PoC" }
              : null,
            result: null,
          }),
        );
      const body =
        url === "/api/programs/program"
          ? program
          : url === "/api/accounts"
            ? {
                items: [
                  {
                    id: "account",
                    label: "Fixture account",
                    provider: "openai",
                    auth_type: "api_key",
                    supported_agents: ["codex"],
                    status: "ready",
                    credential_configured: true,
                    models: [
                      {
                        id: "fixture-model",
                        name: "Fixture model",
                        reasoning_efforts: ["high"],
                        default_effort: "high",
                      },
                    ],
                  },
                ],
                next_cursor: null,
              }
            : url === "/api/settings"
              ? {
                  monitor_interval_days: 7,
                  default_profiles: { cve_analysis: profile },
                  webhook_enabled: false,
                  webhook_configured: false,
                }
              : { items: [program], next_cursor: null };
      return new Response(JSON.stringify(body));
    }),
  );
  render(
    <MemoryRouter initialEntries={[url]}>
      <CVEList
        collection={{
          data: { items: [record], truncated: false },
          loading: false,
          refreshing: false,
          refresh: vi.fn(),
        }}
      />
    </MemoryRouter>,
  );
  return submissions;
}

it("opens saved analysis links, switches runs, and downloads the selected run's immutable output", async () => {
  setup("/cves?cve=CVE-2026-12345&cvep=program&view=analysis");
  expect(
    await screen.findByRole("heading", { name: "Latest report" }),
  ).toBeInTheDocument();
  expect(
    screen.getByText("The issue is reproducible in the pinned source."),
  ).toBeInTheDocument();
  expect(
    screen.queryByText("Earlier investigation retained partial evidence."),
  ).not.toBeInTheDocument();
  expect(
    screen.getByRole("link", { name: "Download analysis bundle" }),
  ).toHaveAttribute("href", "/api/analyses/latest/download");
  expect(screen.getByRole("link", { name: "View job" })).toHaveAttribute(
    "href",
    "/jobs/latest-job",
  );
  expect(
    screen.getByText("The deployed version still needs confirmation."),
  ).toBeInTheDocument();
  expect(screen.getByText("Example CMS >= 1.0.0, < 1.0.1")).toBeInTheDocument();
  expect(screen.getByText("Example CMS 1.0.1")).toBeInTheDocument();
  await userEvent
    .setup()
    .selectOptions(screen.getByLabelText("Analysis run"), "earlier");
  expect(
    await screen.findByRole("heading", { name: "Earlier report" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("heading", { name: "Latest report" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByRole("link", { name: "Download analysis bundle" }),
  ).toHaveAttribute("href", "/api/analyses/earlier/download");
  expect(await screen.findByText(/Missing Python PoC/)).toBeInTheDocument();
  await userEvent
    .setup()
    .click(screen.getByRole("button", { name: "Analyze CVE" }));
  await userEvent
    .setup()
    .click(await screen.findByRole("button", { name: "Cancel" }));
  expect(
    await screen.findByRole("heading", { name: "Earlier report" }),
  ).toBeInTheDocument();
});

it("returns to CVE details on cancel and submits the selected profile and vulnerable revision", async () => {
  const submissions = setup("/cves?cve=CVE-2026-12345&cvep=program");
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Analyze CVE" }));
  await user.click(await screen.findByRole("button", { name: "Cancel" }));
  const detail = screen.getByRole("dialog", { name: "CVE-2026-12345" });
  expect(detail).toBeInTheDocument();
  await user.click(within(detail).getByRole("button", { name: "Analyze CVE" }));
  await user.type(
    await screen.findByLabelText("Vulnerable revision (optional)"),
    "1.0.0",
  );
  await user.click(screen.getByRole("button", { name: "Start analysis" }));
  expect(
    await screen.findByRole("dialog", { name: "CVE-2026-12345" }),
  ).toBeInTheDocument();
  expect(submissions).toEqual([{ profile, source_ref: "1.0.0" }]);
});

it("keeps ineligible records inspectable and explains their analysis gate", () => {
  setup("/cves?cve=CVE-2026-12345&cvep=program&act=analyze", {
    ...cve,
    eligible: false,
    qualifying_score: null,
    eligibility_reason: "Product identity requires confirmation",
  });
  expect(screen.getByRole("button", { name: "Analyze CVE" })).toBeDisabled();
  expect(
    screen.getByText(/Product identity requires confirmation/),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Confirm product match" }),
  ).toBeEnabled();
});

it("opens existing CVE notification links and clears their selection when closed", async () => {
  setup("/cves?program_id=program&cve_id=CVE-2026-12345");
  const dialog = screen.getByRole("dialog", { name: "CVE-2026-12345" });
  await userEvent
    .setup()
    .click(within(dialog).getByRole("button", { name: "Close dialog" }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});
