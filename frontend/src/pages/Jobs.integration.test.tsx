import { act, cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { JobDetail, Jobs } from "./Jobs";
import { AnalysisHistory } from "./Commits";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it.each(["succeeded", "failed"])(
  "links a %s CVE job to its report and retained finding bundle",
  async (status) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        const body = url.endsWith("/events")
          ? { items: [], next_cursor: null }
          : {
              id: "job-1",
              kind: "cve_analysis",
              application_id: "application-1",
              status,
              progress: {},
              created_at: "2026-10-04T00:00:00Z",
              error: status === "failed" ? { message: "Missing PoC" } : null,
              result: {
                cve_id: "CVE-2026-12345",
                analysis_id: "analysis-1",
                finding_id: "finding-1",
              },
            };
        return new Response(JSON.stringify(body), {
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    render(
      <MemoryRouter initialEntries={["/jobs/job-1"]}>
        <Routes>
          <Route path="/jobs/:id" element={<JobDetail />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(
      await screen.findByRole("link", { name: "View CVE analysis and report" }),
    ).toHaveAttribute(
      "href",
      "/cves?cve=CVE-2026-12345&cve_application=application-1&view=analysis&run=analysis-1",
    );
    expect(
      screen.getByRole("link", { name: "View finding artifacts" }),
    ).toHaveAttribute("href", "/findings/finding-1");
  },
);

it("links the CVE analysis history to its generated finding", () => {
  render(
    <MemoryRouter>
      <AnalysisHistory
        applicationId="application-1"
        analyses={[
          {
            id: "analysis-1",
            result: { summary: "CVE investigation", finding_id: "finding-1" },
          },
        ]}
      />
    </MemoryRouter>,
  );
  expect(
    screen.getByRole("link", { name: "View finding artifacts" }),
  ).toHaveAttribute("href", "/findings/finding-1");
});

it.each(["cancelling", "succeeded", "failed", "cancelled"])(
  "keeps the %s job's agent session visible and read only",
  async (status) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        const body = url.endsWith("/events")
          ? { items: [], next_cursor: null }
          : url.includes("/session")
            ? {
                runs: ["run-1"],
                run_id: "run-1",
                agent_status: status,
                held: false,
                live: status === "cancelling",
                screen: "Retained first line\nRetained final line",
              }
            : {
                id: "job-1",
                kind: "cve_analysis",
                status,
                progress: {},
                created_at: "2026-10-04T00:00:00Z",
                profile: {
                  agent: "codex",
                  connection_id: "account-1",
                  model_id: "gpt-5",
                  reasoning_effort: null,
                },
                error: null,
                result: null,
              };
        return new Response(JSON.stringify(body), {
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    render(
      <MemoryRouter initialEntries={["/jobs/job-1"]}>
        <Routes>
          <Route path="/jobs/:id" element={<JobDetail />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(
      await screen.findByRole("region", { name: "Agent terminal output" }),
    ).toHaveTextContent("Retained first line Retained final line");
    // Only a running job offers controls; this session is for review.
    expect(
      screen.queryByRole("textbox", { name: "Message the agent" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Send" }),
    ).not.toBeInTheDocument();
  },
);

it.each([
  { kind: "account_login", title: "Account login" },
  { kind: "account_capabilities", title: "Account capabilities" },
])(
  "does not mount an interactive terminal for $kind jobs with a profile",
  async ({ kind, title }) => {
    const fetch = vi.fn(
      async (url: string) =>
        new Response(
          JSON.stringify(
            url.endsWith("/events")
              ? { items: [], next_cursor: null }
              : {
                  id: "job-1",
                  kind,
                  status: "running",
                  progress: {},
                  created_at: "2026-10-04T00:00:00Z",
                  profile: {
                    agent: "codex",
                    connection_id: "account-1",
                    model_id: "gpt-5",
                    reasoning_effort: null,
                  },
                  error: null,
                  result: null,
                },
          ),
          { headers: { "Content-Type": "application/json" } },
        ),
    );
    vi.stubGlobal("fetch", fetch);
    render(
      <MemoryRouter initialEntries={["/jobs/job-1"]}>
        <Routes>
          <Route path="/jobs/:id" element={<JobDetail />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(
      await screen.findByRole("heading", { name: title }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Agent session" }),
    ).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([url]) => url.includes("/session"))).toBe(
      false,
    );
  },
);

it("loads the final transcript after a running job passes through read-only cancellation", async () => {
  vi.useFakeTimers();
  let status = "running";
  const output: Record<string, string> = {
    running: "FIRST\nRunning output",
    cancelling: "FIRST\nCancellation checkpoint",
    cancelled: "FIRST\nFinal complete cancellation transcript\nLAST",
  };
  const fetch = vi.fn(async (url: string) => {
    const body = url.endsWith("/events")
      ? { items: [], next_cursor: null }
      : url.includes("/session")
        ? {
            runs: ["run-1"],
            run_id: "run-1",
            agent_status: status,
            held: false,
            live: status === "running",
            screen: output[status],
          }
        : {
            id: "job-1",
            kind: "cve_analysis",
            status,
            progress: {},
            created_at: "2026-10-04T00:00:00Z",
            error: null,
            result: null,
            profile: {
              agent: "codex",
              connection_id: "account-1",
              model_id: "gpt-5",
              reasoning_effort: null,
            },
          };
    return new Response(JSON.stringify(body), {
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetch);
  render(
    <MemoryRouter initialEntries={["/jobs/job-1"]}>
      <Routes>
        <Route path="/jobs/:id" element={<JobDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  await act(async () => {});
  expect(
    screen.getByRole("textbox", { name: "Message the agent" }),
  ).toBeEnabled();
  status = "cancelling";
  await act(async () => {
    await vi.advanceTimersByTimeAsync(3000);
  });
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Cancellation checkpoint");
  expect(
    screen.queryByRole("textbox", { name: "Message the agent" }),
  ).not.toBeInTheDocument();
  const checkpointReads = fetch.mock.calls.filter(([url]) =>
    url.includes("/session"),
  ).length;
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1500);
  });
  expect(
    fetch.mock.calls.filter(([url]) => url.includes("/session")).length,
  ).toBeGreaterThan(checkpointReads);
  status = "cancelled";
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1500);
  });
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }).textContent,
  ).toBe("FIRST\nFinal complete cancellation transcript\nLAST");
  const finalReads = fetch.mock.calls.filter(([url]) =>
    url.includes("/session"),
  ).length;
  await act(async () => {
    await vi.advanceTimersByTimeAsync(10000);
  });
  expect(
    fetch.mock.calls.filter(([url]) => url.includes("/session")),
  ).toHaveLength(finalReads);
});

const triage = {
  id: "job-triage",
  kind: "commit_triage",
  application_id: "application-1",
  application_name: "Customer portal",
  subject: {
    type: "commit",
    label: "Potential path traversal in template selection",
    ref: "a1b2c3d4e5",
    link: "/commits/commit-1",
  },
  status: "succeeded",
  progress: { stage: "runtime", status: "succeeded" },
  created_at: "2026-10-04T00:00:00Z",
  started_at: "2026-10-04T00:00:00Z",
  finished_at: "2026-10-04T00:02:30Z",
  error: null,
  result: {
    decision: "security_candidate",
    change_kind: "vulnerability_fix",
    confidence: { level: "medium" },
  },
};
function serveJobs(jobs: Record<string, unknown>[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const job = jobs.find((j) => url === `/api/jobs/${String(j.id)}`);
      const body = job
        ? job
        : url.startsWith("/api/applications")
          ? { items: [], next_cursor: null }
          : url.startsWith("/api/jobs?") || url.endsWith("/events")
            ? { items: url.endsWith("/events") ? [] : jobs, next_cursor: null }
            : {};
      return new Response(JSON.stringify(body));
    }),
  );
}
function renderJob(id: string) {
  render(
    <MemoryRouter initialEntries={[`/jobs/${id}`]}>
      <Routes>
        <Route path="/jobs/:id" element={<JobDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

it("names each job's subject, links to it and its application, and states the outcome", async () => {
  serveJobs([triage]);
  render(
    <MemoryRouter initialEntries={["/jobs"]}>
      <Routes>
        <Route path="/jobs" element={<Jobs />} />
      </Routes>
    </MemoryRouter>,
  );
  const title = await screen.findByRole("link", {
    name: "Potential path traversal in template selection",
  });
  expect(title).toHaveAttribute("href", "/jobs/job-triage");
  const row = title.closest("tr")!;
  expect(
    within(row).getByRole("link", { name: /Open commit a1b2c3d4e5/ }),
  ).toHaveAttribute("href", "/commits/commit-1");
  expect(
    within(row).getByRole("link", { name: "Customer portal" }),
  ).toHaveAttribute("href", "/applications/application-1");
  expect(
    within(row).getByText("Flagged as a security candidate"),
  ).toBeInTheDocument();
  expect(within(row).getByText("took 3 min")).toBeInTheDocument();
});

it("explains a failure with its code, remedy, and where to fix it", async () => {
  serveJobs([
    {
      ...triage,
      id: "job-failed",
      kind: "version_recipe",
      subject: {
        type: "version",
        label: "example/portal",
        ref: null,
        link: "/applications/application-1?tab=version",
      },
      status: "failed",
      result: null,
      error: {
        code: "source_not_checked",
        message: "Complete a source check before generating grounded evidence",
        retryable: false,
      },
    },
  ]);
  renderJob("job-failed");
  expect(
    await screen.findByRole("heading", {
      level: 1,
      name: "Version recipe: example/portal",
    }),
  ).toBeInTheDocument();
  const outcome = screen.getByRole("region", { name: "Job outcome" });
  expect(outcome).toHaveTextContent(
    "Version recipe failed: Complete a source check before generating grounded evidence.",
  );
  expect(outcome).toHaveTextContent(
    "Run a source check for this application first, then retry this job.",
  );
  expect(
    within(outcome).getByText("Error code source_not_checked"),
  ).toBeInTheDocument();
  expect(
    within(outcome).getByRole("link", { name: "Open application" }),
  ).toHaveAttribute("href", "/applications/application-1");
  expect(screen.queryByText("Application details")).not.toBeInTheDocument();
  expect(
    screen.getAllByRole("link", { name: "Customer portal" })[0],
  ).toHaveAttribute("href", "/applications/application-1");
});

it("summarizes what a successful job produced", async () => {
  serveJobs([
    {
      ...triage,
      id: "job-source",
      kind: "source_check",
      subject: {
        type: "source",
        label: "example/portal",
        ref: null,
        link: "/applications/application-1?tab=repositories",
      },
      result: { imported: 87, baseline: false, source_ref: "f".repeat(40) },
    },
  ]);
  renderJob("job-source");
  const outcome = await screen.findByRole("region", { name: "Job outcome" });
  expect(outcome).toHaveTextContent(
    "Source check succeeded: Imported 87 new revisions",
  );
  expect(
    within(outcome).getByText(`Upstream at ${"f".repeat(10)}`),
  ).toBeInTheDocument();
  expect(within(outcome).getByText("Took 3 min")).toBeInTheDocument();
  expect(
    screen.getAllByRole("link", { name: /Open repositories/ })[0],
  ).toHaveAttribute("href", "/applications/application-1?tab=repositories");
});

it("summarizes an Upstream derivation", async () => {
  serveJobs([
    {
      ...triage,
      id: "job-derive",
      kind: "derive_upstreams",
      subject: {
        type: "source",
        label: "example/portal",
        ref: null,
        link: "/applications/application-1?tab=repositories",
      },
      result: {
        source_ref: "f".repeat(40),
        repositories: 3,
        added: ["https://github.com/facebook/react"],
        removed: [],
        unresolved: 2,
      },
    },
  ]);
  renderJob("job-derive");
  const outcome = await screen.findByRole("region", { name: "Job outcome" });
  expect(outcome).toHaveTextContent(
    "Derive upstreams succeeded: Found 3 Upstream repositories",
  );
  expect(within(outcome).getByText("1 added")).toBeInTheDocument();
  expect(
    within(outcome).getByText("2 unresolved packages"),
  ).toBeInTheDocument();
});
