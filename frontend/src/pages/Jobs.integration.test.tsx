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
    title: "Potential path traversal in template selection",
    reason: "The include path is now validated",
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

it("summarizes an Advisory check", async () => {
  serveJobs([
    {
      ...triage,
      id: "job-advisory",
      kind: "advisory_check",
      subject: {
        type: "advisory",
        label: "example/portal",
        ref: null,
        link: "/applications/application-1?tab=advisories",
      },
      result: {
        source_ref: "f".repeat(40),
        runtimes: 3,
        packages: 120,
        unknown: 1,
        matches: 2,
        opened: 1,
        attached: 1,
        finding_ids: ["finding-1", "finding-2"],
      },
    },
  ]);
  renderJob("job-advisory");
  const outcome = await screen.findByRole("region", { name: "Job outcome" });
  expect(outcome).toHaveTextContent(
    "Advisory check succeeded: Collected 3 runtime and 120 package pins · 1 Finding opened",
  );
  expect(
    within(outcome).getByText("1 unreadable version, counted as exposed"),
  ).toBeInTheDocument();
  expect(
    within(outcome).getByText("Attached to 1 Finding"),
  ).toBeInTheDocument();
  expect(
    screen.getAllByRole("link", { name: /Open Advisories/ })[0],
  ).toHaveAttribute("href", "/applications/application-1?tab=advisories");
});

it.each([
  [
    "served_check",
    { pages: 2, fetches: 4, changed: 1, matches: 3, awaiting_baseline: 0, failed: 0 },
    "Served-content check succeeded: 2 Watched pages checked · 1 changed fingerprint",
  ],
  [
    "served_triage",
    { decision: "security_candidate" },
    "Served-content Triage succeeded: Flagged as a security candidate",
  ],
  [
    "served_analysis",
    { verdict: "Malicious change", confidence: "high", finding_id: "f-1" },
    "Served-content Analysis succeeded: Malicious change · finding created",
  ],
  [
    "served_content_sweep",
    { status: "matched", count: 2, matches: [], truncated: false },
    "Detection rule sweep of served content succeeded: 2 matches in stored served content",
  ],
])("summarizes a %s job", async (kind, result, heading) => {
  serveJobs([
    {
      ...triage,
      id: "job-served",
      kind,
      subject: {
        type: "served",
        label: "https://shop.test/ · Googlebot",
        ref: "cccccccccccc",
        link: "/applications/application-1?tab=served",
      },
      result,
    },
  ]);
  renderJob("job-served");
  const outcome = await screen.findByRole("region", { name: "Job outcome" });
  expect(outcome).toHaveTextContent(heading);
  expect(
    screen.getAllByRole("link", { name: /Open Served content/ })[0],
  ).toHaveAttribute("href", "/applications/application-1?tab=served");
});

it("summarizes an Analysis by its Verdict and confidence", async () => {
  serveJobs([
    {
      ...triage,
      id: "job-analysis",
      kind: "commit_analysis",
      result: {
        verdict: "Vulnerability fix",
        confidence: "high",
        finding_id: "finding-1",
      },
    },
  ]);
  renderJob("job-analysis");
  const outcome = await screen.findByRole("region", { name: "Job outcome" });
  expect(outcome).toHaveTextContent(
    "Commit analysis succeeded: Vulnerability fix · finding created",
  );
  expect(within(outcome).getByText("High confidence")).toBeInTheDocument();
});

it.each([
  [
    "commit_analysis",
    "api_key_required",
    "Automated runs use only Provider accounts that hold an API key.",
  ],
  ["commit_triage", "triage_codex_unsupported", "Triage cannot run on Codex."],
  [
    "commit_analysis",
    "analysis_codex_unsupported",
    "Analysis and CVE analysis cannot run on Codex",
  ],
  [
    "commit_analysis",
    "verdict_not_allowed",
    "Served content can only be Malicious change",
  ],
  [
    "commit_analysis",
    "timeout",
    "Analysis stopped at its 30-minute deadline. The change stays pending and is never read as Unrelated.",
  ],
  [
    "lab_run",
    "broker_unavailable",
    "A Lab is not retried: fix the cause, then start a new Lab from its Finding with a new Approval.",
  ],
  [
    "remediation_pr",
    "github_write_token_required",
    "Add a GitHub write token under Settings → Integrations, then approve again.",
  ],
  [
    "remediation_pr",
    "github_write_failed",
    "A Remediation PR is not retried: fix the cause, then approve it again from its Finding.",
  ],
  [
    "patch_drafting",
    "diff_rejected",
    "A draft is not retried: fix the cause, then draft it again from its Finding.",
  ],
])("explains a %s failed with %s", async (kind, code, hint) => {
  serveJobs([
    {
      ...triage,
      id: "job-failed",
      kind,
      status: "failed",
      result: null,
      error: { code, message: "Refused", retryable: false },
    },
  ]);
  renderJob("job-failed");
  expect(
    await screen.findByRole("region", { name: "Job outcome" }),
  ).toHaveTextContent(hint);
});

it("offers no Retry for a failed Lab or Remediation PR: each needs a new Approval", async () => {
  const failed = {
    status: "failed",
    result: null,
    error: { code: "invalid_lab_result", message: "No result" },
  };
  serveJobs([
    { ...triage, ...failed },
    {
      ...triage,
      ...failed,
      id: "job-lab",
      kind: "lab_run",
      subject: {
        type: "finding",
        label: "Stored XSS in settings",
        ref: null,
        link: "/findings/finding-1",
      },
    },
    {
      ...triage,
      ...failed,
      id: "job-pr",
      kind: "remediation_pr",
      subject: {
        type: "finding",
        label: "Stored XSS in timezone settings",
        ref: null,
        link: "/findings/finding-2",
      },
    },
  ]);
  render(
    <MemoryRouter initialEntries={["/jobs"]}>
      <Routes>
        <Route path="/jobs" element={<Jobs />} />
      </Routes>
    </MemoryRouter>,
  );
  const row = async (name: string) =>
    (await screen.findByRole("link", { name })).closest("tr")!;
  const triageRow = await row("Potential path traversal in template selection");
  expect(
    within(triageRow).getByRole("button", { name: "Retry" }),
  ).toBeInTheDocument();
  const labRow = await row("Stored XSS in settings");
  expect(
    within(labRow).queryByRole("button", { name: "Retry" }),
  ).not.toBeInTheDocument();
  const prRow = await row("Stored XSS in timezone settings");
  expect(
    within(prRow).queryByRole("button", { name: "Retry" }),
  ).not.toBeInTheDocument();
});

it("summarises a detection_rule job by its result", async () => {
  const passed = (name: string) => ({ name, status: "passed", message: "" });
  for (const [result, summary, tone] of [
    [
      { current: true, checks: ["rule", "changed", "parent"].map(passed) },
      "Detection rule succeeded: Detection rule validated",
      "good",
    ],
    [
      {
        current: true,
        checks: [
          passed("rule"),
          passed("changed"),
          { name: "parent", status: "failed", message: "", files: ["a.js"] },
          { name: "baseline", status: "failed", message: "" },
        ],
      },
      "Detection rule succeeded: Detection rule failed: Matches nothing in the parent tree",
      "warm",
    ],
    [
      { current: false, checks: [passed("rule")] },
      "Detection rule succeeded: Validated an earlier revision",
      "good",
    ],
  ] as const) {
    serveJobs([
      {
        ...triage,
        id: "job-rule",
        kind: "detection_rule",
        subject: null,
        result: { finding_id: "finding-1", artifact_revision: "r1", ...result },
      },
    ]);
    renderJob("job-rule");
    const outcome = await screen.findByRole("region", { name: "Job outcome" });
    expect(outcome).toHaveTextContent(summary);
    expect(outcome).toHaveClass(tone);
    cleanup();
  }
});
