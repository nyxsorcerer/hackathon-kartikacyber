import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { Reviews, CommitDetail } from "./Commits";

afterEach(() => vi.unstubAllGlobals());
const applications = ["alpha", "beta"].map((id) => ({
  id,
  asset_name: id === "alpha" ? "Customer portal" : "Partner site",
  asset_url: `https://${id}.example.test`,
  product_kind: "cms",
  product_name: "Example CMS",
  monitor_interval_seconds: 604800,
  monitor_enabled: true,
  archived: false,
  source_generation: 1,
  last_check_at: null,
  next_check_at: null,
  repositories: [],
  version: null,
  config: {
    profiles: {},
    triage_mode: "codex",
    cve_selectors: [],
    cve_versions: [],
    cve_auto_analyze: false,
  },
}));
const records = ["alpha", "beta"].map((id) => ({
  id: `${id}-commit`,
  application_id: id,
  revision: id === "alpha" ? "a".repeat(40) : "b".repeat(40),
  message:
    id === "alpha" ? "Update template handling" : "Adjust login processing",
  author: "Upstream",
  committed_at: "2026-10-06T00:00:00Z",
  files: [{ path: "src/controller.php" }],
  diff: "- old\n+ new",
  diff_complete: true,
  triage_status: "completed",
  review_decision: "candidate",
  triage_result: {
    decision: "security_candidate",
    title:
      id === "alpha"
        ? "Potential path traversal through template selection"
        : "Potential authorization bypass in partner login",
    reason: "A trust boundary changed",
  },
  verdict: null,
  analysis_state: null,
  prefilter: [],
  analyses: [],
}));
function fixture() {
  const fetch = vi.fn(async (url: string) => {
    const items =
      url.includes("/applications") && !url.includes("/commits")
        ? applications
        : records.filter(
            (c) =>
              !url.includes("application_id=") ||
              url.includes(`application_id=${c.application_id}`),
          );
    return new Response(JSON.stringify({ items, next_cursor: null }));
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

it("starts with application selection and reviews only the chosen application's security queue", async () => {
  const fetch = fixture();
  render(
    <MemoryRouter initialEntries={["/reviews"]}>
      <Routes>
        <Route path="/reviews" element={<Reviews />} />
      </Routes>
    </MemoryRouter>,
  );
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole("link", {
      name: "Review commits for Customer portal",
    }),
  );
  expect(
    await screen.findByRole("link", {
      name: "Potential path traversal through template selection",
    }),
  ).toHaveAttribute("href", "/commits/alpha-commit");
  expect(
    screen.queryByRole("link", {
      name: "Potential authorization bypass in partner login",
    }),
  ).not.toBeInTheDocument();
  expect(screen.getByText("Update template handling")).toBeInTheDocument();
  expect(
    fetch.mock.calls.some(
      ([url]) =>
        url.startsWith("/api/commits?") && !url.includes("application_id="),
    ),
  ).toBe(false);
  await user.selectOptions(screen.getByLabelText("Application"), "beta");
  expect(
    await screen.findByRole("link", {
      name: "Potential authorization bypass in partner login",
    }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("link", {
      name: "Potential path traversal through template selection",
    }),
  ).not.toBeInTheDocument();
});

it("presents each Verdict with its confidence and selects one report at a time", async () => {
  const commit = {
    ...records[0],
    verdict: "Security hardening",
    analyses: [
      {
        id: "hardening",
        job_id: "job-hardening",
        created_at: "2026-10-06T00:00:00Z",
        result: {
          title: "Restrict template names to the registered allowlist",
          verdict: "Security hardening",
          confidence: "high",
          summary: "Defensive restriction without an established exploit",
          before_after: "Free-form names are now restricted",
          affected_behavior: "Template selection",
          evidence: [],
        },
        artifacts: [
          {
            id: "hardening-report",
            path: "report.md",
            size: 100,
            sha256: "a".repeat(64),
          },
        ],
      },
      {
        id: "finding-run",
        job_id: "job-finding",
        created_at: "2026-10-05T00:00:00Z",
        // Carried over from Numen: its confidence is unknown.
        result: {
          title: "Path traversal through template file inclusion",
          verdict: "Vulnerability fix",
          confidence: "unknown",
          numen_confidence: { level: "high" },
          summary: "The parent revision accepts traversal sequences",
          finding_decision: "finding",
          finding_id: "finding-1",
          vulnerable_ref: "f".repeat(40),
          addresses: ["GHSA-abcd-efgh-ijkl"],
        },
        artifacts: [
          {
            id: "finding-report",
            path: "report.md",
            size: 100,
            sha256: "b".repeat(64),
          },
        ],
      },
    ],
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.includes("/artifacts/"))
        return new Response(
          url.includes("hardening")
            ? "# Hardening report"
            : "# Vulnerability report",
        );
      const body =
        url === "/api/commits/alpha-commit"
          ? commit
          : url === "/api/applications/alpha"
            ? applications[0]
            : url.startsWith("/api/jobs/")
              ? {
                  id: url.split("/").at(-1),
                  kind: "commit_analysis",
                  status: "succeeded",
                  progress: {},
                  created_at: "2026-10-06T00:00:00Z",
                  error: null,
                  result: null,
                }
              : { items: [commit], next_cursor: null };
      return new Response(JSON.stringify(body));
    }),
  );
  render(
    <MemoryRouter initialEntries={["/commits/alpha-commit"]}>
      <Routes>
        <Route path="/commits/:id" element={<CommitDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(
    await screen.findByRole("heading", { name: "Hardening report" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("heading", { name: "Vulnerability report" }),
  ).not.toBeInTheDocument();
  const summary = () =>
    screen.getByRole("region", { name: "Analysis summary" });
  expect(within(summary()).getByText("Security hardening")).toBeInTheDocument();
  expect(within(summary()).getByText("High confidence")).toBeInTheDocument();
  expect(within(summary()).queryByText("Finding decision")).toBeNull();
  await userEvent
    .setup()
    .selectOptions(screen.getByLabelText("Analysis run"), "finding-run");
  expect(
    await screen.findByRole("heading", { name: "Vulnerability report" }),
  ).toBeInTheDocument();
  expect(within(summary()).getByText("Vulnerability fix")).toBeInTheDocument();
  expect(within(summary()).getByText("Unknown confidence")).toBeInTheDocument();
  expect(
    within(summary()).getByText("GHSA-abcd-efgh-ijkl"),
  ).toBeInTheDocument();
  expect(
    within(summary()).getByText(/Drafts are not reproduced/),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("link", { name: "View finding artifacts" }),
  ).toHaveAttribute("href", "/findings/finding-1");
  expect(
    screen.getByRole("link", { name: "Download analysis bundle" }),
  ).toHaveAttribute("href", "/api/analyses/finding-run/download");
  expect(screen.getByRole("link", { name: "Commit review" })).toHaveAttribute(
    "href",
    "/reviews?application=alpha",
  );
});

/** An application queue whose decisions change through the batch endpoint. */
function batchFixture() {
  const queue = ["one", "two", "three"].map((name, i) => ({
    ...records[0],
    id: `commit-${name}`,
    revision: String(i + 1).repeat(40),
    message: `Change ${name}`,
    committed_at: `2026-10-0${6 - i}T00:00:00Z`,
    review_decision: name === "two" ? "candidate" : "pending",
    triage_result: null,
  }));
  const batches: { ids: string[]; decision: string }[] = [];
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === "/api/commits/review" && init?.method === "POST") {
      const body = JSON.parse(String(init.body)) as {
        ids: string[];
        decision: string;
      };
      batches.push(body);
      const items = body.ids.map((id) => {
        const commit = queue.find((c) => c.id === id)!;
        const previous = commit.review_decision;
        commit.review_decision = body.decision;
        return { id, previous, review_decision: body.decision };
      });
      return new Response(JSON.stringify({ items }));
    }
    const items = url.includes("/applications")
      ? applications
      : queue.map((c) => ({ ...c }));
    return new Response(JSON.stringify({ items, next_cursor: null }));
  });
  vi.stubGlobal("fetch", fetch);
  return { queue, batches };
}
function renderQueue(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/reviews" element={<Reviews />} />
      </Routes>
    </MemoryRouter>,
  );
}

it("sets one decision on a selected range of revisions and can undo it", async () => {
  const { queue, batches } = batchFixture();
  renderQueue("/reviews?application=alpha&decision=all");
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole("checkbox", { name: "Select Change one" }),
  );
  await user.keyboard("{Shift>}");
  await user.click(
    screen.getByRole("checkbox", { name: "Select Change three" }),
  );
  await user.keyboard("{/Shift}");
  expect(
    screen.getByRole("checkbox", { name: "Select Change two" }),
  ).toBeChecked();
  const actions = screen.getByRole("group", {
    name: "Set review decision for selected revisions",
  });
  expect(
    within(actions).getByRole("button", { name: "Dismiss" }),
  ).toBeEnabled();
  await user.click(within(actions).getByRole("button", { name: "Dismiss" }));
  expect(await screen.findByText("3 revisions dismissed.")).toBeInTheDocument();
  expect(batches).toEqual([
    {
      ids: ["commit-one", "commit-two", "commit-three"],
      decision: "dismissed",
    },
  ]);
  expect(queue.map((c) => c.review_decision)).toEqual([
    "dismissed",
    "dismissed",
    "dismissed",
  ]);
  await user.click(screen.getByRole("button", { name: "Undo" }));
  expect(
    await screen.findByText("Restored 3 revisions to the previous decision."),
  ).toBeInTheDocument();
  expect(queue.map((c) => c.review_decision)).toEqual([
    "pending",
    "candidate",
    "pending",
  ]);
});

it("selects every matching revision but never changes a hidden one", async () => {
  const { batches } = batchFixture();
  renderQueue("/reviews?application=alpha&decision=pending");
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole("checkbox", { name: "Select all shown revisions" }),
  );
  expect(screen.getByText("selected").parentElement).toHaveTextContent(
    "2 selected",
  );
  const actions = screen.getByRole("group", {
    name: "Set review decision for selected revisions",
  });
  expect(
    within(actions).getByRole("button", { name: "Leave pending" }),
  ).toBeDisabled();
  // Changing the view drops the selection instead of acting on hidden rows.
  await user.click(screen.getByRole("button", { name: /^All/ }));
  expect(screen.queryByText("selected")).not.toBeInTheDocument();
  expect(
    screen.getByRole("checkbox", { name: "Select Change one" }),
  ).not.toBeChecked();
  expect(batches).toEqual([]);
});

it("shows findings ready to confirm and confirms them from the queue", async () => {
  const { queue, batches } = batchFixture();
  Object.assign(queue[0], {
    review_decision: "candidate",
    findings: [
      {
        id: "finding-1",
        title: "Path traversal",
        status: "open",
        source: "commit",
        application_id: "alpha",
        application_name: "Customer portal",
        relation: "source",
      },
    ],
  });
  renderQueue("/reviews?application=alpha");
  const user = userEvent.setup();
  const row = (
    await screen.findByRole("checkbox", { name: "Select Change one" })
  ).closest("tr")!;
  expect(within(row).getByText("Finding ready")).toBeInTheDocument();
  expect(
    within(row).getByRole("link", {
      name: "Open finding · Customer portal",
    }),
  ).toHaveAttribute("href", "/findings/finding-1");
  await user.click(within(row).getByRole("checkbox"));
  await user.click(screen.getByRole("button", { name: "Confirm revision" }));
  expect(await screen.findByText("1 revision confirmed.")).toBeInTheDocument();
  expect(batches).toEqual([{ ids: ["commit-one"], decision: "confirmed" }]);
  await user.click(screen.getByRole("button", { name: /^Confirmed/ }));
  expect(
    await screen.findByRole("checkbox", { name: "Select Change one" }),
  ).toBeInTheDocument();
});

it("prompts to confirm an analysed finding and to record a missing one", async () => {
  const reviewed: string[] = [];
  let commit = {
    ...records[0],
    findings: [
      {
        id: "finding-1",
        title: "Path traversal",
        status: "open",
        source: "commit",
        application_id: "alpha",
        application_name: "Customer portal",
        relation: "source",
      },
    ],
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/commits/alpha-commit/review") {
        const { decision } = JSON.parse(String(init?.body)) as {
          decision: string;
        };
        reviewed.push(decision);
        commit = { ...commit, review_decision: decision, findings: [] };
        return new Response(JSON.stringify(commit));
      }
      const body =
        url === "/api/commits/alpha-commit"
          ? commit
          : url === "/api/applications/alpha"
            ? applications[0]
            : { items: [commit], next_cursor: null };
      return new Response(JSON.stringify(body));
    }),
  );
  render(
    <MemoryRouter initialEntries={["/commits/alpha-commit"]}>
      <Routes>
        <Route path="/commits/:id" element={<CommitDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  const user = userEvent.setup();
  const prompt = (await screen.findByText("Analysis opened a Finding"))
    .parentElement!.parentElement!;
  expect(
    within(prompt).getByRole("link", { name: "Review finding" }),
  ).toHaveAttribute("href", "/findings/finding-1");
  await user.click(
    within(prompt).getByRole("button", { name: "Confirm revision" }),
  );
  expect(reviewed).toEqual(["confirmed"]);
  // Confirmed without a recorded finding: offer the prefilled form.
  const create = await screen.findByRole("link", { name: "Create finding" });
  const href = new URL(create.getAttribute("href")!, "https://numen.test");
  expect(href.pathname).toBe("/findings/new");
  expect(Object.fromEntries(href.searchParams)).toEqual({
    application_id: "alpha",
    source_commit_id: "alpha-commit",
    title: "Potential path traversal through template selection",
  });
});

it("links a Verdict to the Findings it opened and was linked to", async () => {
  const findings = [
    {
      id: "shop-finding",
      title: "Path traversal",
      status: "open",
      source: "commit",
      application_id: "alpha",
      application_name: "Shop",
      relation: "source",
    },
    {
      id: "blog-finding",
      title: "Stored XSS",
      status: "confirmed",
      source: "commit",
      application_id: "beta",
      application_name: "Blog",
      relation: "linked",
    },
  ];
  const expectLinks = (scope: HTMLElement) => {
    expect(
      within(scope).getByRole("link", { name: "Open finding · Shop" }),
    ).toHaveAttribute("href", "/findings/shop-finding");
    expect(
      within(scope).getByRole("link", {
        name: "Linked: Confirmed finding · Blog",
      }),
    ).toHaveAttribute("href", "/findings/blog-finding");
  };
  const commit = { ...records[0], findings };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const body =
        url === "/api/commits/alpha-commit"
          ? commit
          : url === "/api/applications/alpha"
            ? applications[0]
            : { items: [commit], next_cursor: null };
      return new Response(JSON.stringify(body));
    }),
  );
  const { unmount } = render(
    <MemoryRouter initialEntries={["/commits/alpha-commit"]}>
      <Routes>
        <Route path="/commits/:id" element={<CommitDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  const verdict = (
    await screen.findByText("Verdict", { selector: "dt" })
  ).closest("div")!;
  const row = verdict.nextElementSibling as HTMLElement;
  expect(row).toHaveTextContent(/^Finding/);
  expectLinks(row);
  unmount();
  const { queue } = batchFixture();
  Object.assign(queue[0], { review_decision: "candidate", findings });
  renderQueue("/reviews?application=alpha");
  expectLinks(
    (
      await screen.findByRole("checkbox", { name: "Select Change one" })
    ).closest("tr")!,
  );
});

it("queues a detailed analysis for each selected revision and reports skipped ones", async () => {
  const profile = {
    agent: "codex",
    connection_id: "account",
    model_id: "fixture-model",
    reasoning_effort: "high",
  };
  const { queue } = batchFixture();
  const submitted: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/commits/analyses" && init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { ids: string[] };
        submitted.push(body);
        // The second revision already has an analysis running.
        const items = body.ids.map((id, i) =>
          i === 1
            ? { id, job_id: null, skipped: "analysis_active" }
            : { id, job_id: `job-${id}`, skipped: null },
        );
        return new Response(JSON.stringify({ items }), { status: 202 });
      }
      const body =
        url === "/api/accounts"
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
                monitor_interval_seconds: 604800,
                default_profiles: { commit_analysis: profile },
                webhook_enabled: false,
                webhook_configured: false,
              }
            : {
                items: url.includes("/applications") ? applications : queue,
                next_cursor: null,
              };
      return new Response(JSON.stringify(body));
    }),
  );
  renderQueue("/reviews?application=alpha&decision=all");
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole("checkbox", { name: "Select all shown revisions" }),
  );
  await user.click(screen.getByRole("button", { name: "Analyze" }));
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByText("3 revisions")).toBeInTheDocument();
  expect(within(dialog).getByText("Change one")).toBeInTheDocument();
  await user.click(
    await within(dialog).findByRole("button", { name: "Start 3 analyses" }),
  );
  expect(
    await screen.findByText("Queued 2 analyses · 1 already being analyzed."),
  ).toBeInTheDocument();
  expect(submitted).toEqual([
    { profile, ids: ["commit-one", "commit-two", "commit-three"] },
  ]);
  expect(screen.getByRole("link", { name: "View jobs" })).toHaveAttribute(
    "href",
    "/jobs?kind=commit_analysis",
  );
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(
    screen.getByRole("checkbox", { name: "Select Change one" }),
  ).not.toBeChecked();
});

/** Serves one application queue and the page of each commit in it. */
function serveQueue(queue: Record<string, unknown>[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const commit = queue.find((c) => url === `/api/commits/${String(c.id)}`);
      const body =
        commit ||
        (url === "/api/applications/alpha"
          ? applications[0]
          : {
              items: url.includes("/applications") ? applications : queue,
              next_cursor: null,
            });
      return new Response(JSON.stringify(body));
    }),
  );
}
function change(name: string, fields: Record<string, unknown> = {}) {
  return {
    ...records[0],
    id: `commit-${name}`,
    message: `Change ${name}`,
    triage_result: null,
    review_decision: "pending",
    ...fields,
  };
}
function row(name: string) {
  return screen
    .getByRole("checkbox", { name: `Select Change ${name}` })
    .closest("tr")!;
}

it("shows each Verdict with its confidence, migrated ones as unknown, and filters by Verdict", async () => {
  serveQueue([
    change("fix", {
      verdict: "Vulnerability fix",
      analyses: [
        {
          id: "migrated",
          result: {
            verdict: "Vulnerability fix",
            confidence: "unknown",
            numen_confidence: { level: "high" },
          },
        },
      ],
    }),
    change("noise", {
      verdict: "Unrelated",
      analyses: [
        { id: "a2", result: { verdict: "Unrelated", confidence: "high" } },
      ],
    }),
    change("new"),
  ]);
  renderQueue("/reviews?application=alpha&decision=all");
  await screen.findByRole("checkbox", { name: "Select Change fix" });
  expect(within(row("fix")).getByText("Vulnerability fix")).toBeInTheDocument();
  expect(
    within(row("fix")).getByText("Unknown confidence"),
  ).toBeInTheDocument();
  expect(within(row("noise")).getByText("Unrelated")).toBeInTheDocument();
  expect(within(row("noise")).getByText("High confidence")).toBeInTheDocument();
  expect(within(row("new")).getByText("Not analysed")).toBeInTheDocument();
  const user = userEvent.setup();
  await user.selectOptions(screen.getByLabelText("Verdict"), "Unrelated");
  expect(row("noise")).toBeInTheDocument();
  expect(
    screen.queryByRole("checkbox", { name: "Select Change fix" }),
  ).not.toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText("Verdict"), "none");
  expect(row("new")).toBeInTheDocument();
  expect(
    screen.queryByRole("checkbox", { name: "Select Change noise" }),
  ).not.toBeInTheDocument();
});

it("filters to the Review queue: Insufficient context Verdicts still pending", async () => {
  serveQueue([
    change("open", { verdict: "Insufficient context" }),
    change("judged", {
      verdict: "Insufficient context",
      review_decision: "dismissed",
    }),
    change("fix", { verdict: "Vulnerability fix" }),
  ]);
  renderQueue("/reviews?application=alpha");
  const user = userEvent.setup();
  await user.selectOptions(await screen.findByLabelText("Show"), "review");
  expect(
    await screen.findByRole("checkbox", { name: "Select Change open" }),
  ).toBeInTheDocument();
  for (const name of ["judged", "fix"])
    expect(
      screen.queryByRole("checkbox", { name: `Select Change ${name}` }),
    ).not.toBeInTheDocument();
});

it("lists a Pre-filter hit that Triage rejected with both results", async () => {
  serveQueue([
    change("ci", {
      triage_result: {
        decision: "unrelated",
        title: "Bump the release workflow",
        reason: "Version bump only",
      },
      review_decision: "dismissed",
      prefilter: [
        { rule: "ci_workflow", paths: [".github/workflows/release.yml"] },
      ],
    }),
  ]);
  render(
    <MemoryRouter initialEntries={["/reviews?application=alpha&decision=all"]}>
      <Routes>
        <Route path="/reviews" element={<Reviews />} />
        <Route path="/commits/:id" element={<CommitDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  const link = await screen.findByRole("link", {
    name: "Bump the release workflow",
  });
  const cells = within(link.closest("tr")!);
  expect(cells.getByText("Unrelated")).toBeInTheDocument();
  expect(
    within(cells.getByRole("list", { name: "Pre-filter flags" })).getByText(
      "CI workflow",
    ),
  ).toBeInTheDocument();
  const user = userEvent.setup();
  await user.click(link);
  await user.click(await screen.findByRole("tab", { name: "Triage" }));
  const pre = screen.getByRole("list", { name: "Pre-filter rules" });
  expect(within(pre).getByText("CI workflow")).toBeInTheDocument();
  expect(
    within(pre).getByText(".github/workflows/release.yml"),
  ).toBeInTheDocument();
});

it("shows a failed or blocked Triage with its reason, never as unrelated", async () => {
  serveQueue([
    change("failed", {
      triage_status: "failed",
      triage_result: {
        error: "invalid_agent_output",
        reason: "The reply did not match the Triage schema",
        attempt: 1,
        retry_job_id: "job-retry",
      },
    }),
    change("blocked", {
      triage_status: "blocked",
      triage_result: {
        error: "api_key_required",
        reason:
          "Automated runs use only Provider accounts that hold an API key",
      },
    }),
  ]);
  renderQueue("/reviews?application=alpha&decision=all");
  await screen.findByRole("checkbox", { name: "Select Change failed" });
  expect(within(row("failed")).getByText("Triage failed")).toBeInTheDocument();
  expect(
    within(row("failed")).getByText(
      "The reply did not match the Triage schema",
    ),
  ).toBeInTheDocument();
  expect(
    within(row("blocked")).getByText("Triage blocked"),
  ).toBeInTheDocument();
  expect(
    within(row("blocked")).getByText(
      "Automated runs use only Provider accounts that hold an API key",
    ),
  ).toBeInTheDocument();
  for (const name of ["failed", "blocked"])
    expect(within(row(name)).queryByText(/unrelated/i)).not.toBeInTheDocument();
});

it("shows an Analysis that is queued, waits for a cap, timed out, or was blocked", async () => {
  serveQueue([
    change("queued", {
      analysis_state: { status: "queued", job_id: "job-queued" },
    }),
    change("waiting", {
      analysis_state: {
        status: "waiting_for_cap",
        since: "2026-10-06T10:00:00Z",
        cap: "account",
      },
    }),
    change("late", {
      verdict: "Security hardening",
      analyses: [
        {
          id: "old",
          result: { verdict: "Security hardening", confidence: "low" },
        },
      ],
      analysis_state: {
        status: "timed_out",
        job_id: "job-late",
        error: { code: "timeout", message: "Workload deadline exceeded" },
      },
    }),
    change("blocked", {
      analysis_state: {
        status: "blocked",
        error: {
          code: "api_key_required",
          message:
            "Automated runs use only Provider accounts that hold an API key",
        },
      },
    }),
  ]);
  renderQueue("/reviews?application=alpha&decision=all");
  await screen.findByRole("checkbox", { name: "Select Change queued" });
  expect(within(row("queued")).getByText("Queued")).toBeInTheDocument();
  expect(
    within(row("waiting")).getByText("Waiting for cap"),
  ).toBeInTheDocument();
  expect(
    within(row("waiting")).getByText("Daily Provider account cap reached"),
  ).toBeInTheDocument();
  // An expired deadline keeps the earlier Verdict and never reads as Unrelated.
  expect(
    within(row("late")).getByText("Timed out after 30 minutes"),
  ).toBeInTheDocument();
  expect(
    within(row("late")).getByText("Security hardening"),
  ).toBeInTheDocument();
  expect(within(row("blocked")).getByText("Blocked")).toBeInTheDocument();
  expect(
    within(row("blocked")).getByText(
      "Automated runs use only Provider accounts that hold an API key",
    ),
  ).toBeInTheDocument();
});
