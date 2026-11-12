import { render, screen } from "@testing-library/react";
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
  kind: "0day",
  cve_id: null,
  title: "Stored XSS in timezone settings",
  status: "open",
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

it("preserves structured version evidence when editing the operator status", async () => {
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
  await user.selectOptions(
    await screen.findByLabelText("Operator status"),
    "fixed",
  );
  expect(screen.getByLabelText("Affected versions (one per line)")).toHaveValue(
    "Example CMS <= 9.5.3",
  );
  await user.click(screen.getByRole("button", { name: "Save finding" }));
  expect(
    await screen.findByRole("heading", { name: "Saved finding" }),
  ).toBeInTheDocument();
  expect(saved?.status).toBe("fixed");
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
