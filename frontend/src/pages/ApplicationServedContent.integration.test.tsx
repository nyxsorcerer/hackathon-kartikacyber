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

const SHOP = "https://shop.example.test/";
const application = {
  id: "app-1",
  asset_name: "Toko Batik Sari",
  asset_url: SHOP,
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
const at = "2026-11-13T09:00:00Z";
const fetched = (id: string, fingerprint: string) => ({
  id,
  status: "fetched",
  fingerprint,
  created_at: at,
  error: null,
  resources: [],
});
const judol: Record<string, { added: string[]; removed: string[] }> = {
  link_hosts: { added: ["slot-gacor.test"], removed: [] },
  words: { added: ["gacor", "slot"], removed: ["batik"] },
};
// GET /applications/{id}/watched-pages: each Watched page with each user agent's latest fetch,
// its Baseline, how they compare, their diff and the served-content change (A10).
function watchedPages() {
  return {
    items: [
      {
        id: "page-home",
        url: SHOP,
        homepage: true,
        removed_at: null,
        created_at: at,
        user_agents: [
          {
            user_agent: "browser",
            latest: fetched("fetch-b2", "a".repeat(64)),
            baseline: {
              fetch_id: "fetch-b1",
              fingerprint: "a".repeat(64),
              accepted_at: at,
            },
            state: "matches",
            diff: {},
            change: null,
            accept_allowed: false,
          },
          {
            user_agent: "googlebot",
            latest: fetched("fetch-g2", "c".repeat(64)),
            baseline: {
              fetch_id: "fetch-g1",
              fingerprint: "b".repeat(64),
              accepted_at: at,
            },
            state: "changed",
            diff: judol,
            change: {
              id: "change-1",
              fingerprint: "c".repeat(64),
              fetch_id: "fetch-g2",
              previous_fetch_id: "fetch-g1",
              baseline_fetch_id: "fetch-g1",
              diff: judol,
              triage_status: "completed",
              triage_result: { decision: "security_candidate" },
              review_decision: "candidate",
              verdict: "Malicious change",
              analysis_state: { status: "completed", analysis_id: "a-1" },
              created_at: at,
              finding_id: "finding-1",
            },
            accept_allowed: false,
          },
        ],
      },
      {
        id: "page-verify",
        url: `${SHOP}verify`,
        homepage: false,
        removed_at: null,
        created_at: at,
        user_agents: [
          {
            user_agent: "browser",
            latest: fetched("fetch-v1", "d".repeat(64)),
            baseline: null,
            state: "awaiting_baseline",
            diff: null,
            change: null,
            accept_allowed: true,
          },
          {
            user_agent: "googlebot",
            latest: {
              ...fetched("fetch-v2", ""),
              status: "failed",
              fingerprint: null,
              error: { status: 503, error: null },
            },
            baseline: null,
            state: "failed",
            diff: null,
            change: null,
            accept_allowed: false,
          },
        ],
      },
    ],
  };
}
type Call = { method: string; url: string; body?: unknown; csrf?: string };
function serve(pages: unknown = watchedPages()) {
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
      if (url.endsWith("/served-content-checks") || url.endsWith("/analyses"))
        return new Response(
          JSON.stringify({ job_id: "job-1", status_url: "/api/jobs/job-1" }),
          { status: 202 },
        );
      if (method !== "GET")
        return new Response(
          JSON.stringify(watchedPages().items[1]),
          method === "POST" ? { status: 201 } : {},
        );
      const body =
        url === "/api/applications/app-1"
          ? application
          : url === "/api/applications/app-1/watched-pages"
            ? pages
            : { items: [], next_cursor: null };
      return new Response(JSON.stringify(body));
    }),
  );
  return calls;
}
function open() {
  return render(
    <MemoryRouter initialEntries={["/applications/app-1?tab=served"]}>
      <Routes>
        <Route path="/applications/:id" element={<ApplicationDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}
async function rows() {
  open();
  const region = await screen.findByRole("region", { name: "Watched pages" });
  return within(region).getAllByRole("row").slice(1);
}

it("lists each Watched page with its fingerprints and Baseline per user agent", async () => {
  serve();
  const [homeBrowser, homeGooglebot, verifyBrowser, verifyGooglebot] =
    await rows();
  // The homepage, as text and never a link, and its browser fetch matching its Baseline.
  expect(homeBrowser).toHaveTextContent(SHOP);
  expect(homeBrowser).toHaveTextContent("Homepage");
  expect(within(homeBrowser).queryByRole("link")).toBeNull();
  expect(homeBrowser).toHaveTextContent("Browser");
  expect(homeBrowser).toHaveTextContent("aaaaaaaaaaaa");
  expect(homeBrowser).toHaveTextContent("Matches the Baseline");
  // AC-A10: the difference is attributed to the user agent that saw it.
  expect(homeGooglebot).toHaveTextContent("Googlebot");
  expect(homeGooglebot).toHaveTextContent("cccccccccccc");
  expect(homeGooglebot).toHaveTextContent("Baseline bbbbbbbbbbbb");
  expect(homeGooglebot).toHaveTextContent("Changed");
  expect(homeGooglebot).toHaveTextContent("Link hosts addedslot-gacor.test");
  expect(homeGooglebot).toHaveTextContent("Words addedgacorslot");
  expect(homeGooglebot).toHaveTextContent("Words removedbatik");
  expect(homeBrowser).not.toHaveTextContent("slot-gacor.test");
  // The change's Triage, Analysis, Verdict and Review queue state, and its Finding.
  expect(homeGooglebot).toHaveTextContent("TriageSecurity candidate");
  expect(homeGooglebot).toHaveTextContent("AnalysisCompleted");
  expect(homeGooglebot).toHaveTextContent("VerdictMalicious change");
  expect(homeGooglebot).toHaveTextContent("Review queueNot queued");
  expect(
    within(homeGooglebot).getByRole("link", { name: "Open Finding" }),
  ).toHaveAttribute("href", "/findings/finding-1");
  // A changed fingerprint without a Security hardening or Unrelated Verdict cannot be accepted.
  for (const row of [homeBrowser, homeGooglebot, verifyGooglebot])
    expect(
      within(row).queryByRole("button", { name: "Accept Baseline" }),
    ).toBeNull();
  expect(verifyBrowser).toHaveTextContent(`${SHOP}verify`);
  expect(verifyBrowser).toHaveTextContent("No Baseline yet");
  expect(
    within(verifyBrowser).getByRole("button", { name: "Accept Baseline" }),
  ).toBeEnabled();
  expect(verifyGooglebot).toHaveTextContent("Fetch failed");
  expect(verifyGooglebot).toHaveTextContent("HTTP 503");
});

it("Accept Baseline posts the fetch with the CSRF token", async () => {
  const calls = serve();
  setCsrfToken("fixture-csrf");
  const verifyBrowser = (await rows())[2];
  await userEvent
    .setup()
    .click(
      within(verifyBrowser).getByRole("button", { name: "Accept Baseline" }),
    );
  // Accepting a Baseline is not an Approval: no password, only the session's CSRF token.
  await vi.waitFor(() =>
    expect(calls).toContainEqual({
      method: "POST",
      url: "/api/applications/app-1/watched-pages/page-verify/baselines",
      body: { fetch_id: "fetch-v1" },
      csrf: "fixture-csrf",
    }),
  );
});

it("Check now queues a Served-content check", async () => {
  const calls = serve();
  await rows();
  // The Asset's Check now, beside the Application's own one for its repositories.
  const served = screen.getByRole("region", { name: "Served content" });
  await userEvent
    .setup()
    .click(within(served).getByRole("button", { name: "Check now" }));
  await vi.waitFor(() =>
    expect(calls.map(({ method, url }) => ({ method, url }))).toContainEqual({
      method: "POST",
      url: "/api/applications/app-1/served-content-checks",
    }),
  );
});

it("adds a page and cannot remove the homepage", async () => {
  const calls = serve();
  const [homeBrowser, , verifyBrowser] = await rows();
  const user = userEvent.setup();
  expect(within(homeBrowser).queryByRole("button", { name: "Remove" })).toBeNull();
  await user.click(within(verifyBrowser).getByRole("button", { name: "Remove" }));
  await user.click(
    within(verifyBrowser).getByRole("button", { name: "Confirm remove" }),
  );
  await user.type(screen.getByLabelText("Page URL"), `${SHOP}cart`);
  await user.click(screen.getByRole("button", { name: "Add Watched page" }));
  await vi.waitFor(() =>
    expect(calls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          method: "DELETE",
          url: "/api/applications/app-1/watched-pages/page-verify",
        }),
        expect.objectContaining({
          method: "POST",
          url: "/api/applications/app-1/watched-pages",
          body: { url: `${SHOP}cart` },
        }),
      ]),
    ),
  );
});

it("judges a change in the Review queue and starts its Analysis", async () => {
  const pages = watchedPages();
  Object.assign(pages.items[0].user_agents[1].change!, {
    verdict: "Insufficient context",
    review_decision: "pending",
    finding_id: null,
  });
  const calls = serve(pages);
  const homeGooglebot = (await rows())[1];
  expect(homeGooglebot).toHaveTextContent("Review queueWaiting for your review");
  const user = userEvent.setup();
  await user.click(within(homeGooglebot).getByRole("button", { name: "Dismiss" }));
  await user.click(
    within(homeGooglebot).getByRole("button", { name: "Run Analysis" }),
  );
  await vi.waitFor(() =>
    expect(calls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          method: "POST",
          url: "/api/served-changes/change-1/review",
          body: { decision: "dismissed" },
        }),
        expect.objectContaining({
          method: "POST",
          url: "/api/served-changes/change-1/analyses",
        }),
      ]),
    ),
  );
});

it("renders fetched values as text", async () => {
  const markup = "<script>alert(1)</script>";
  const pages = watchedPages();
  const googlebot = pages.items[0].user_agents[1];
  googlebot.diff = {
    words: { added: [markup], removed: [] },
    links: { added: [`https://slot-gacor.test/${markup}`], removed: [] },
  };
  pages.items[1].url = `${SHOP}${markup}`;
  serve(pages);
  const { container } = open();
  const region = await screen.findByRole("region", { name: "Watched pages" });
  expect(region).toHaveTextContent(`Words added${markup}`);
  expect(region).toHaveTextContent(`Links addedhttps://slot-gacor.test/${markup}`);
  expect(region).toHaveTextContent(`${SHOP}${markup}`);
  expect(container.querySelector("script, iframe")).toBeNull();
});
