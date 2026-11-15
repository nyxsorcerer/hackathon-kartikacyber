import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { ApplicationDetail } from "./ApplicationDetail";

afterEach(() => vi.unstubAllGlobals());

type Link = Record<string, unknown>;
const link = (id: string, fields: Link): Link => ({
  repository_id: id,
  role: "upstream",
  enabled: true,
  removed_at: null,
  locked_version: null,
  locked_version_source: null,
  release_branch: null,
  release_branch_status: null,
  packages: [],
  source_kind: "github",
  source_url: `https://github.com/example/${id}`,
  plugin_slug: null,
  source_ref: null,
  source_path: null,
  cursor: "c".repeat(40),
  baseline_revision: "c".repeat(40),
  last_check_at: "2026-11-12T10:00:00Z",
  last_error: null,
  ...fields,
});
const application = (repositories: Link[], extra: Link = {}) => ({
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
  repositories,
  unresolved_dependencies: [],
  version: null,
  latest_version_check: null,
  config: {
    triage_mode: "disabled",
    profiles: {},
    cve_selectors: [],
    cve_versions: [],
  },
  ...extra,
});
type Call = { method: string; url: string; body: unknown };
/** A fake API holding one Application; `reply` answers mutations and may change `state`. */
function serve(
  state: ReturnType<typeof application>,
  reply: (call: Call) => Response | undefined = () => undefined,
) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method || "GET";
      const call = {
        method,
        url,
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      };
      if (method === "GET")
        return new Response(
          JSON.stringify(
            url === "/api/applications/app-1"
              ? state
              : { items: [], next_cursor: null },
          ),
        );
      calls.push(call);
      const custom = reply(call);
      if (custom) return custom;
      const match = url.match(/\/repositories\/([^/]+)$/);
      const target = state.repositories.find(
        (r) => r.repository_id === match?.[1],
      );
      if (target && method === "PATCH") {
        Object.assign(target, call.body);
        if ("locked_version" in (call.body as object))
          target.locked_version_source = target.locked_version
            ? "operator"
            : null;
        return new Response(JSON.stringify(target));
      }
      if (target && method === "DELETE") {
        target.removed_at = "2026-11-13T09:00:00Z";
        return new Response(JSON.stringify(target));
      }
      throw new Error(`Unexpected ${method} ${url}`);
    }),
  );
  return calls;
}
function open() {
  return render(
    <MemoryRouter initialEntries={["/applications/app-1?tab=repositories"]}>
      <Routes>
        <Route path="/applications/:id" element={<ApplicationDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });

it("adds, shows and removes the Own repository", async () => {
  const state = application([]);
  let posts = 0;
  const calls = serve(state, ({ method, url, body }) => {
    if (method !== "POST" || url !== "/api/applications/app-1/repositories")
      return;
    posts += 1;
    if (posts === 1)
      return json(
        {
          code: "validation_error",
          message: "Check the supplied fields",
          fields: {
            "": "Value error, GitHub source requires https://github.com/owner/repository",
          },
        },
        422,
      );
    if (posts === 2)
      return json(
        {
          code: "own_repository_exists",
          message:
            "This Application already has an Own repository; remove it first",
        },
        409,
      );
    const own = link("portal", {
      role: "own",
      source_url: "https://github.com/example/portal",
      last_error: { code: "github_token_required", message: "Add a token" },
    });
    state.repositories.push(own);
    void body;
    return json(own, 201);
  });
  const user = userEvent.setup();
  open();
  const field = await screen.findByLabelText("Own repository URL");
  expect(
    screen.getByText(/worked out from its manifests and lockfiles/),
  ).toBeInTheDocument();
  await user.type(field, "https://gitlab.com/example/portal");
  await user.click(screen.getByRole("button", { name: "Add Own repository" }));
  expect(await screen.findByText(/GitHub source requires/)).toBeInTheDocument();
  await user.clear(field);
  await user.type(field, "https://github.com/Example/Portal");
  await user.click(screen.getByRole("button", { name: "Add Own repository" }));
  expect(
    await screen.findByText(/already has an Own repository/),
  ).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Add Own repository" }));
  const panel = (
    await screen.findByRole("heading", { name: "Own repository" })
  ).closest("section")!;
  expect(await within(panel).findByText("example/portal")).toBeInTheDocument();
  expect(within(panel).getByText("Add a token.")).toBeInTheDocument();
  expect(calls[2]).toEqual({
    method: "POST",
    url: "/api/applications/app-1/repositories",
    body: {
      role: "own",
      source_kind: "github",
      source_url: "https://github.com/Example/Portal",
    },
  });
  await user.click(within(panel).getByRole("button", { name: "Remove" }));
  await user.click(
    within(panel).getByRole("button", { name: "Confirm remove" }),
  );
  expect(
    await screen.findByLabelText("Own repository URL"),
  ).toBeInTheDocument();
  expect(calls[3]).toMatchObject({
    method: "DELETE",
    url: "/api/applications/app-1/repositories/portal",
  });
});

const upstreams = () => [
  link("removed", {
    removed_at: "2026-11-10T00:00:00Z",
    packages: ["npm:left"],
  }),
  link("react", {
    source_url: "https://github.com/facebook/react",
    packages: ["npm:react", "npm:react-dom"],
    locked_version: "18.2.0",
    locked_version_source: "manifest",
    release_branch: "18.2",
    release_branch_status: "matched",
  }),
  link("off", { enabled: false }),
  link("broken", {
    locked_version: "2.0.0",
    locked_version_source: "operator",
    release_branch_status: "unknown",
    last_error: { message: "GitHub answered 500" },
  }),
  link("akismet", {
    source_kind: "wordpress",
    source_url: "https://plugins.svn.wordpress.org/akismet",
    plugin_slug: "akismet",
    locked_version: "5.3",
    locked_version_source: "deployed",
  }),
];
const row = (name: string) => screen.getByRole("link", { name }).closest("tr")!;

it("shows each Upstream repository's state and edits it", async () => {
  const state = application(upstreams());
  const calls = serve(state);
  const user = userEvent.setup();
  const view = open();
  await screen.findByRole("heading", { name: "Upstream repositories" });
  const rows = screen.getAllByRole("row").slice(1);
  expect(rows).toHaveLength(5);
  // Removed links come last.
  expect(rows[4]).toHaveTextContent("example/removed");
  expect(rows[4]).toHaveClass("dimmed");
  expect(within(rows[4]).getByText("Removed")).toBeInTheDocument();
  expect(within(rows[4]).getByRole("checkbox")).toBeDisabled();
  const react = row("facebook/react");
  expect(within(react).getByText("Watching")).toBeInTheDocument();
  expect(within(react).getByText("Release branch 18.2")).toBeInTheDocument();
  expect(within(react).getByText("npm:react-dom")).toBeInTheDocument();
  expect(within(react).getByText("Manifest")).toBeInTheDocument();
  expect(within(row("example/off")).getByText("Off")).toBeInTheDocument();
  const broken = row("example/broken");
  expect(within(broken).getByText("Error")).toBeInTheDocument();
  expect(within(broken).getByText("GitHub answered 500.")).toBeInTheDocument();
  expect(
    within(broken).getByText("release branch unknown"),
  ).toBeInTheDocument();
  expect(within(broken).getByText("Operator")).toBeInTheDocument();
  expect(
    within(row("WordPress · akismet")).getByText("Deployed"),
  ).toBeInTheDocument();

  await user.click(within(react).getByRole("checkbox", { name: "Watch" }));
  expect(calls[0]).toEqual({
    method: "PATCH",
    url: "/api/applications/app-1/repositories/react",
    body: { enabled: false },
  });
  const locked = within(react).getByLabelText("Locked version");
  await user.clear(locked);
  await user.type(locked, "18.3.0");
  await user.click(within(react).getByRole("button", { name: "Save" }));
  expect(calls[1]).toEqual({
    method: "PATCH",
    url: "/api/applications/app-1/repositories/react",
    body: { locked_version: "18.3.0" },
  });
  await user.clear(within(broken).getByLabelText("Locked version"));
  await user.click(within(broken).getByRole("button", { name: "Save" }));
  expect(calls[2]).toEqual({
    method: "PATCH",
    url: "/api/applications/app-1/repositories/broken",
    body: { locked_version: null },
  });

  // A saved Application reopens with its repositories and their states.
  view.unmount();
  open();
  await screen.findByRole("heading", { name: "Upstream repositories" });
  const reopened = row("facebook/react");
  expect(within(reopened).getByText("Off")).toBeInTheDocument();
  expect(within(reopened).getByLabelText("Locked version")).toHaveValue(
    "18.3.0",
  );
  expect(within(reopened).getByText("Operator")).toBeInTheDocument();
  expect(
    within(row("example/broken")).getByLabelText("Locked version"),
  ).toHaveValue("");
  expect(screen.getByRole("tab", { name: /Repositories/ })).toHaveTextContent(
    "4",
  );
});

it("lists unresolved packages", async () => {
  serve(
    application([], {
      unresolved_dependencies: [
        {
          ecosystem: "npm",
          name: "left-pad",
          version: "1.3.0",
          reason: "Source repository is not on GitHub: https://gitlab.com/x/y",
        },
      ],
    }),
  );
  open();
  const heading = await screen.findByRole("heading", {
    name: "Unresolved packages",
  });
  const panel = within(heading.closest("section")!);
  expect(panel.getByText("left-pad")).toBeInTheDocument();
  expect(panel.getByText("1.3.0")).toBeInTheDocument();
  expect(
    panel.getByText(/Source repository is not on GitHub/),
  ).toBeInTheDocument();
});

it("requests a Backfill of the last N commits", async () => {
  const calls = serve(application(upstreams()), ({ method, url }) =>
    method === "POST" && url.endsWith("/backfills")
      ? json({ job_id: "job-1", status_url: "/api/jobs/job-1" }, 202)
      : undefined,
  );
  const notices: string[] = [];
  const listener = (e: Event) =>
    notices.push((e as CustomEvent<{ message: string }>).detail.message);
  window.addEventListener("numen:notice", listener);
  const user = userEvent.setup();
  open();
  await screen.findByRole("heading", { name: "Upstream repositories" });
  await user.click(
    within(row("facebook/react")).getByRole("button", { name: "Backfill" }),
  );
  const dialog = await screen.findByRole("dialog");
  expect(dialog).toHaveTextContent(/older than the Baseline/);
  const count = within(dialog).getByLabelText("Commits to backfill");
  expect(count).toHaveValue(20);
  await user.clear(count);
  await user.type(count, "5");
  await user.click(
    within(dialog).getByRole("button", { name: "Queue Backfill" }),
  );
  expect(calls[0]).toEqual({
    method: "POST",
    url: "/api/applications/app-1/repositories/react/backfills",
    body: { count: 5 },
  });
  await vi.waitFor(() => expect(notices).toContain("Backfill queued"));
  window.removeEventListener("numen:notice", listener);
  expect(
    within(row("example/removed")).getByRole("button", { name: "Backfill" }),
  ).toBeDisabled();
});

it("adds an Upstream repository by hand", async () => {
  const state = application([]);
  const calls = serve(state, ({ method, url, body }) => {
    if (method !== "POST" || !url.endsWith("/repositories")) return;
    const added = link("akismet", {
      source_kind: "wordpress",
      source_url: "https://plugins.svn.wordpress.org/akismet",
      plugin_slug: "akismet",
      locked_version: "5.3",
      locked_version_source: "operator",
      cursor: null,
      baseline_revision: null,
      last_check_at: null,
    });
    state.repositories.push(added);
    void body;
    return json(added, 201);
  });
  const user = userEvent.setup();
  open();
  expect(
    await screen.findByText("No Upstream repositories yet"),
  ).toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText("Kind"), "wordpress");
  await user.type(screen.getByLabelText("Plugin slug"), "akismet");
  await user.type(screen.getByLabelText("Locked version (optional)"), "5.3");
  await user.click(
    screen.getByRole("button", { name: "Add Upstream repository" }),
  );
  expect(calls[0]).toEqual({
    method: "POST",
    url: "/api/applications/app-1/repositories",
    body: {
      role: "upstream",
      source_kind: "wordpress",
      plugin_slug: "akismet",
      locked_version: "5.3",
    },
  });
  const added = await screen.findByRole("link", {
    name: "WordPress · akismet",
  });
  expect(
    within(added.closest("tr")!).getByText("Operator"),
  ).toBeInTheDocument();
  // Not checked yet, so there is no Baseline to backfill from.
  expect(
    within(added.closest("tr")!).getByRole("button", { name: "Backfill" }),
  ).toBeDisabled();
  expect(screen.getByLabelText("Plugin slug")).toHaveValue("");
});

const PATH = `/push/${"a".repeat(32)}`;
const pushPanel = async () =>
  (await screen.findByRole("heading", { name: "Push webhook" })).closest(
    "section",
  )!;
const ownLink = (fields: Link = {}) =>
  link("portal", {
    role: "own",
    source_url: "https://github.com/example/portal",
    ...fields,
  });
const webhook = (fields: Link = {}) => ({
  created_at: "2026-11-14T08:00:00Z",
  last_accepted: null,
  last_refusal: null,
  ...fields,
});

it("sets up the Push webhook and shows its secret once", async () => {
  const own = ownLink();
  const state = application([own, ...upstreams()]);
  const calls = serve(state, ({ method, url }) => {
    if (method !== "POST" || !url.endsWith("/portal/push-webhook")) return;
    own.push_webhook = webhook();
    return json({ path: PATH, secret: "s3cret-shown-once" }, 201);
  });
  const user = userEvent.setup();
  open();
  const panel = within(await pushPanel());
  expect(panel.getByText(/Public tunnel/)).toBeInTheDocument();
  await user.click(
    panel.getByRole("button", { name: "Set up push webhook" }),
  );
  expect(calls[0]).toEqual({
    method: "POST",
    url: "/api/applications/app-1/repositories/portal/push-webhook",
    body: {},
  });
  const dialog = within(await screen.findByRole("dialog"));
  expect(dialog.getByText(/Public tunnel URL followed by/)).toBeInTheDocument();
  expect(dialog.getByText(PATH)).toBeInTheDocument();
  expect(dialog.getByText("application/json")).toBeInTheDocument();
  expect(dialog.getByText("s3cret-shown-once")).toBeInTheDocument();
  expect(dialog.getByText("Just the push event")).toBeInTheDocument();
  expect(dialog.getByText(/shown only now/)).toBeInTheDocument();
  expect(dialog.getByText(/within 15 s/)).toBeInTheDocument();
  await user.click(dialog.getByRole("button", { name: "Done" }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.queryByText("s3cret-shown-once")).not.toBeInTheDocument();
  expect(screen.queryByText(new RegExp(PATH))).not.toBeInTheDocument();
  const on = within(await pushPanel());
  expect(await on.findByRole("button", { name: "Regenerate" })).toBeVisible();
  expect(on.getByRole("button", { name: "Turn off" })).toBeVisible();
  expect(
    on.queryByRole("button", { name: "Set up push webhook" }),
  ).not.toBeInTheDocument();
});

it("regenerates and turns off the Push webhook", async () => {
  const own = ownLink({ push_webhook: webhook() });
  const state = application([own]);
  const calls = serve(state, ({ method, url }) => {
    if (method === "POST" && url.endsWith("/portal/push-webhook/secret"))
      return json({ path: PATH, secret: "new-secret" });
    if (method === "DELETE" && url.endsWith("/portal/push-webhook")) {
      own.push_webhook = null;
      return json(own);
    }
  });
  const user = userEvent.setup();
  open();
  const panel = within(await pushPanel());
  await user.click(panel.getByRole("button", { name: "Regenerate" }));
  expect(calls).toHaveLength(0);
  await user.click(panel.getByRole("button", { name: "Confirm regenerate" }));
  expect(calls[0]).toEqual({
    method: "POST",
    url: "/api/applications/app-1/repositories/portal/push-webhook/secret",
    body: {},
  });
  const dialog = within(await screen.findByRole("dialog"));
  expect(dialog.getByText("new-secret")).toBeInTheDocument();
  await user.click(dialog.getByRole("button", { name: "Close dialog" }));
  expect(screen.queryByText("new-secret")).not.toBeInTheDocument();
  await user.click(panel.getByRole("button", { name: "Turn off" }));
  await user.click(panel.getByRole("button", { name: "Confirm turn off" }));
  expect(calls[1]).toMatchObject({
    method: "DELETE",
    url: "/api/applications/app-1/repositories/portal/push-webhook",
  });
  expect(
    await screen.findByRole("button", { name: "Set up push webhook" }),
  ).toBeInTheDocument();
});

it("shows the last accepted delivery and the last refusal as text", async () => {
  const own = ownLink({
    push_webhook: webhook({
      last_accepted: {
        at: "2026-11-14T09:00:00Z",
        event: "push",
        delivery_id: "<img src=x onerror=alert(1)>",
      },
      last_refusal: { at: "2026-11-14T09:05:00Z", reason: "wrong_signature" },
    }),
  });
  serve(application([own, ...upstreams()]));
  const view = open();
  const panel = await pushPanel();
  expect(
    within(panel).getByText("<img src=x onerror=alert(1)>"),
  ).toBeInTheDocument();
  expect(panel.querySelector("img")).toBeNull();
  expect(within(panel).getByText(/Wrong signature/)).toBeInTheDocument();
  // Upstream repositories stay polled: no push controls on their rows.
  for (const name of ["facebook/react", "WordPress · akismet"])
    expect(
      within(row(name)).queryByRole("button", {
        name: /push webhook|Regenerate|Turn off/,
      }),
    ).not.toBeInTheDocument();
  expect(screen.getAllByRole("heading", { name: "Push webhook" })).toHaveLength(
    1,
  );

  view.unmount();
  own.push_webhook = webhook({
    last_accepted: { at: "2026-11-14T10:00:00Z", event: "ping", delivery_id: "d-2" },
    last_refusal: { at: "2026-11-14T10:05:00Z", reason: "<b>new_code</b>" },
  });
  open();
  const again = await pushPanel();
  const reopened = within(again);
  expect(reopened.getByText(/ping received/)).toBeInTheDocument();
  expect(reopened.getByText("d-2")).toBeInTheDocument();
  expect(reopened.getByText(/<b>new_code<\/b>/)).toBeInTheDocument();
  expect(again.querySelector("b")).toBeNull();
});
