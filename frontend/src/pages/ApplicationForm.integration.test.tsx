import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { ApplicationForm } from "./ApplicationForm";
afterEach(() => vi.unstubAllGlobals());
it("saves an Application without repositories and retains field values after server validation", async () => {
  const submissions: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/settings")
        return new Response(
          JSON.stringify({
            monitor_interval_seconds: 259200,
            default_profiles: {},
            webhook_enabled: false,
            webhook_configured: false,
          }),
        );
      if (url === "/api/accounts")
        return new Response(JSON.stringify({ items: [], next_cursor: null }));
      if (url === "/api/applications" && init?.method === "POST") {
        const body: unknown = JSON.parse(String(init.body));
        if (typeof body !== "object" || body === null)
          throw new Error("Unexpected test request");
        const payload = Object.fromEntries(Object.entries(body));
        submissions.push(payload);
        if (submissions.length === 1)
          return new Response(
            JSON.stringify({
              code: "validation_error",
              message: "Asset URL is not permitted",
              fields: { asset_url: "Choose an HTTP(S) asset" },
            }),
            { status: 422 },
          );
        return new Response(
          JSON.stringify({
            ...payload,
            id: "saved-application",
            monitor_interval_seconds: 259200,
            source_generation: 1,
            last_check_at: null,
            next_check_at: null,
            repositories: [],
            version: null,
          }),
        );
      }
      throw new Error(`Unexpected fixture request ${url}`);
    }),
  );
  const user = userEvent.setup();
  render(
    <MemoryRouter initialEntries={["/applications/new"]}>
      <Routes>
        <Route path="/applications/new" element={<ApplicationForm />} />
        <Route path="/applications/:id" element={<h1>Saved application</h1>} />
      </Routes>
    </MemoryRouter>,
  );
  await user.type(await screen.findByLabelText("Name"), "Customer portal");
  await user.type(
    screen.getByLabelText("Asset URL"),
    "https://portal.example.test",
  );
  await user.type(screen.getByLabelText("Product name"), "Example plugin");
  // Repositories are linked from the Application's page, not this form.
  expect(screen.queryByLabelText("Source type")).not.toBeInTheDocument();
  // Triage on Codex is refused: it has no flag that removes its shell.
  expect(
    within(screen.getByLabelText("Triage mode")).queryByRole("option", {
      name: "Codex CLI",
    }),
  ).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Save application" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Asset URL is not permitted",
  );
  expect(screen.getByLabelText("Name")).toHaveValue("Customer portal");
  expect(screen.getByLabelText("Product name")).toHaveValue("Example plugin");
  expect(screen.getByLabelText("Asset URL")).toHaveValue(
    "https://portal.example.test",
  );
  await user.click(screen.getByLabelText("Keep the audit context current"));
  await user.click(screen.getByRole("button", { name: "Save application" }));
  expect(
    await screen.findByRole("heading", { name: "Saved application" }),
  ).toBeInTheDocument();
  expect(submissions[1]).toMatchObject({
    asset_name: "Customer portal",
    monitor_interval_seconds: null,
    config: expect.objectContaining({ audit_auto_refresh: true }),
  });
  expect(submissions[1]).not.toHaveProperty("source_kind");
  // Off unless the operator turns it on.
  expect(submissions[0].config).toMatchObject({ audit_auto_refresh: false });
});
it("enters the interval in minutes, hours or days and keeps it after a field error", async () => {
  const submissions: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/settings")
        return new Response(
          JSON.stringify({
            monitor_interval_seconds: 21600,
            default_profiles: {},
            webhook_enabled: false,
            webhook_configured: false,
          }),
        );
      if (url === "/api/accounts")
        return new Response(JSON.stringify({ items: [], next_cursor: null }));
      if (url === "/api/applications" && init?.method === "POST") {
        const body: unknown = JSON.parse(String(init.body));
        if (typeof body !== "object" || body === null)
          throw new Error("Unexpected test request");
        const payload = Object.fromEntries(Object.entries(body));
        submissions.push(payload);
        if (payload.monitor_interval_seconds !== 300)
          return new Response(
            JSON.stringify({
              code: "validation_error",
              message: "Check the supplied fields",
              fields: { monitor_interval_seconds: "At least 5 minutes" },
            }),
            { status: 422 },
          );
        return new Response(
          JSON.stringify({
            ...payload,
            id: "saved-application",
            source_generation: 1,
            last_check_at: null,
            next_check_at: null,
            repositories: [],
            version: null,
          }),
        );
      }
      throw new Error(`Unexpected fixture request ${url}`);
    }),
  );
  const user = userEvent.setup();
  render(
    <MemoryRouter initialEntries={["/applications/new"]}>
      <Routes>
        <Route path="/applications/new" element={<ApplicationForm />} />
        <Route path="/applications/:id" element={<h1>Saved application</h1>} />
      </Routes>
    </MemoryRouter>,
  );
  await user.type(await screen.findByLabelText("Name"), "Customer portal");
  await user.type(
    screen.getByLabelText("Asset URL"),
    "https://portal.example.test",
  );
  await user.type(screen.getByLabelText("Product name"), "Example plugin");
  const inherit = screen.getByLabelText("Use the global default (6 hours)");
  expect(screen.getByLabelText("Check interval")).toHaveValue(6);
  expect(screen.getByLabelText("Check interval unit")).toHaveValue("3600");
  await user.click(inherit);
  const count = screen.getByLabelText("Check interval");
  await user.clear(count);
  await user.type(count, "4");
  await user.selectOptions(
    screen.getByLabelText("Check interval unit"),
    "minutes",
  );
  await user.click(screen.getByRole("button", { name: "Save application" }));
  expect(await screen.findByText("At least 5 minutes")).toBeInTheDocument();
  expect(submissions[0]).toMatchObject({ monitor_interval_seconds: 240 });
  expect(screen.getByLabelText("Check interval")).toHaveValue(4);
  expect(screen.getByLabelText("Check interval unit")).toHaveValue("60");
  await user.clear(screen.getByLabelText("Check interval"));
  await user.type(screen.getByLabelText("Check interval"), "5");
  await user.click(screen.getByRole("button", { name: "Save application" }));
  expect(
    await screen.findByRole("heading", { name: "Saved application" }),
  ).toBeInTheDocument();
  expect(submissions[1]).toMatchObject({ monitor_interval_seconds: 300 });
});
it("names a stored Codex Triage mode and asks for another one", async () => {
  const application = {
    id: "app-1",
    asset_name: "Customer portal",
    asset_url: "https://portal.example.test",
    product_kind: "cms",
    product_name: "Example CMS",
    monitor_interval_seconds: 3600,
    monitor_enabled: true,
    archived: false,
    source_generation: 1,
    last_check_at: null,
    next_check_at: null,
    repositories: [],
    version: null,
    config: { triage_mode: "codex" },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const body =
        url === "/api/applications/app-1"
          ? application
          : url === "/api/settings"
            ? { monitor_interval_seconds: 3600, default_profiles: {} }
            : { items: [], next_cursor: null };
      return new Response(JSON.stringify(body));
    }),
  );
  render(
    <MemoryRouter initialEntries={["/applications/app-1/edit"]}>
      <Routes>
        <Route path="/applications/:id/edit" element={<ApplicationForm />} />
      </Routes>
    </MemoryRouter>,
  );
  const mode = await screen.findByLabelText("Triage mode");
  expect(mode).toHaveValue("codex");
  expect(
    within(mode).getByRole("option", { name: /Codex CLI/ }),
  ).toBeDisabled();
  expect(
    screen.getByText(/Choose another Triage mode to save/),
  ).toBeInTheDocument();
  await userEvent.setup().selectOptions(mode, "jev");
  expect(
    screen.queryByText(/Choose another Triage mode to save/),
  ).not.toBeInTheDocument();
});
