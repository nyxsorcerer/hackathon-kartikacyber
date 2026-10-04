import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { ProgramForm } from "./ProgramForm";
afterEach(() => vi.unstubAllGlobals());
it("saves WordPress independently of GitHub and retains field values after server validation", async () => {
  const submissions: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url === "/api/settings")
        return new Response(
          JSON.stringify({
            monitor_interval_days: 3,
            default_profiles: {},
            webhook_enabled: false,
            webhook_configured: false,
          }),
        );
      if (url === "/api/accounts")
        return new Response(JSON.stringify({ items: [], next_cursor: null }));
      if (url === "/api/programs" && init?.method === "POST") {
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
            id: "saved-program",
            source_url: "https://plugins.svn.wordpress.org/example-plugin",
            source_ref: "trunk",
            monitor_interval_days: 3,
            source_generation: 1,
            last_check_at: null,
            next_check_at: null,
            last_error: null,
            version: null,
          }),
        );
      }
      throw new Error(`Unexpected fixture request ${url}`);
    }),
  );
  const user = userEvent.setup();
  render(
    <MemoryRouter initialEntries={["/programs/new"]}>
      <Routes>
        <Route path="/programs/new" element={<ProgramForm />} />
        <Route path="/programs/:id" element={<h1>Saved program</h1>} />
      </Routes>
    </MemoryRouter>,
  );
  await user.type(
    await screen.findByLabelText("Asset name"),
    "Customer portal",
  );
  await user.type(
    screen.getByLabelText("Asset URL"),
    "https://portal.example.test",
  );
  await user.type(screen.getByLabelText("Product name"), "Example plugin");
  await user.selectOptions(screen.getByLabelText("Source type"), "wordpress");
  expect(screen.queryByLabelText("GitHub repository")).not.toBeInTheDocument();
  await user.type(
    screen.getByLabelText("WordPress plugin slug"),
    "example-plugin",
  );
  await user.click(screen.getByRole("button", { name: "Save program" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Asset URL is not permitted",
  );
  expect(screen.getByLabelText("Asset name")).toHaveValue("Customer portal");
  expect(screen.getByLabelText("WordPress plugin slug")).toHaveValue(
    "example-plugin",
  );
  expect(screen.getByLabelText("Asset URL")).toHaveValue(
    "https://portal.example.test",
  );
  await user.click(screen.getByRole("button", { name: "Save program" }));
  expect(
    await screen.findByRole("heading", { name: "Saved program" }),
  ).toBeInTheDocument();
  expect(submissions[1]).toMatchObject({
    asset_name: "Customer portal",
    source_kind: "wordpress",
    source_url: null,
    plugin_slug: "example-plugin",
    monitor_interval_days: null,
  });
});
