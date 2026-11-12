import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { AuditTab } from "./AuditContext";
import { JobLaunch } from "../components/JobLaunch";
import { setCsrfToken } from "../api";
import type { Application } from "../types";

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken(undefined);
});
const application: Application = {
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
  unresolved_dependencies: [],
  version: null,
  config: {
    profiles: {},
    triage_mode: "disabled",
    cve_selectors: [],
    cve_versions: [],
    cve_auto_analyze: false,
    audit_auto_refresh: false,
  },
};
const context = {
  id: "refreshed",
  source_ref: "b".repeat(40),
  source_generation: 1,
  skill_revision: "skill-revision",
  status: "stale",
  job_id: "refresh-job",
  created_at: "2026-10-07T00:00:00Z",
  artifacts: [],
  coverage: {
    selected: 3,
    completed: 2,
    failed: 0,
    removed: 1,
    deferred: 2,
    reused_functions: 1,
    stage: "complete",
    refresh: {
      from: "base",
      from_revision: "a".repeat(40),
      changed_files: ["change.py", "gone.py", "new.py"],
      changed_files_total: 3,
      removed_units: [{ index: 2, name: "gone", path: "gone.py" }],
    },
  },
};

it("shows what a refresh reused and offers to refresh a context behind the source", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(JSON.stringify({ items: [context], next_cursor: null })),
    ),
  );
  const onRefresh = vi.fn();
  render(
    <MemoryRouter>
      <AuditTab
        application={application}
        onGenerate={vi.fn()}
        onRefresh={onRefresh}
      />
    </MemoryRouter>,
  );
  const refreshed = await screen.findByText(
    (_, element) =>
      element?.tagName === "P" &&
      !!element.textContent?.startsWith("Refreshed from"),
  );
  expect(refreshed).toHaveTextContent(
    "Refreshed from aaaaaaaaaaaa with its orientation · 3 files changed · 1 reused · 1 analysed again · 1 removed",
  );
  expect(
    screen.getByText(/Orientation selected 2 more functions than the limit/),
  ).toBeInTheDocument();
  await userEvent
    .setup()
    .click(screen.getByRole("button", { name: "Refresh for current source" }));
  expect(onRefresh).toHaveBeenCalledWith(
    expect.objectContaining({ id: "refreshed" }),
  );
});

it("starts a refresh with the chosen profile and the context's own scope", async () => {
  const profile = {
    agent: "codex",
    connection_id: "account",
    model_id: "fixture-model",
    reasoning_effort: "high",
  };
  const posted: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(String(init.body)));
        return new Response(
          JSON.stringify({ job_id: "job", status_url: "/api/jobs/job" }),
          { status: 202 },
        );
      }
      return new Response(
        JSON.stringify(
          url === "/api/settings"
            ? {
                monitor_interval_seconds: 604800,
                default_profiles: { audit_context: profile },
                webhook_enabled: false,
                webhook_configured: false,
              }
            : {
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
              },
        ),
      );
    }),
  );
  setCsrfToken("fixture-csrf");
  const onClose = vi.fn();
  render(
    <MemoryRouter>
      <JobLaunch
        path="/applications/application/audit-contexts"
        operation="audit_context"
        context="Example CMS"
        refresh={{ id: "base", revision: "a".repeat(40) }}
        onClose={onClose}
      />
    </MemoryRouter>,
  );
  expect(
    await screen.findByText(/files changed since aaaaaaaaaaaa/),
  ).toBeInTheDocument();
  // The refresh keeps the context's focus and limit, so neither is asked for.
  expect(screen.queryByLabelText("Max functions")).not.toBeInTheDocument();
  await userEvent
    .setup()
    .click(await screen.findByRole("button", { name: "Start refresh" }));
  await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
  expect(posted).toEqual([{ profile, refresh_from: "base" }]);
});
