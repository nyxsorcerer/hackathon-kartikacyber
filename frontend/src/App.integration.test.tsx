import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.history.replaceState({}, "", "/");
});
describe("operator authentication", () => {
  it("keeps a protected review URL through login and sends CSRF on logout", async () => {
    window.history.replaceState({}, "", "/commits/commit-1");
    const calls: { url: string; init?: RequestInit }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        calls.push({ url, init });
        let body: unknown;
        if (url === "/api/auth/session") body = { authenticated: false };
        else if (url === "/api/auth/login")
          body = {
            authenticated: true,
            username: "admin",
            csrf_token: "csrf-value",
          };
        else if (url === "/api/auth/logout") body = { authenticated: false };
        else if (url === "/api/commits/commit-1")
          body = {
            id: "commit-1",
            application_id: "application-1",
            revision: "abc123",
            message: "Validate incoming paths",
            author: "Maintainer",
            committed_at: null,
            url: null,
            files: [],
            diff: "diff",
            diff_complete: true,
            triage_status: "disabled",
            triage_result: null,
            review_decision: "pending",
            analyses: [],
          };
        else if (url === "/api/applications/application-1")
          body = {
            id: "application-1",
            asset_name: "Fixture asset",
            asset_url: "https://example.test",
            product_kind: "CMS",
            product_name: "Fixture",
            monitor_interval_seconds: 86400,
            monitor_enabled: true,
            archived: false,
            source_generation: 1,
            last_check_at: null,
            next_check_at: null,
            repositories: [],
            version: null,
            config: {},
          };
        else body = { items: [], next_cursor: null };
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    const user = userEvent.setup();
    render(<App />);
    await user.type(await screen.findByLabelText("Password"), "correct-horse");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(
      await screen.findByRole("heading", { name: "Validate incoming paths" }),
    ).toBeInTheDocument();
    expect(window.location.pathname).toBe("/commits/commit-1");
    await user.click(screen.getByRole("button", { name: "Sign out" }));
    expect(
      await screen.findByRole("button", { name: "Sign in" }),
    ).toBeInTheDocument();
    expect(
      new Headers(
        calls.find((call) => call.url === "/api/auth/logout")?.init?.headers,
      ).get("X-CSRF-Token"),
    ).toBe("csrf-value");
  });
});

it("requires an explicit analysis submit and preserves the runtime model and native effort", async () => {
  window.history.replaceState({}, "", "/commits/review-1");
  const submissions: unknown[] = [];
  const readyAccount = {
    id: "account-1",
    label: "OpenAI API",
    provider: "openai",
    auth_type: "api_key",
    supported_agents: ["pi", "codex"],
    status: "ready",
    credential_configured: true,
    models: [
      {
        id: "pi-model",
        name: "Pi model",
        reasoning_efforts: [],
        default_effort: null,
      },
      {
        id: "codex-model",
        name: "Codex native model",
        reasoning_efforts: ["low", "xhigh"],
        default_effort: "xhigh",
      },
    ],
    agent_models: {
      pi: [
        {
          id: "pi-model",
          name: "Pi model",
          reasoning_efforts: [],
          default_effort: null,
        },
      ],
      codex: [
        {
          id: "codex-model",
          name: "Codex native model",
          reasoning_efforts: ["low", "xhigh"],
          default_effort: "xhigh",
        },
      ],
    },
    usage: null,
    last_checked_at: null,
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      let body: unknown;
      if (url === "/api/auth/session")
        body = { authenticated: true, username: "admin", csrf_token: "token" };
      else if (url === "/api/settings")
        body = {
          monitor_interval_seconds: 172800,
          default_profiles: {},
          webhook_enabled: false,
          webhook_configured: false,
        };
      else if (url === "/api/accounts")
        body = { items: [readyAccount], next_cursor: null };
      else if (url === "/api/commits/review-1/analyses") {
        submissions.push(JSON.parse(String(init?.body)));
        body = { job_id: "job-1", status_url: "/api/jobs/job-1" };
      } else if (url === "/api/commits/review-1")
        body = {
          id: "review-1",
          application_id: "application-1",
          revision: "abc123",
          message: "Validate incoming paths",
          author: "Maintainer",
          committed_at: null,
          url: null,
          files: ["src/parser.py"],
          diff: "diff",
          diff_complete: true,
          triage_status: "security_candidate",
          triage_result: { decision: "security_candidate" },
          review_decision: "candidate",
          analyses: [
            {
              id: "analysis-1",
              created_at: "2026-10-03T00:00:00Z",
              result: {
                category: "Likely vulnerability fix",
                summary: "Prior evidence retained",
              },
              artifacts: [],
            },
          ],
        };
      else if (url === "/api/applications/application-1")
        body = {
          id: "application-1",
          asset_name: "Fixture asset",
          asset_url: "https://example.test",
          product_kind: "CMS",
          product_name: "Fixture",
          monitor_interval_seconds: 172800,
          monitor_enabled: true,
          archived: false,
          source_generation: 1,
          last_check_at: null,
          next_check_at: null,
          repositories: [],
          version: null,
          config: {},
        };
      else body = { items: [], next_cursor: null };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  const user = userEvent.setup();
  render(<App />);
  expect(
    await screen.findByText("Likely vulnerability fix"),
  ).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Create finding" })).toHaveAttribute(
    "href",
    "/findings/new?application_id=application-1&source_commit_id=review-1&source_analysis_id=analysis-1",
  );
  expect(submissions).toHaveLength(0);
  await user.click(screen.getByRole("button", { name: "Analyze" }));
  await user.selectOptions(
    await screen.findByLabelText("Agent runtime"),
    "codex",
  );
  expect(screen.getByLabelText("Model")).toHaveValue("codex-model");
  expect(screen.getByLabelText("Reasoning effort")).toHaveValue("xhigh");
  expect(submissions).toHaveLength(0);
  await user.click(screen.getByRole("button", { name: "Start analysis" }));
  expect(
    await screen.findByText("Background job submitted."),
  ).toBeInTheDocument();
  expect(submissions).toEqual([
    {
      profile: {
        agent: "codex",
        connection_id: "account-1",
        model_id: "codex-model",
        reasoning_effort: "xhigh",
      },
    },
  ]);
});
