import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { setCsrfToken } from "../api";
import { Settings } from "./Settings";
const nativeAccount = {
  id: "claude-native",
  label: "Claude subscription",
  provider: "claude",
  auth_type: "native_oauth",
  supported_agents: ["claude"],
  status: "unchecked",
  credential_configured: false,
  models: [],
  agent_models: {},
  usage: null,
  last_checked_at: null,
};
const codexAccount = {
  ...nativeAccount,
  id: "codex-native",
  label: "Codex subscription",
  provider: "openai",
  supported_agents: ["codex"],
};
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  setCsrfToken(undefined);
});
function mountAccounts(
  handler?: (url: string, init?: RequestInit) => Promise<Response>,
) {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      handler ||
        (async () =>
          new Response(
            JSON.stringify({
              items: [nativeAccount, codexAccount],
              next_cursor: null,
            }),
          )),
    ),
  );
  render(
    <MemoryRouter initialEntries={["/settings?tab=accounts"]}>
      <Settings />
    </MemoryRouter>,
  );
}
it("imports native-session JSON as a protected file without previewing or logging its values, then clears the selection", async () => {
  const marker = "fixture-private-session-value";
  const log = vi.spyOn(console, "log");
  const errorLog = vi.spyOn(console, "error");
  const warn = vi.spyOn(console, "warn");
  let imported = false;
  let upload: FormData | undefined;
  let headers: Headers | undefined;
  setCsrfToken("import-csrf");
  mountAccounts(async (url, init) => {
    if (url === "/api/accounts/claude-native/native-cache") {
      expect(init?.method).toBe("POST");
      upload = init?.body instanceof FormData ? init.body : undefined;
      headers = new Headers(init?.headers);
      imported = true;
      return new Response(
        JSON.stringify({ ...nativeAccount, credential_configured: true }),
      );
    }
    return new Response(
      JSON.stringify({
        items: [
          { ...nativeAccount, credential_configured: imported },
          codexAccount,
        ],
        next_cursor: null,
      }),
    );
  });
  const user = userEvent.setup();
  await screen.findByText("Claude subscription");
  const claudeCard = screen.getByText("Claude subscription").closest("article");
  if (!claudeCard) throw new Error("Connection card not found");
  expect(
    within(claudeCard).getByRole("button", { name: "Native login" }),
  ).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "Native login" })).toHaveLength(
    2,
  );
  await user.click(
    within(claudeCard).getByRole("button", { name: "Import native session" }),
  );
  const input = screen.getByLabelText("Native-session JSON file");
  await user.upload(
    input,
    new File(
      [
        JSON.stringify({
          claudeAiOauth: {
            accessToken: marker,
            refreshToken: "fixture-refresh",
          },
        }),
      ],
      ".credentials.json",
      { type: "application/json" },
    ),
  );
  expect(document.body).not.toHaveTextContent(marker);
  expect(document.body.innerHTML).not.toContain(marker);
  await user.click(screen.getByRole("button", { name: "Import session" }));
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  expect(upload?.get("file")).toBeInstanceOf(File);
  expect(headers?.get("X-CSRF-Token")).toBe("import-csrf");
  expect(input).toHaveValue("");
  expect(document.body).not.toHaveTextContent(marker);
  expect(document.body.innerHTML).not.toContain(marker);
  expect(log).not.toHaveBeenCalled();
  expect(errorLog).not.toHaveBeenCalled();
  expect(warn).not.toHaveBeenCalled();
});
it("uses a generic parse error for malformed JSON and makes no import request", async () => {
  mountAccounts();
  const user = userEvent.setup();
  await screen.findByText("Claude subscription");
  await user.click(
    screen.getAllByRole("button", { name: "Import native session" })[0],
  );
  await user.upload(
    screen.getByLabelText("Native-session JSON file"),
    new File(
      ['{"accessToken":"fixture-private-session-value"'],
      ".credentials.json",
      { type: "application/json" },
    ),
  );
  await user.click(screen.getByRole("button", { name: "Import session" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Select a valid native-session JSON file.",
  );
  expect(document.body).not.toHaveTextContent("fixture-private-session-value");
  expect(
    vi
      .mocked(fetch)
      .mock.calls.some(([url]) => String(url).endsWith("/native-cache")),
  ).toBe(false);
});
it("rejects files above the one MiB boundary before reading or submitting them", async () => {
  mountAccounts();
  const user = userEvent.setup();
  await screen.findByText("Claude subscription");
  await user.click(
    screen.getAllByRole("button", { name: "Import native session" })[0],
  );
  await user.upload(
    screen.getByLabelText("Native-session JSON file"),
    new File(["x".repeat(1048577)], "large.json", { type: "application/json" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Choose a JSON file no larger than 1 MiB.",
  );
  expect(screen.getByRole("button", { name: "Import session" })).toBeDisabled();
  expect(
    vi
      .mocked(fetch)
      .mock.calls.some(([url]) => String(url).endsWith("/native-cache")),
  ).toBe(false);
});
it("shows device instructions arriving during a running login, prevents duplicate starts, and lets the operator cancel", async () => {
  let polls = 0;
  let cancelled = false;
  setCsrfToken("login-csrf");
  mountAccounts(async (url, init) => {
    if (url === "/api/accounts/codex-native/login") {
      polls += 1;
      return new Response(
        JSON.stringify({
          status: cancelled ? "cancelled" : "running",
          job_id: "login-job",
          events:
            polls > 1
              ? [
                  {
                    kind: "login",
                    verification_uri: "https://auth.openai.com/codex/device",
                  },
                  { kind: "login", user_code: "ABCD-12345" },
                ]
              : [],
        }),
      );
    }
    if (url === "/api/jobs/login-job/cancel") {
      expect(init?.method).toBe("POST");
      expect(new Headers(init?.headers).get("X-CSRF-Token")).toBe("login-csrf");
      cancelled = true;
      return new Response(
        JSON.stringify({
          job_id: "login-job",
          status_url: "/api/jobs/login-job",
        }),
      );
    }
    return new Response(
      JSON.stringify({ items: [codexAccount], next_cursor: null }),
    );
  });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Native login" }));
  await screen.findByText(/Waiting for you to complete provider verification/);
  expect(
    screen.getByRole("button", { name: "Start native login" }),
  ).toBeDisabled();
  const link = await screen.findByRole(
    "link",
    { name: "Open provider verification" },
    { timeout: 3000 },
  );
  expect(link).toHaveAttribute("href", "https://auth.openai.com/codex/device");
  expect(screen.getByText("ABCD-12345")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Cancel login" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Start native login" }),
    ).toBeEnabled(),
  );
  expect(screen.queryByText("ABCD-12345")).not.toBeInTheDocument();
  expect(
    screen.queryByRole("link", { name: "Open provider verification" }),
  ).not.toBeInTheDocument();
});
it("lets the operator paste the Claude authorization code without displaying it", async () => {
  const marker = "fixture-authorization-code#fixture-state";
  let submitted: unknown;
  let headers: Headers | undefined;
  setCsrfToken("claude-login-csrf");
  mountAccounts(async (url, init) => {
    if (url === "/api/accounts/claude-native/login/code") {
      expect(init?.method).toBe("POST");
      submitted = JSON.parse(String(init?.body));
      headers = new Headers(init?.headers);
      return new Response(
        JSON.stringify({ job_id: "claude-login", status: "code_received" }),
        { status: 202 },
      );
    }
    if (url === "/api/accounts/claude-native/login") {
      const instruction = {
        kind: "login",
        verification_uri:
          "https://claude.com/cai/oauth/authorize?code=true&state=fixture",
        input_required: "authorization_code",
      };
      return new Response(
        JSON.stringify({
          status: "running",
          job_id: "claude-login",
          events: submitted
            ? [instruction, { kind: "login", status: "code_received" }]
            : [instruction],
        }),
      );
    }
    return new Response(
      JSON.stringify({ items: [nativeAccount], next_cursor: null }),
    );
  });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Native login" }));
  const link = await screen.findByRole("link", {
    name: "Open provider verification",
  });
  expect(link).toHaveAttribute(
    "href",
    "https://claude.com/cai/oauth/authorize?code=true&state=fixture",
  );
  const input = screen.getByLabelText("Authorization code");
  expect(input).toHaveAttribute("type", "password");
  await user.type(input, `  ${marker}  `);
  await user.click(
    screen.getByRole("button", { name: "Submit authorization code" }),
  );
  await screen.findByText(/Authorization code submitted/);
  expect(submitted).toEqual({ code: marker });
  expect(headers?.get("X-CSRF-Token")).toBe("claude-login-csrf");
  expect(screen.queryByLabelText("Authorization code")).not.toBeInTheDocument();
  expect(document.body).not.toHaveTextContent(marker);
  expect(document.body.innerHTML).not.toContain(marker);
});
it("signs in to Command Code by pasting the API key Studio shows, without displaying it", async () => {
  const marker = "user_fixture-commandcode-key";
  const commandCodeAccount = {
    ...nativeAccount,
    id: "commandcode-native",
    label: "My Command Code",
    provider: "commandcode",
    supported_agents: ["pi"],
  };
  let submitted: unknown;
  setCsrfToken("commandcode-login-csrf");
  mountAccounts(async (url, init) => {
    if (url === "/api/accounts/commandcode-native/login/code") {
      submitted = JSON.parse(String(init?.body));
      expect(new Headers(init?.headers).get("X-CSRF-Token")).toBe(
        "commandcode-login-csrf",
      );
      return new Response(
        JSON.stringify({
          job_id: "commandcode-login",
          status: "code_received",
        }),
        { status: 202 },
      );
    }
    if (url === "/api/accounts/commandcode-native/login") {
      const instruction = {
        kind: "login",
        verification_uri:
          "https://commandcode.ai/studio/auth/cli?callback=http%3A%2F%2Flocalhost%3A5959%2Fcallback&state=fixture",
        input_required: "api_key",
      };
      return new Response(
        JSON.stringify({
          status: "running",
          job_id: "commandcode-login",
          events: submitted
            ? [instruction, { kind: "login", status: "code_received" }]
            : [instruction],
        }),
      );
    }
    return new Response(
      JSON.stringify({ items: [commandCodeAccount], next_cursor: null }),
    );
  });
  const user = userEvent.setup();
  expect(
    await screen.findByText("Command Code · Command Code login"),
  ).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Native login" }));
  expect(
    await screen.findByRole("link", { name: "Open provider verification" }),
  ).toHaveAttribute(
    "href",
    "https://commandcode.ai/studio/auth/cli?callback=http%3A%2F%2Flocalhost%3A5959%2Fcallback&state=fixture",
  );
  expect(screen.getByText(/copy it and paste it here/)).toBeInTheDocument();
  const input = screen.getByLabelText("API key");
  expect(input).toHaveAttribute("type", "password");
  await user.type(input, marker);
  await user.click(screen.getByRole("button", { name: "Submit API key" }));
  await screen.findByText(/API key submitted/);
  expect(submitted).toEqual({ code: marker });
  expect(screen.queryByLabelText("API key")).not.toBeInTheDocument();
  expect(document.body.innerHTML).not.toContain(marker);
});
