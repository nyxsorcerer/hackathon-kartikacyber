import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { AgentSession } from "./AgentSession";

type Fetch = (url: string, options?: RequestInit) => Promise<Response>;
const session = (overrides: Record<string, unknown> = {}) => ({
  runs: ["run-1", "run-2"],
  run_id: "run-1",
  agent: "codex",
  agent_status: "working",
  screen: "First terminal output",
  held: false,
  live: true,
  ...overrides,
});
const response = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
const flush = () => act(async () => {});
const advance = (ms: number) =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it("finishes slow polls before scheduling another request", async () => {
  vi.useFakeTimers();
  const fetch = vi.fn<Fetch>(
    (_url, options) =>
      new Promise((resolve, reject) => {
        const timeout = setTimeout(() => resolve(response(session())), 2500);
        options?.signal?.addEventListener("abort", () => {
          clearTimeout(timeout);
          reject(new DOMException("Aborted", "AbortError"));
        });
      }),
  );
  vi.stubGlobal("fetch", fetch);
  render(<AgentSession jobId="job-1" active />);
  await advance(1500);
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(fetch.mock.calls[0][1]?.signal?.aborted).toBe(false);
  await advance(1000);
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("First terminal output");
  await advance(1499);
  expect(fetch).toHaveBeenCalledTimes(1);
  await advance(1);
  expect(fetch).toHaveBeenCalledTimes(2);
  await advance(2500);
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("First terminal output");
});

it("retains successful output on a poll failure and offers an immediate retry", async () => {
  vi.useFakeTimers();
  const fetch = vi
    .fn<Fetch>()
    .mockResolvedValueOnce(response(session()))
    .mockResolvedValueOnce(response({ message: "Terminal unavailable" }, 503))
    .mockResolvedValueOnce(response(session({ screen: "Recovered output" })));
  vi.stubGlobal("fetch", fetch);
  render(<AgentSession jobId="job-1" active />);
  await flush();
  await advance(1500);
  expect(screen.getByRole("alert")).toHaveTextContent("Terminal unavailable");
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("First terminal output");
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await flush();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Recovered output");
  expect(fetch).toHaveBeenCalledTimes(3);
});

it("stops automatic retries for an unavailable inactive session while allowing manual retry and active startup polling", async () => {
  vi.useFakeTimers();
  const fetch = vi.fn<Fetch>().mockImplementation(async () =>
    response(
      {
        code: "session_unavailable",
        message: "This job has no recorded agent session",
      },
      409,
    ),
  );
  vi.stubGlobal("fetch", fetch);
  const view = render(<AgentSession jobId="job-1" active={false} />);
  await flush();
  expect(screen.getByRole("alert")).toHaveTextContent(
    "This job has no recorded agent session",
  );
  await advance(10000);
  expect(fetch).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await flush();
  expect(fetch).toHaveBeenCalledTimes(2);
  await advance(5000);
  expect(fetch).toHaveBeenCalledTimes(2);
  view.rerender(<AgentSession jobId="job-1" active />);
  await flush();
  expect(fetch).toHaveBeenCalledTimes(3);
  await advance(1500);
  expect(fetch).toHaveBeenCalledTimes(4);
});

it("continues polling and keeps output when an inactive live session temporarily becomes unavailable", async () => {
  vi.useFakeTimers();
  const fetch = vi
    .fn<Fetch>()
    .mockResolvedValueOnce(response(session()))
    .mockResolvedValueOnce(
      response(
        {
          code: "session_unavailable",
          message: "Temporary unavailable session",
        },
        409,
      ),
    )
    .mockResolvedValueOnce(
      response(session({ live: false, screen: "Final retained output" })),
    );
  vi.stubGlobal("fetch", fetch);
  render(<AgentSession jobId="job-1" active={false} />);
  await flush();
  await advance(1500);
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Temporary unavailable session",
  );
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("First terminal output");
  await advance(1500);
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Final retained output");
  expect(fetch).toHaveBeenCalledTimes(3);
});

it("isolates selected runs, aborts stale polls, and steers only the confirmed run", async () => {
  vi.useFakeTimers();
  const stale = deferred<Response>();
  const selected = deferred<Response>();
  const fetch = vi
    .fn<Fetch>()
    .mockResolvedValueOnce(response(session()))
    .mockReturnValueOnce(stale.promise)
    .mockReturnValueOnce(selected.promise)
    .mockResolvedValue(response({}));
  vi.stubGlobal("fetch", fetch);
  render(<AgentSession jobId="job-1" active />);
  await flush();
  fireEvent.change(screen.getByRole("textbox", { name: "Message the agent" }), {
    target: { value: "Draft for the first run" },
  });
  await advance(1500);
  const oldSignal = fetch.mock.calls[1][1]?.signal;
  fireEvent.change(screen.getByRole("combobox", { name: "Agent run" }), {
    target: { value: "run-2" },
  });
  expect(screen.queryByText("First terminal output")).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Send" }),
  ).not.toBeInTheDocument();
  expect(oldSignal?.aborted).toBe(true);
  await act(async () => {
    stale.resolve(response(session({ screen: "Late first-run output" })));
  });
  expect(screen.queryByText("Late first-run output")).not.toBeInTheDocument();
  await act(async () => {
    selected.resolve(
      response(session({ run_id: "run-2", screen: "Second run" })),
    );
  });
  const message = screen.getByRole("textbox", { name: "Message the agent" });
  expect(message).toHaveValue("");
  fireEvent.change(message, { target: { value: "Run two prompt" } });
  fireEvent.click(screen.getByRole("button", { name: "Send" }));
  await flush();
  expect(JSON.parse(String(fetch.mock.calls[3][1]?.body))).toEqual({
    run_id: "run-2",
    action: "prompt",
    text: "Run two prompt",
  });
});

it("follows the latest phase from archived orientation to a live run by default", async () => {
  vi.useFakeTimers();
  let reads = 0;
  const fetch = vi.fn<Fetch>((url, options) => {
    if (options?.method === "POST") return Promise.resolve(response({}));
    const older = reads++ === 0 || url.endsWith("run=run-1");
    return Promise.resolve(
      response(
        session(
          older
            ? { live: false, screen: "Archived orientation" }
            : { run_id: "run-2", live: true, screen: "Live analysis phase" },
        ),
      ),
    );
  });
  vi.stubGlobal("fetch", fetch);
  render(<AgentSession jobId="job-1" active />);
  await flush();
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Archived orientation");
  expect(screen.getByRole("button", { name: "Interrupt" })).toBeDisabled();
  await advance(1500);
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Live analysis phase");
  expect(screen.getByRole("button", { name: "Interrupt" })).toBeEnabled();
  expect(screen.getByRole("combobox", { name: "Agent run" })).toHaveValue("");
  expect(fetch.mock.calls.slice(0, 2).map(([url]) => url)).toEqual([
    "/api/jobs/job-1/session",
    "/api/jobs/job-1/session",
  ]);
  fireEvent.change(screen.getByRole("textbox", { name: "Message the agent" }), {
    target: { value: "Latest phase prompt" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Send" }));
  await flush();
  const post = fetch.mock.calls.find(
    ([, options]) => options?.method === "POST",
  );
  expect(JSON.parse(String(post?.[1]?.body))).toEqual({
    action: "prompt",
    text: "Latest phase prompt",
    run_id: "run-2",
  });
});

it("keeps explicitly selected history pinned and can return to Latest run", async () => {
  vi.useFakeTimers();
  const fetch = vi.fn<Fetch>((url) =>
    Promise.resolve(
      response(
        session(
          url.endsWith("run=run-1")
            ? { live: false, screen: "Earlier run history" }
            : { run_id: "run-2", live: true, screen: "Latest live run" },
        ),
      ),
    ),
  );
  vi.stubGlobal("fetch", fetch);
  render(<AgentSession jobId="job-1" active />);
  await flush();
  expect(screen.getByRole("option", { name: "Latest run" })).toHaveValue("");
  fireEvent.change(screen.getByRole("combobox", { name: "Agent run" }), {
    target: { value: "run-1" },
  });
  await flush();
  expect(screen.getByRole("combobox", { name: "Agent run" })).toHaveValue(
    "run-1",
  );
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Earlier run history");
  await advance(1500);
  expect(fetch.mock.calls.slice(1).map(([url]) => url)).toEqual([
    "/api/jobs/job-1/session?run=run-1",
    "/api/jobs/job-1/session?run=run-1",
  ]);
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Earlier run history");
  fireEvent.change(screen.getByRole("combobox", { name: "Agent run" }), {
    target: { value: "" },
  });
  expect(screen.queryByText("Earlier run history")).not.toBeInTheDocument();
  await flush();
  expect(screen.getByRole("combobox", { name: "Agent run" })).toHaveValue("");
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Latest live run");
  expect(screen.getByRole("button", { name: "Interrupt" })).toBeEnabled();
  expect(fetch.mock.calls.at(-1)?.[0]).toBe("/api/jobs/job-1/session");
});

it("isolates draft and pending delivery when automatic latest moves to another run", async () => {
  vi.useFakeTimers();
  const pending = deferred<Response>();
  let newer = false;
  const fetch = vi.fn<Fetch>((url, options) => {
    if (options?.method === "POST") return pending.promise;
    return Promise.resolve(
      response(
        session(
          newer && !url.includes("?run=")
            ? { run_id: "run-2", screen: "New phase output" }
            : {},
        ),
      ),
    );
  });
  vi.stubGlobal("fetch", fetch);
  render(<AgentSession jobId="job-1" active />);
  await flush();
  fireEvent.change(screen.getByRole("textbox", { name: "Message the agent" }), {
    target: { value: "Prompt for old phase" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Send" }));
  const post = fetch.mock.calls.find(
    ([, options]) => options?.method === "POST",
  );
  newer = true;
  await advance(1500);
  expect(post?.[1]?.signal?.aborted).toBe(true);
  const message = screen.getByRole("textbox", { name: "Message the agent" });
  expect(message).toHaveValue("");
  expect(screen.getByRole("button", { name: "Interrupt" })).toBeEnabled();
  fireEvent.change(message, { target: { value: "New phase draft" } });
  await act(async () =>
    pending.resolve(response({ message: "Previous phase failure" }, 409)),
  );
  expect(message).toHaveValue("New phase draft");
  expect(screen.queryByText("Previous phase failure")).not.toBeInTheDocument();
});

it("clears a previous job and aborts its request when navigation changes the job", async () => {
  const old = deferred<Response>();
  const next = deferred<Response>();
  const fetch = vi
    .fn<Fetch>()
    .mockReturnValueOnce(old.promise)
    .mockReturnValueOnce(next.promise);
  vi.stubGlobal("fetch", fetch);
  const view = render(<AgentSession jobId="job-1" active />);
  view.rerender(<AgentSession jobId="job-2" active />);
  expect(fetch.mock.calls[0][1]?.signal?.aborted).toBe(true);
  await act(async () => {
    old.resolve(response(session({ screen: "Previous job" })));
    next.resolve(response(session({ screen: "Current job" })));
  });
  expect(screen.queryByText("Previous job")).not.toBeInTheDocument();
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Current job");
});

it("sends a prompt once, preserves whitespace and edits made while delivery is pending", async () => {
  const pending = deferred<Response>();
  const fetch = vi.fn<Fetch>((_url, options) =>
    options?.method === "POST"
      ? pending.promise
      : Promise.resolve(response(session())),
  );
  vi.stubGlobal("fetch", fetch);
  render(<AgentSession jobId="job-1" active />);
  await flush();
  const message = screen.getByRole("textbox", { name: "Message the agent" });
  fireEvent.change(message, { target: { value: "  Keep\n    indentation\n" } });
  act(() => {
    fireEvent.keyDown(message, { key: "Enter", ctrlKey: true });
    fireEvent.keyDown(message, { key: "Enter", ctrlKey: true });
  });
  const posts = () =>
    fetch.mock.calls.filter(([, options]) => options?.method === "POST");
  expect(posts()).toHaveLength(1);
  expect(JSON.parse(String(posts()[0][1]?.body))).toEqual({
    run_id: "run-1",
    action: "prompt",
    text: "  Keep\n    indentation\n",
  });
  expect(screen.getByRole("button", { name: /Sending/ })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Interrupt" })).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Hold session open" }),
  ).toBeDisabled();
  fireEvent.change(message, { target: { value: "Next draft" } });
  await act(async () => pending.resolve(response({})));
  expect(message).toHaveValue("Next draft");
  expect(screen.getByRole("button", { name: "Send" })).toBeEnabled();
});

it("serializes terminal keys with prompts and keeps delivery errors visible", async () => {
  const pending = deferred<Response>();
  const fetch = vi.fn<Fetch>((_url, options) =>
    options?.method === "POST"
      ? pending.promise
      : Promise.resolve(response(session())),
  );
  vi.stubGlobal("fetch", fetch);
  render(<AgentSession jobId="job-1" active />);
  await flush();
  fireEvent.click(screen.getByText("Terminal controls"));
  fireEvent.click(screen.getByRole("button", { name: "Enter" }));
  const message = screen.getByRole("textbox", { name: "Message the agent" });
  fireEvent.change(message, { target: { value: "Keep this draft" } });
  fireEvent.keyDown(message, { key: "Enter", ctrlKey: true });
  expect(
    fetch.mock.calls.filter(([, options]) => options?.method === "POST"),
  ).toHaveLength(1);
  await act(async () =>
    pending.resolve(response({ message: "Session no longer live" }, 409)),
  );
  expect(screen.getByRole("alert")).toHaveTextContent("Session no longer live");
  expect(message).toHaveValue("Keep this draft");
  expect(screen.getByRole("button", { name: "Send" })).toBeEnabled();
});

it("does not let an old delivery affect a newly selected run", async () => {
  const pending = deferred<Response>();
  const fetch = vi.fn<Fetch>((url, options) => {
    if (options?.method === "POST") return pending.promise;
    return Promise.resolve(
      response(
        session(
          url.endsWith("run=run-2")
            ? { run_id: "run-2", screen: "Second run" }
            : {},
        ),
      ),
    );
  });
  vi.stubGlobal("fetch", fetch);
  render(<AgentSession jobId="job-1" active />);
  await flush();
  fireEvent.change(screen.getByRole("textbox", { name: "Message the agent" }), {
    target: { value: "First run prompt" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Send" }));
  const post = fetch.mock.calls.find(
    ([, options]) => options?.method === "POST",
  );
  fireEvent.change(screen.getByRole("combobox", { name: "Agent run" }), {
    target: { value: "run-2" },
  });
  await flush();
  const message = screen.getByRole("textbox", { name: "Message the agent" });
  fireEvent.change(message, { target: { value: "New run draft" } });
  expect(post?.[1]?.signal?.aborted).toBe(true);
  await act(async () =>
    pending.resolve(response({ message: "Old delivery failure" }, 409)),
  );
  expect(message).toHaveValue("New run draft");
  expect(screen.queryByText("Old delivery failure")).not.toBeInTheDocument();
});

it.each([
  { active: false, live: true },
  { active: true, live: false },
])(
  "keeps retained output read only when active=$active and live=$live",
  async ({ active, live }) => {
    const fetch = vi.fn<Fetch>().mockResolvedValue(response(session({ live })));
    vi.stubGlobal("fetch", fetch);
    render(<AgentSession jobId="job-1" active={active} />);
    await flush();
    expect(screen.getByText(/Retained session/)).toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: "Agent terminal output" }),
    ).toHaveTextContent("First terminal output");
    if (active) {
      // A running job keeps its controls in place, disabled while not live.
      expect(
        screen.getByRole("textbox", { name: "Message the agent" }),
      ).toBeDisabled();
      expect(screen.getByRole("button", { name: "Send" })).toBeDisabled();
      expect(screen.getByRole("button", { name: "Interrupt" })).toBeDisabled();
      expect(
        screen.getByRole("button", { name: "Hold session open" }),
      ).toBeDisabled();
      fireEvent.click(screen.getByText("Terminal controls"));
      expect(screen.getByRole("button", { name: "Enter" })).toBeDisabled();
    } else {
      // A finished job's session is for review only; no controls are offered.
      expect(
        screen.queryByRole("textbox", { name: "Message the agent" }),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByRole("button", { name: "Interrupt" }),
      ).not.toBeInTheDocument();
    }
    expect(
      fetch.mock.calls.filter(([, options]) => options?.method === "POST"),
    ).toHaveLength(0);
  },
);

it("renders the entire retained screen including its first and last characters", async () => {
  const fullScreen = `FIRST\n${"0123456789  terminal alignment\n".repeat(10000)}LAST`;
  vi.stubGlobal(
    "fetch",
    vi.fn<Fetch>().mockResolvedValue(response(session({ screen: fullScreen }))),
  );
  render(<AgentSession jobId="job-1" active={false} />);
  await flush();
  const terminal = screen.getByRole("region", {
    name: "Agent terminal output",
  });
  expect(terminal.textContent).toBe(fullScreen);
  expect(terminal).toHaveAttribute("tabindex", "0");
});

it("stops refetching inactive archives and refreshes again when job activity changes", async () => {
  vi.useFakeTimers();
  const fetch = vi
    .fn<Fetch>()
    .mockResolvedValue(response(session({ live: false })));
  vi.stubGlobal("fetch", fetch);
  const view = render(<AgentSession jobId="job-1" active />);
  await flush();
  await advance(1500);
  expect(fetch).toHaveBeenCalledTimes(2);
  view.rerender(<AgentSession jobId="job-1" active={false} />);
  await flush();
  expect(fetch).toHaveBeenCalledTimes(3);
  await advance(10000);
  expect(fetch).toHaveBeenCalledTimes(3);
  view.rerender(<AgentSession jobId="job-1" active />);
  await flush();
  expect(fetch).toHaveBeenCalledTimes(4);
  await advance(1500);
  expect(fetch).toHaveBeenCalledTimes(5);
});

it("finishes a pending read and performs the final archive read when a job becomes inactive", async () => {
  vi.useFakeTimers();
  const pending = deferred<Response>();
  const fetch = vi
    .fn<Fetch>()
    .mockReturnValueOnce(pending.promise)
    .mockResolvedValue(
      response(session({ live: false, screen: "Final retained output" })),
    );
  vi.stubGlobal("fetch", fetch);
  const view = render(<AgentSession jobId="job-1" active />);
  view.rerender(<AgentSession jobId="job-1" active={false} />);
  expect(fetch.mock.calls[0][1]?.signal?.aborted).toBe(false);
  expect(fetch).toHaveBeenCalledTimes(1);
  await act(async () => pending.resolve(response(session({ live: false }))));
  await advance(0);
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Final retained output");
  await advance(5000);
  expect(fetch).toHaveBeenCalledTimes(2);
});

it("keeps read-only cancellation checkpoints fresh and fetches the final archive when polling settles", async () => {
  vi.useFakeTimers();
  const fetch = vi
    .fn<Fetch>()
    .mockResolvedValueOnce(response(session({ screen: "Running output" })))
    .mockResolvedValueOnce(
      response(session({ live: false, screen: "Cancellation checkpoint" })),
    )
    .mockResolvedValueOnce(
      response(
        session({ live: false, screen: "Updated cancellation checkpoint" }),
      ),
    )
    .mockResolvedValueOnce(
      response(
        session({
          live: false,
          screen: "FIRST\nComplete final transcript\nLAST",
        }),
      ),
    );
  vi.stubGlobal("fetch", fetch);
  const view = render(<AgentSession jobId="job-1" active polling />);
  await flush();
  view.rerender(<AgentSession jobId="job-1" active={false} polling />);
  await advance(1500);
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Cancellation checkpoint");
  expect(
    screen.queryByRole("textbox", { name: "Message the agent" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Interrupt" }),
  ).not.toBeInTheDocument();
  await advance(1500);
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }),
  ).toHaveTextContent("Updated cancellation checkpoint");
  view.rerender(<AgentSession jobId="job-1" active={false} polling={false} />);
  await flush();
  expect(
    screen.getByRole("region", { name: "Agent terminal output" }).textContent,
  ).toBe("FIRST\nComplete final transcript\nLAST");
  expect(fetch).toHaveBeenCalledTimes(4);
  await advance(10000);
  expect(fetch).toHaveBeenCalledTimes(4);
});

it("follows new output until the operator scrolls back, then jumps to latest explicitly", async () => {
  vi.useFakeTimers();
  let revision = 0;
  vi.stubGlobal(
    "fetch",
    vi
      .fn<Fetch>()
      .mockImplementation(async () =>
        response(session({ screen: `Output ${revision++}` })),
      ),
  );
  render(<AgentSession jobId="job-1" active />);
  await flush();
  const terminal = screen.getByRole("region", {
    name: "Agent terminal output",
  });
  let height = 1000;
  Object.defineProperties(terminal, {
    scrollHeight: { get: () => height, configurable: true },
    clientHeight: { value: 100, configurable: true },
  });
  terminal.scrollLeft = 150;
  await advance(1500);
  expect(terminal.scrollTop).toBe(900);
  expect(screen.getByRole("checkbox", { name: "Follow output" })).toBeChecked();
  terminal.scrollTop = 100;
  fireEvent.scroll(terminal);
  expect(
    screen.getByRole("checkbox", { name: "Follow output" }),
  ).not.toBeChecked();
  height = 1200;
  await advance(1500);
  expect(terminal.scrollTop).toBe(100);
  expect(terminal.scrollLeft).toBe(150);
  fireEvent.click(screen.getByRole("button", { name: "Jump to latest" }));
  expect(terminal.scrollTop).toBe(1100);
  expect(screen.getByRole("checkbox", { name: "Follow output" })).toBeChecked();
});

const conversation = [
  "=== session-transcripts/pi/run.jsonl ===",
  "[user]",
  `Analyze the commit. ${"Follow the output contract carefully. ".repeat(30)}Final instruction.`,
  "",
  "[toolResult · numen_shell]",
  ...Array.from({ length: 40 }, (_, i) => `result line ${i + 1}`),
  "",
  "[assistant]",
  "The fix escapes the form name.",
].join("\n");
const withTerminal = (terminal: string) =>
  `${conversation}\n\n=== Latest terminal view ===\n${terminal}`;

it("shows the live terminal in its own colors and the conversation as a separate transcript", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn<Fetch>().mockResolvedValue(
      response(
        session({
          screen: withTerminal("\x1b[1m\x1b[38;5;1mError:\x1b[0m retrying"),
        }),
      ),
    ),
  );
  render(<AgentSession jobId="job-1" active />);
  await flush();
  const terminal = screen.getByRole("region", {
    name: "Agent terminal output",
  });
  expect(terminal.textContent).toBe("Error: retrying");
  expect(screen.getByText("Error:")).toHaveStyle({
    color: "var(--ansi-1)",
    fontWeight: "700",
  });
  expect(terminal).not.toHaveTextContent("Analyze the commit");
  fireEvent.click(screen.getByRole("button", { name: /Transcript/ }));
  const transcript = screen.getByRole("region", {
    name: "Agent conversation transcript",
  });
  expect(transcript).toHaveTextContent("Analyze the commit");
  // Numen's long task prompt folds to its opening.
  expect(transcript).not.toHaveTextContent("Final instruction.");
  fireEvent.click(
    screen.getByRole("button", {
      name: /show full message \(1,\d{3} characters\)/,
    }),
  );
  expect(transcript).toHaveTextContent("Final instruction.");
  expect(transcript).toHaveTextContent("Tool result · numen_shell");
  expect(transcript).toHaveTextContent("result line 12");
  expect(transcript).not.toHaveTextContent("result line 13");
  fireEvent.click(screen.getByRole("button", { name: "… 28 more lines" }));
  expect(transcript).toHaveTextContent("result line 40");
  expect(transcript).toHaveTextContent("The fix escapes the form name.");
});

it("opens a finished job's session on its full transcript", async () => {
  vi.stubGlobal(
    "fetch",
    vi
      .fn<Fetch>()
      .mockResolvedValue(
        response(session({ live: false, screen: withTerminal("done") })),
      ),
  );
  render(<AgentSession jobId="job-1" active={false} />);
  await flush();
  expect(
    screen.getByRole("region", { name: "Agent conversation transcript" }),
  ).toHaveTextContent("The fix escapes the form name.");
  expect(screen.getByRole("button", { name: /Transcript/ })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
});

it("announces new output below while the operator reads earlier output", async () => {
  vi.useFakeTimers();
  let revision = 0;
  vi.stubGlobal(
    "fetch",
    vi
      .fn<Fetch>()
      .mockImplementation(async () =>
        response(session({ screen: `Output ${revision++}` })),
      ),
  );
  render(<AgentSession jobId="job-1" active />);
  await flush();
  const terminal = screen.getByRole("region", {
    name: "Agent terminal output",
  });
  Object.defineProperties(terminal, {
    scrollHeight: { value: 1000, configurable: true },
    clientHeight: { value: 100, configurable: true },
  });
  terminal.scrollTop = 100;
  fireEvent.scroll(terminal);
  expect(screen.queryByText("New output below")).not.toBeInTheDocument();
  await advance(1500);
  expect(screen.getByText("New output below")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Jump to latest" }));
  expect(terminal.scrollTop).toBe(900);
  expect(screen.queryByText("New output below")).not.toBeInTheDocument();
});

it("lets the operator scroll back through the whole saved terminal scrollback", async () => {
  const scrollback = Array.from(
    { length: 1500 },
    (_, i) => `\x1b[0m\x1b[38;5;2mline\x1b[0m ${i + 1}`,
  ).join("\n");
  vi.stubGlobal(
    "fetch",
    vi
      .fn<Fetch>()
      .mockResolvedValue(
        response(session({ screen: withTerminal(scrollback) })),
      ),
  );
  render(<AgentSession jobId="job-1" active />);
  await flush();
  const terminal = screen.getByRole("region", {
    name: "Agent terminal output",
  });
  expect(terminal.textContent).toBe(
    Array.from({ length: 1500 }, (_, i) => `line ${i + 1}`).join("\n"),
  );
  expect(screen.getAllByText("line")).toHaveLength(1500);
});
