import { useEffect, useRef, useState } from "react";
import { z } from "zod";
import { mutate } from "../api";
import { useResource } from "../hooks";
import { agentSessionSchema } from "../types";
import { ActionButton, Badge, Panel } from "./ui";

// Herdr key names sent to the agent's terminal.
const keys: [string, string, string][] = [
  ["Interrupt", "esc", "Stop the current turn (Esc)"],
  ["Enter", "enter", "Confirm the highlighted choice"],
  ["↑", "up", "Previous choice"],
  ["↓", "down", "Next choice"],
  ["Tab", "tab", "Tab"],
  ["Shift+Tab", "shift+tab", "Cycle agent mode"],
  ["Ctrl+O", "ctrl+o", "Toggle detail/transcript view (shows thinking)"],
  ["Ctrl+C", "ctrl+c", "Ctrl+C"],
];

/** Live view of a running job's Herdr agent session, with chat and steering controls. */
export function AgentSession({ jobId }: { jobId: string }) {
  const [run, setRun] = useState<string>();
  const [text, setText] = useState("");
  const [error, setError] = useState<string>();
  const base = `/jobs/${encodeURIComponent(jobId)}/session`;
  const session = useResource(
    run ? `${base}?run=${encodeURIComponent(run)}` : base,
    agentSessionSchema,
    1500,
    true,
  );
  const data = session.data;
  const screen = useRef<HTMLPreElement>(null);
  const stick = useRef(true);
  useEffect(() => {
    const el = screen.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [data?.screen]);
  const send = async (body: Record<string, unknown>) => {
    if (!data) return;
    await mutate(base, z.unknown(), { run_id: data.run_id, ...body });
    session.refresh();
  };
  return (
    <Panel
      title="Agent session"
      description="Live Herdr terminal of the running agent. Chat, interrupt, or hold the session open to inspect it."
      actions={
        data && (
          <>
            {data.runs.length > 1 && (
              <select
                aria-label="Agent run"
                value={data.run_id}
                onChange={(e) => setRun(e.target.value)}
              >
                {data.runs.map((id, i) => (
                  <option key={id} value={id}>
                    Run {i + 1} · {id.slice(0, 8)}
                  </option>
                ))}
              </select>
            )}
            <Badge>{data.agent_status}</Badge>
            {data.held && <Badge tone="warm">held</Badge>}
          </>
        )
      }
    >
      <div className="panel-body agent-session">
        {!data ? (
          <p className="hint">
            {session.error ||
              "Waiting for the agent session to start. Sessions need NUMEN_AGENT_BACKEND=herdr."}
          </p>
        ) : (
          <>
            {session.error && <p className="hint">{session.error}</p>}
            <pre
              ref={screen}
              className="agent-screen"
              onScroll={(e) => {
                const el = e.currentTarget;
                stick.current =
                  el.scrollTop + el.clientHeight >= el.scrollHeight - 24;
              }}
            >
              {data.screen}
            </pre>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const message = text.trim();
                if (message)
                  send({ action: "prompt", text: message })
                    .then(() => {
                      setText("");
                      setError(undefined);
                    })
                    .catch((err: unknown) =>
                      setError(
                        err instanceof Error ? err.message : "Not delivered.",
                      ),
                    );
              }}
            >
              <label>
                Message the agent
                <textarea
                  value={text}
                  maxLength={16000}
                  onChange={(e) => setText(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.metaKey || e.ctrlKey))
                      e.currentTarget.form?.requestSubmit();
                  }}
                  placeholder="Ask why, add context, or redirect the work (Ctrl+Enter to send)"
                />
              </label>
              {error && (
                <p className="action-error" role="alert">
                  {error}
                </p>
              )}
              <div className="inline-actions">
                <button type="submit" disabled={!text.trim()}>
                  Send
                </button>
                {keys.map(([label, key, title]) => (
                  <ActionButton
                    key={key}
                    className="secondary"
                    title={title}
                    onAction={() => send({ action: "keys", keys: [key] })}
                  >
                    {label}
                  </ActionButton>
                ))}
                <ActionButton
                  className="secondary"
                  title="A held session never finishes on its own, even after a failure, until released"
                  onAction={() =>
                    send({ action: data.held ? "release" : "hold" })
                  }
                >
                  {data.held ? "Release session" : "Hold session open"}
                </ActionButton>
              </div>
            </form>
          </>
        )}
      </div>
    </Panel>
  );
}
