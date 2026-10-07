import {
  Fragment,
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { ArrowDown, Maximize2, Minimize2 } from "lucide-react";
import type { CSSProperties } from "react";
import { z } from "zod";
import { ApiError, request } from "../api";
import { agentSessionSchema } from "../types";
import { Badge, CopyButton, Panel, Segmented } from "./ui";
import {
  ansiLines,
  hasEscapes,
  splitSession,
  stripAnsi,
  transcriptEntries,
} from "./terminalText";
import type { Entry, Span } from "./terminalText";
import { entryLines, markerOf, visible } from "./transcriptRender";

// Herdr key names sent to the agent's terminal.
const keys: [string, string, string][] = [
  ["Enter", "enter", "Confirm the highlighted choice"],
  ["↑", "up", "Previous choice"],
  ["↓", "down", "Next choice"],
  ["Tab", "tab", "Tab"],
  ["Shift+Tab", "shift+tab", "Cycle agent mode"],
  ["Ctrl+O", "ctrl+o", "Toggle detail/transcript view (shows thinking)"],
  ["Ctrl+C", "ctrl+c", "Ctrl+C"],
];
type Session = z.infer<typeof agentSessionSchema>;
type Props = { jobId: string; active: boolean; polling?: boolean };

function sameSession(a: Session, b: Session) {
  return (
    a.screen === b.screen &&
    a.run_id === b.run_id &&
    a.agent_status === b.agent_status &&
    a.held === b.held &&
    a.live === b.live &&
    a.runs.join() === b.runs.join()
  );
}
/** Poll only after completion: slow terminal reads must not abort each other. */
function useAgentSession(
  base: string,
  run: string | undefined,
  polling: boolean,
) {
  const [data, setData] = useState<Session>();
  const [error, setError] = useState<string>();
  const refreshRef = useRef<() => void>(() => {});
  const refresh = useCallback(() => refreshRef.current(), []);
  const pollingRef = useRef(polling);
  useEffect(() => {
    const changed = pollingRef.current !== polling;
    pollingRef.current = polling;
    if (changed) refresh();
  }, [polling, refresh]);
  useEffect(() => {
    let disposed = false;
    let pending = false;
    let refreshQueued = false;
    let lastSession: Session | undefined;
    let unavailable = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let abort: AbortController | undefined;
    const poll = async () => {
      if (disposed || pending) return;
      pending = true;
      abort = new AbortController();
      try {
        const value = await request(
          run ? `${base}?run=${encodeURIComponent(run)}` : base,
          agentSessionSchema,
          { signal: abort.signal },
        );
        if (disposed || abort.signal.aborted) return;
        if (run && value.run_id !== run)
          throw new Error(
            "The terminal response did not match the selected run. Retry to load it again.",
          );
        // An unchanged poll keeps the rendered terminal as is (no re-render, no scroll jump).
        if (!lastSession || !sameSession(lastSession, value)) setData(value);
        lastSession = value;
        unavailable = false;
        setError(undefined);
      } catch (err: unknown) {
        if (!disposed && !abort.signal.aborted) {
          unavailable =
            !lastSession &&
            err instanceof ApiError &&
            err.code === "session_unavailable" &&
            err.status === 409;
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load the agent session.",
          );
        }
      } finally {
        pending = false;
        if (
          !disposed &&
          (refreshQueued ||
            pollingRef.current ||
            (lastSession?.live !== false && !unavailable))
        ) {
          timer = setTimeout(poll, refreshQueued ? 0 : 1500);
          refreshQueued = false;
        }
      }
    };
    refreshRef.current = () => {
      if (pending) {
        refreshQueued = true;
        return;
      }
      clearTimeout(timer);
      void poll();
    };
    void poll();
    return () => {
      disposed = true;
      clearTimeout(timer);
      abort?.abort();
      refreshRef.current = () => {};
    };
  }, [base, run]);
  return { data, error, refresh };
}

/** Job and run boundaries reset drafts, pending actions, and terminal output. */
export function AgentSession(props: Props) {
  return <JobSession key={props.jobId} {...props} />;
}
function JobSession(props: Props) {
  const [run, setRun] = useState<string>();
  return (
    <RunSession key={run || ""} {...props} run={run} onSelectRun={setRun} />
  );
}
function RunSession({
  jobId,
  active,
  polling = active,
  run,
  onSelectRun,
}: Props & { run?: string; onSelectRun: (run: string | undefined) => void }) {
  const base = `/jobs/${encodeURIComponent(jobId)}/session`;
  const session = useAgentSession(base, run, polling);
  const data = session.data;
  return (
    <Panel
      title="Agent session"
      description="Agent terminal output and retained session history."
      actions={
        data && (
          <>
            {(data.runs.length > 1 || run !== undefined) && (
              <select
                aria-label="Agent run"
                value={run || ""}
                onChange={(e) => onSelectRun(e.target.value || undefined)}
              >
                <option value="">Latest run</option>
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
        {session.error && (
          <div className="agent-session-error">
            <p className="action-error" role="alert">
              {session.error}
            </p>
            <button
              type="button"
              className="secondary"
              onClick={session.refresh}
            >
              Retry
            </button>
          </div>
        )}
        {!data ? (
          <p className="hint" role="status">
            {session.error
              ? active
                ? "Waiting for session output. Retry or leave this view open to reconnect."
                : "Session output could not be loaded. Retry to check again."
              : active
                ? "Waiting for the agent session to start…"
                : "Loading retained session output…"}
          </p>
        ) : (
          <TerminalSession
            key={data.run_id}
            base={base}
            data={data}
            active={active}
            refresh={session.refresh}
          />
        )}
      </div>
    </Panel>
  );
}
/** Styled lines, joined by newlines so the text reads (and copies) as written. */
function SpanLines({ lines }: { lines: Span[][] }) {
  return lines.map((spans, i) => (
    <Fragment key={i}>
      {i > 0 && "\n"}
      {spans.map((span, j) =>
        span.style ? (
          <span key={j} style={span.style}>
            {span.text}
          </span>
        ) : (
          <Fragment key={j}>{span.text}</Fragment>
        ),
      )}
    </Fragment>
  ));
}
const AnsiChunk = memo(function AnsiChunk({ text }: { text: string }) {
  const lines = useMemo(() => ansiLines(text), [text]);
  return <SpanLines lines={lines} />;
});
// Long terminals render in fixed line ranges; as output grows only the last ones change.
const CHUNK_LINES = 200;
/** Terminal text with its ANSI colors; text without escapes stays one text node. */
const AnsiText = memo(function AnsiText({ text }: { text: string }) {
  const chunks = useMemo(() => {
    if (!hasEscapes(text)) return undefined;
    const lines = text.split("\n");
    const result: string[] = [];
    for (let i = 0; i < lines.length; i += CHUNK_LINES)
      result.push(lines.slice(i, i + CHUNK_LINES).join("\n"));
    return result;
  }, [text]);
  if (!chunks) return <>{text}</>;
  return (
    <>
      {chunks.map((chunk, i) => (
        <Fragment key={i}>
          {i > 0 && "\n"}
          <AnsiChunk text={chunk} />
        </Fragment>
      ))}
    </>
  );
});
// Long tool output, arguments and log metadata fold to their first lines until opened.
const FOLD_OVER = 24;
const FOLD_PREVIEW = 12;
// A long prompt (Numen's own task instructions) folds to its opening.
const PROMPT_FOLD_CHARS = 800;
const PROMPT_PREVIEW_CHARS = 400;
function promptPreview(body: string) {
  const cut = body.slice(0, PROMPT_PREVIEW_CHARS);
  return cut.slice(0, Math.max(cut.lastIndexOf(" "), 1)) + " …";
}
function folds(entry: Entry) {
  return (
    entry.type === "file" ||
    (entry.type === "message" &&
      (entry.kind === "output" || entry.kind === "call"))
  );
}
function TranscriptEntryView({
  entry,
  unfoldAll,
}: {
  entry: Entry;
  unfoldAll: boolean;
}) {
  const [open, setOpen] = useState(false);
  const longPrompt =
    entry.type === "message" &&
    entry.kind === "user" &&
    entry.body.length > PROMPT_FOLD_CHARS;
  const lines = useMemo(
    () =>
      entryLines(
        longPrompt && !open
          ? { ...entry, body: promptPreview(entry.body) }
          : entry,
      ),
    [entry, longPrompt, open],
  );
  const canFold = folds(entry) && lines.length > FOLD_OVER && !unfoldAll;
  const shown = canFold && !open ? lines.slice(0, FOLD_PREVIEW) : lines;
  const marker = markerOf(entry);
  const kind = entry.type === "message" ? entry.kind : entry.type;
  return (
    <div
      className={`t-entry t-${kind}`}
      style={
        marker
          ? ({
              "--indent": `${marker.indent}ch`,
              "--mark-left": `${marker.indent > 2 ? 2 : 0}ch`,
            } as CSSProperties)
          : undefined
      }
    >
      {marker && (
        <span className="t-mark" style={marker.style} aria-hidden="true">
          {marker.symbol}
        </span>
      )}
      {entry.type === "message" && (
        <span className="sr-only">{entry.label}: </span>
      )}
      <pre className="t-body">
        <SpanLines lines={shown} />
      </pre>
      {canFold && (
        <button
          type="button"
          className="t-fold"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          {open ? "(show less)" : `… ${lines.length - FOLD_PREVIEW} more lines`}
        </button>
      )}
      {longPrompt && (
        <button
          type="button"
          className="t-fold"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          {open
            ? "(show less)"
            : `show full message (${entry.body.length.toLocaleString("en-US")} characters)`}
        </button>
      )}
    </div>
  );
}
// Polls re-parse the transcript; an entry whose content is unchanged is not redrawn.
const TranscriptEntry = memo(
  TranscriptEntryView,
  (a, b) =>
    a.unfoldAll === b.unfoldAll &&
    a.entry.type === b.entry.type &&
    a.entry.body === b.entry.body &&
    ("label" in a.entry ? a.entry.label : "") ===
      ("label" in b.entry ? b.entry.label : "") &&
    ("kind" in a.entry ? a.entry.kind : "") ===
      ("kind" in b.entry ? b.entry.kind : ""),
);
type View = "terminal" | "transcript";
function TerminalSession({
  base,
  data,
  active,
  refresh,
}: {
  base: string;
  data: Session;
  active: boolean;
  refresh: () => void;
}) {
  const writable = active && data.live !== false;
  const [text, setText] = useState("");
  const [error, setError] = useState<string>();
  const [pendingAction, setPendingAction] = useState<string>();
  const pending = useRef(false);
  const draftRevision = useRef(0);
  const mounted = useRef(true);
  const actionAbort = useRef<AbortController>(undefined);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      actionAbort.current?.abort();
    };
  }, []);

  const parts = useMemo(() => splitSession(data.screen), [data.screen]);
  const entries = useMemo(
    () => (parts.transcript ? transcriptEntries(parts.transcript) : []),
    [parts.transcript],
  );
  const views: View[] = [];
  if (parts.terminal !== undefined) views.push("terminal");
  if (parts.transcript !== undefined) views.push("transcript");
  // A live run opens on its terminal; a retained one on the full conversation.
  const [chosen, setChosen] = useState<View>(
    writable ? "terminal" : "transcript",
  );
  const view = views.includes(chosen) ? chosen : views[0];
  const [wrap, setWrap] = useState(true);
  const [unfoldAll, setUnfoldAll] = useState(false);
  const [tall, setTall] = useState(false);
  const shownText =
    view === "transcript" ? parts.transcript || "" : parts.terminal || "";
  const plain = useMemo(() => stripAnsi(shownText), [shownText]);

  const screen = useRef<HTMLElement>(null);
  const follow = useRef(true);
  const jumping = useRef(false);
  const jumpTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const [following, setFollowing] = useState(true);
  const [unseen, setUnseen] = useState(false);
  useEffect(() => () => clearTimeout(jumpTimer.current), []);
  const jumpToLatest = (smooth: boolean) => {
    follow.current = true;
    setFollowing(true);
    setUnseen(false);
    const el = screen.current;
    if (!el) return;
    const top = Math.max(0, el.scrollHeight - el.clientHeight);
    const reduced = window.matchMedia?.(
      "(prefers-reduced-motion: reduce)",
    ).matches;
    if (smooth && !reduced && typeof el.scrollTo === "function") {
      // Scroll events during the animation must not switch following off;
      // the guard ends when scrolling does (or after a fallback delay).
      jumping.current = true;
      clearTimeout(jumpTimer.current);
      const done = () => {
        jumping.current = false;
        clearTimeout(jumpTimer.current);
      };
      el.addEventListener("scrollend", done, { once: true });
      jumpTimer.current = setTimeout(done, 2500);
      // A long way back snaps to the last screen and glides only that far.
      if (top - el.scrollTop > el.clientHeight * 2)
        el.scrollTop = top - el.clientHeight;
      el.scrollTo({ top, behavior: "smooth" });
    } else el.scrollTop = top;
  };
  useEffect(() => {
    const el = screen.current;
    if (el && follow.current)
      el.scrollTop = Math.max(0, el.scrollHeight - el.clientHeight);
    else if (el) setUnseen(true);
  }, [data.screen]);
  useEffect(() => {
    const el = screen.current;
    if (el && follow.current)
      el.scrollTop = Math.max(0, el.scrollHeight - el.clientHeight);
  }, [view, tall, wrap, unfoldAll]);
  const onScroll = (el: HTMLElement) => {
    const atEnd = el.scrollTop + el.clientHeight >= el.scrollHeight - 24;
    if (jumping.current) {
      if (atEnd) jumping.current = false;
      return;
    }
    follow.current = atEnd;
    setFollowing(atEnd);
    if (atEnd) setUnseen(false);
  };
  const setScreen = (el: HTMLElement | null) => {
    screen.current = el;
  };

  const send = async (body: Record<string, unknown>, sentDraft?: number) => {
    // State updates alone cannot guard repeated keyboard submissions in one turn.
    if (!writable || pending.current || !mounted.current) return;
    pending.current = true;
    setPendingAction(String(body.action));
    setError(undefined);
    const abort = new AbortController();
    actionAbort.current = abort;
    try {
      await request(base, z.unknown(), {
        method: "POST",
        body: JSON.stringify({ ...body, run_id: data.run_id }),
        signal: abort.signal,
      });
      if (!mounted.current || abort.signal.aborted) return;
      if (sentDraft !== undefined && draftRevision.current === sentDraft)
        setText("");
      refresh();
    } catch (err: unknown) {
      if (mounted.current && !abort.signal.aborted)
        setError(
          err instanceof Error ? err.message : "Not delivered. Try again.",
        );
    } finally {
      if (mounted.current && !abort.signal.aborted) {
        pending.current = false;
        setPendingAction(undefined);
      }
    }
  };
  const disabled = !writable || !!pendingAction;
  const foldCount = entries.filter(
    (entry) => folds(entry) && entry.body.split("\n").length > FOLD_OVER,
  ).length;

  return (
    <>
      <div className="agent-terminal-toolbar">
        <div className="inline-actions">
          {views.length > 1 && (
            <Segmented
              label="Session view"
              value={view}
              onChange={(value) => {
                // Each view opens at its latest output.
                setChosen(value as View);
                follow.current = true;
                setFollowing(true);
                setUnseen(false);
              }}
              options={[
                { value: "terminal", label: "Terminal" },
                {
                  value: "transcript",
                  label: "Transcript",
                  count: entries.filter(
                    (e) => e.type === "message" && visible(e),
                  ).length,
                },
              ]}
            />
          )}
          <span className="hint" role="status">
            {writable
              ? "Live session · controls available"
              : "Retained session · read only"}
          </span>
        </div>
        <div className="inline-actions agent-view-options">
          {view === "transcript" && (
            <label className="agent-follow">
              <input
                type="checkbox"
                checked={wrap}
                onChange={(e) => setWrap(e.target.checked)}
              />
              Wrap lines
            </label>
          )}
          {view === "transcript" && foldCount > 0 && (
            <label className="agent-follow">
              <input
                type="checkbox"
                checked={unfoldAll}
                onChange={(e) => setUnfoldAll(e.target.checked)}
              />
              Show full tool output
            </label>
          )}
          <label className="agent-follow">
            <input
              type="checkbox"
              checked={following}
              onChange={(e) => {
                follow.current = e.target.checked;
                setFollowing(e.target.checked);
                if (e.target.checked) jumpToLatest(true);
              }}
            />
            Follow output
          </label>
          <CopyButton
            value={plain}
            label={
              view === "transcript" ? "Copy transcript" : "Copy terminal text"
            }
          />
          <button
            type="button"
            className="icon-button"
            aria-pressed={tall}
            aria-label="Taller view"
            title={tall ? "Restore height" : "Taller view"}
            onClick={() => setTall(!tall)}
          >
            {tall ? (
              <Minimize2 size={15} aria-hidden="true" />
            ) : (
              <Maximize2 size={15} aria-hidden="true" />
            )}
          </button>
        </div>
      </div>
      <div className="agent-screen-frame">
        {view === "transcript" ? (
          <div
            ref={setScreen}
            className={`agent-screen transcript ${wrap ? "wrap" : ""} ${tall ? "tall" : ""}`}
            role="region"
            aria-label="Agent conversation transcript"
            tabIndex={0}
            onScroll={(e) => onScroll(e.currentTarget)}
          >
            {entries.map((entry, i) =>
              visible(entry) ? (
                <TranscriptEntry key={i} entry={entry} unfoldAll={unfoldAll} />
              ) : null,
            )}
          </div>
        ) : (
          <pre
            ref={setScreen}
            className={`agent-screen terminal ${tall ? "tall" : ""}`}
            role="region"
            aria-label="Agent terminal output"
            tabIndex={0}
            onScroll={(e) => onScroll(e.currentTarget)}
          >
            <AnsiText text={parts.terminal || ""} />
          </pre>
        )}
        {!following && (
          <button
            type="button"
            className="secondary jump-latest"
            onClick={() => jumpToLatest(true)}
          >
            {unseen && <span className="jump-dot" aria-hidden="true" />}
            Jump to latest
            <ArrowDown size={14} aria-hidden="true" />
          </button>
        )}
        {unseen && !following && (
          <span className="sr-only" role="status">
            New output below
          </span>
        )}
      </div>
      {active && (
        <form
          className="agent-composer"
          onSubmit={(e) => {
            e.preventDefault();
            if (text.trim())
              void send({ action: "prompt", text }, draftRevision.current);
          }}
        >
          <label>
            Message the agent
            <textarea
              value={text}
              disabled={!writable}
              maxLength={16000}
              onChange={(e) => {
                draftRevision.current += 1;
                setText(e.target.value);
              }}
              onKeyDown={(e) => {
                if (
                  e.key === "Enter" &&
                  (e.metaKey || e.ctrlKey) &&
                  !e.nativeEvent.isComposing
                ) {
                  e.preventDefault();
                  if (!e.repeat) e.currentTarget.form?.requestSubmit();
                }
              }}
              placeholder={
                writable
                  ? "Ask why, add context, or redirect the work"
                  : "This session is retained for review"
              }
            />
          </label>
          {error && (
            <p className="action-error" role="alert">
              {error}
            </p>
          )}
          <div className="agent-composer-actions">
            <div className="inline-actions">
              <button type="submit" disabled={disabled || !text.trim()}>
                {pendingAction === "prompt" ? "Sending…" : "Send"}
              </button>
              <span className="hint">Ctrl / ⌘ + Enter to send</span>
            </div>
            <div className="inline-actions">
              <button
                type="button"
                className="secondary"
                disabled={disabled}
                title="Stop the current turn (Esc)"
                onClick={() => void send({ action: "keys", keys: ["esc"] })}
              >
                Interrupt
              </button>
              <button
                type="button"
                className="secondary"
                disabled={disabled}
                title="Keep the session open until it is released"
                onClick={() =>
                  void send({ action: data.held ? "release" : "hold" })
                }
              >
                {data.held ? "Release session" : "Hold session open"}
              </button>
            </div>
          </div>
          <details className="agent-terminal-controls">
            <summary>Terminal controls</summary>
            <div className="inline-actions">
              {keys.map(([label, key, title]) => (
                <button
                  key={key}
                  type="button"
                  className="secondary"
                  title={title}
                  disabled={disabled}
                  onClick={() => void send({ action: "keys", keys: [key] })}
                >
                  {label}
                </button>
              ))}
            </div>
          </details>
        </form>
      )}
    </>
  );
}
