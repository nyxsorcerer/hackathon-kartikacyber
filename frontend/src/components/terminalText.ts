/**
 * Agent session text: ANSI styling from the terminal, and the saved
 * conversation transcript the runner writes before the latest terminal view.
 */
import type { CSSProperties } from "react";

export type Span = { text: string; style?: CSSProperties };
type Style = {
  fg?: string;
  bg?: string;
  bold?: boolean;
  dim?: boolean;
  italic?: boolean;
  underline?: boolean;
  strike?: boolean;
  inverse?: boolean;
};
// CSI (SGR colors and cursor control), OSC (titles, links), and two-byte escapes.
const ESCAPE =
  // eslint-disable-next-line no-control-regex -- matching terminal escapes is the point.
  /\x1b\[([0-?]*)[ -/]*([@-~])|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]/g;
export function hasEscapes(text: string) {
  return text.includes("\x1b") || text.includes("\r");
}
export function stripAnsi(text: string) {
  return text.replace(ESCAPE, "");
}
const cube = [0, 95, 135, 175, 215, 255];
/** A 256-color index; the first 16 follow the theme's terminal palette. */
function indexed(n: number) {
  if (!Number.isInteger(n) || n < 0 || n > 255) return undefined;
  if (n < 16) return `var(--ansi-${n})`;
  if (n < 232) {
    const i = n - 16;
    return `rgb(${cube[Math.floor(i / 36)]}, ${cube[Math.floor(i / 6) % 6]}, ${cube[i % 6]})`;
  }
  const level = 8 + (n - 232) * 10;
  return `rgb(${level}, ${level}, ${level})`;
}
function rgb(r: number, g: number, b: number) {
  return [r, g, b].every((v) => Number.isInteger(v) && v >= 0 && v <= 255)
    ? `rgb(${r}, ${g}, ${b})`
    : undefined;
}
function applySgr(params: string, style: Style): Style {
  let next: Style = { ...style };
  const tokens = params.split(";");
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].includes(":")) {
      // Colon sub-parameters (38:5:n, 38:2::r:g:b, 4:3) keep one attribute per token.
      const parts = tokens[i].split(":").map(Number);
      const [code, mode] = parts;
      if (code === 38 || code === 48) {
        const [r, g, b] = parts.slice(-3);
        const color =
          mode === 5
            ? indexed(parts[2])
            : mode === 2
              ? rgb(r, g, b)
              : undefined;
        if (code === 38) next.fg = color;
        else next.bg = color;
      } else if (code === 4) next.underline = mode !== 0;
      continue;
    }
    // An empty parameter means 0 (reset), as in a bare ESC[m.
    const code = Number(tokens[i]);
    if (code === 0) next = {};
    else if (code === 1) next.bold = true;
    else if (code === 2) next.dim = true;
    else if (code === 3) next.italic = true;
    else if (code === 4) next.underline = true;
    else if (code === 7) next.inverse = true;
    else if (code === 9) next.strike = true;
    else if (code === 22) next.bold = next.dim = false;
    else if (code === 23) next.italic = false;
    else if (code === 24) next.underline = false;
    else if (code === 27) next.inverse = false;
    else if (code === 29) next.strike = false;
    else if (code >= 30 && code <= 37) next.fg = indexed(code - 30);
    else if (code >= 90 && code <= 97) next.fg = indexed(code - 90 + 8);
    else if (code >= 40 && code <= 47) next.bg = indexed(code - 40);
    else if (code >= 100 && code <= 107) next.bg = indexed(code - 100 + 8);
    else if (code === 39) next.fg = undefined;
    else if (code === 49) next.bg = undefined;
    else if (code === 38 || code === 48) {
      // Extended color across tokens: 38;5;n or 38;2;r;g;b.
      const mode = tokens[i + 1];
      const values = tokens.slice(i + 2, i + 5).map(Number);
      const color =
        mode === "5"
          ? indexed(values[0])
          : mode === "2"
            ? rgb(values[0], values[1], values[2])
            : undefined;
      if (code === 38) next.fg = color;
      else next.bg = color;
      i += mode === "5" ? 2 : mode === "2" ? 4 : 0;
    }
  }
  return next;
}
function css(style: Style): CSSProperties | undefined {
  const fg = style.inverse ? style.bg || "var(--term-bg)" : style.fg;
  const bg = style.inverse ? style.fg || "var(--term-fg)" : style.bg;
  const decoration = [
    style.underline && "underline",
    style.strike && "line-through",
  ].filter(Boolean);
  const result: CSSProperties = {
    ...(fg && { color: fg }),
    ...(bg && { backgroundColor: bg }),
    ...(style.bold && { fontWeight: 700 }),
    ...(style.dim && { opacity: 0.6 }),
    ...(style.italic && { fontStyle: "italic" }),
    ...(decoration.length && { textDecoration: decoration.join(" ") }),
  };
  return Object.keys(result).length ? result : undefined;
}
/**
 * Splits text into lines of styled spans. Style carries across lines as in a
 * terminal; a carriage return overwrites the line, as progress bars expect.
 */
export function ansiLines(text: string): Span[][] {
  let style: Style = {};
  return text
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => {
      let spans: Span[] = [];
      let last = 0;
      const push = (chunk: string) => {
        const parts = chunk.split("\r");
        if (parts.length > 1) spans = [];
        const tail = parts[parts.length - 1];
        if (tail) spans.push({ text: tail, style: css(style) });
      };
      for (const match of line.matchAll(ESCAPE)) {
        push(line.slice(last, match.index));
        last = match.index + match[0].length;
        if (match[2] === "m") style = applySgr(match[1], style);
      }
      push(line.slice(last));
      return spans;
    });
}

// Only the runner's own section headers; an agent may echo "=== x ===" itself.
const FILE_SECTION =
  /^=== ((?:session-transcripts|session-output|\.claude|\.codex)\/.+) ===$/;
const TERMINAL_VIEW = "=== Latest terminal view ===";
const ROLE =
  /^\[(user|assistant|system|developer|reasoning|message|tool call|tool result|toolCall|toolResult|function_call|function_call_output|custom_tool_call|custom_tool_call_output|local_shell_call|local_shell_call_output|web_search_call|bashExecution)((?: · [^\]\n]{0,160})?)\]$/;
const roleNames: Record<string, string> = {
  user: "User",
  assistant: "Assistant",
  system: "System",
  developer: "Developer",
  reasoning: "Reasoning",
  message: "Message",
  "tool call": "Tool call",
  toolCall: "Tool call",
  function_call: "Tool call",
  custom_tool_call: "Tool call",
  local_shell_call: "Shell command",
  web_search_call: "Web search",
  bashExecution: "Shell command",
  "tool result": "Tool result",
  toolResult: "Tool result",
  function_call_output: "Tool result",
  custom_tool_call_output: "Tool result",
  local_shell_call_output: "Shell output",
};
export type EntryKind = "user" | "assistant" | "call" | "output" | "note";
function entryKind(role: string): EntryKind {
  if (role === "user") return "user";
  if (role === "assistant") return "assistant";
  if (/result|output/i.test(role)) return "output";
  if (/call|bash|search/i.test(role)) return "call";
  return "note";
}
export type Entry =
  | { type: "file"; label: string; body: string }
  | { type: "message"; kind: EntryKind; label: string; body: string }
  | { type: "text"; body: string };
/**
 * Separates the saved conversation from the latest terminal view. Sessions
 * without the runner's sections are shown as one terminal view.
 */
export function splitSession(screen: string): {
  transcript?: string;
  terminal?: string;
} {
  const at = screen.lastIndexOf(TERMINAL_VIEW);
  const atLineStart = at === 0 || (at > 0 && screen[at - 1] === "\n");
  const end = at + TERMINAL_VIEW.length;
  if (at >= 0 && atLineStart && (end === screen.length || screen[end] === "\n"))
    return {
      transcript: screen.slice(0, at).replace(/\n+$/, "") || undefined,
      terminal: screen.slice(end + 1),
    };
  if (screen.split("\n").some((line) => FILE_SECTION.test(line)))
    return { transcript: screen };
  return { terminal: screen };
}
/** Groups transcript lines under their file and role headers. */
export function transcriptEntries(transcript: string): Entry[] {
  const entries: Entry[] = [];
  let body: string[] = [];
  let current: Entry | undefined;
  const flush = () => {
    const text = body.join("\n").replace(/^\n+|\n+$/g, "");
    if (current) entries.push({ ...current, body: text });
    else if (text) entries.push({ type: "text", body: text });
    body = [];
  };
  for (const line of transcript.split("\n")) {
    const file = FILE_SECTION.exec(line);
    const role = !file && ROLE.exec(line);
    if (file) {
      flush();
      current = { type: "file", label: file[1], body: "" };
    } else if (role) {
      flush();
      current = {
        type: "message",
        kind: entryKind(role[1]),
        label: `${roleNames[role[1]] || role[1]}${role[2]}`,
        body: "",
      };
    } else body.push(line);
  }
  flush();
  return entries;
}
