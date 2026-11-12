/**
 * Draws saved conversation entries the way an agent's terminal does: a marker in
 * the gutter, light markdown styling (not rendered HTML), tool calls as
 * `name(argument)`, and output dimmed beneath them. Colors come from the same
 * 16-color palette as the live terminal.
 */
import type { CSSProperties } from "react";
import { ansiLines, hasEscapes } from "./terminalText";
import type { Entry, Span } from "./terminalText";

const ansi = (n: number) => `var(--ansi-${n})`;
const DIM: CSSProperties = { color: ansi(8) };
const CODE: CSSProperties = { color: ansi(12) };
const BOLD: CSSProperties = { fontWeight: 700 };

// **bold**, `code`, [text](url), *italic*. Underscores are never emphasis: they
// appear in identifiers and dunder names (__file__) far more often.
const INLINE =
  /\*\*([^*\n]+)\*\*|`([^`\n]+)`|\[([^\]\n]+)\]\(([^)\s]+)\)|\*([^*\s][^*\n]*?)\*/g;

function inline(text: string, base?: CSSProperties): Span[] {
  const spans: Span[] = [];
  const push = (value: string, style?: CSSProperties) => {
    if (!value) return;
    const merged = base || style ? { ...base, ...style } : undefined;
    spans.push(merged ? { text: value, style: merged } : { text: value });
  };
  let last = 0;
  for (const match of text.matchAll(INLINE)) {
    push(text.slice(last, match.index), undefined);
    last = match.index + match[0].length;
    const [, bold, code, link, , italic] = match;
    if (bold !== undefined) push(bold, BOLD);
    else if (code !== undefined) push(code, CODE);
    else if (link !== undefined)
      push(link, { color: ansi(4), textDecoration: "underline" });
    else push(italic, { fontStyle: "italic" });
  }
  push(text.slice(last), undefined);
  return spans;
}

/** Diff-shaped text colors its added, removed, and hunk lines. */
function looksLikeDiff(text: string) {
  return /^(diff --git |@@ |--- a\/)/m.test(text) && /^@@ /m.test(text);
}
function diffLine(line: string): Span[] {
  if (!line) return [];
  if (/^(diff --git|index |\+\+\+ |--- )/.test(line))
    return [{ text: line, style: BOLD }];
  if (line.startsWith("@@")) return [{ text: line, style: { color: ansi(6) } }];
  if (line.startsWith("+")) return [{ text: line, style: { color: ansi(2) } }];
  if (line.startsWith("-")) return [{ text: line, style: { color: ansi(1) } }];
  return [{ text: line }];
}

/** Markdown drawn as a terminal draws it: styled text, never HTML structure. */
export function markdownLines(text: string, base?: CSSProperties): Span[][] {
  if (hasEscapes(text)) return ansiLines(text);
  const lines: Span[][] = [];
  let fence: string | undefined;
  let diff = false;
  for (const line of text.split("\n")) {
    const marker = /^\s*(```|~~~)\s*([\w+-]*)/.exec(line);
    if (marker && (!fence || marker[1] === fence)) {
      fence = fence ? undefined : marker[1];
      diff = !!fence && marker[2] === "diff";
      lines.push([{ text: line, style: DIM }]);
      continue;
    }
    if (fence) {
      lines.push(
        diff
          ? diffLine(line)
          : line
            ? [{ text: line, style: { color: ansi(7) } }]
            : [],
      );
      continue;
    }
    const heading = /^#{1,6}\s+(.*)$/.exec(line);
    const quote = /^\s*>\s?(.*)$/.exec(line);
    const bullet = /^(\s*)[-*+]\s+(.*)$/.exec(line);
    const numbered = /^(\s*)(\d+[.)])\s+(.*)$/.exec(line);
    if (heading) lines.push(inline(heading[1], { ...base, ...BOLD }));
    else if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line))
      lines.push([{ text: "─".repeat(40), style: DIM }]);
    else if (quote)
      lines.push([
        { text: "▎ ", style: DIM },
        ...inline(quote[1], { ...base, fontStyle: "italic", color: ansi(7) }),
      ]);
    else if (bullet)
      lines.push([
        { text: `${bullet[1]}• `, style: DIM },
        ...inline(bullet[2], base),
      ]);
    else if (numbered)
      lines.push([
        { text: `${numbered[1]}${numbered[2]} `, style: DIM },
        ...inline(numbered[3], base),
      ]);
    else lines.push(inline(line, base));
  }
  return lines;
}

/** Tool output: the tool's own colors when present, diffs and exit codes otherwise. */
export function outputLines(text: string): Span[][] {
  if (hasEscapes(text)) return ansiLines(text);
  const diff = looksLikeDiff(text);
  return text.split("\n").map((line) => {
    const exit = /^exit=(\d+)$/.exec(line);
    if (exit)
      return [
        { text: line, style: exit[1] === "0" ? DIM : { color: ansi(1) } },
      ];
    if (diff) return diffLine(line);
    return line ? [{ text: line }] : [];
  });
}

// The argument that says what a call does, in the order agents' tools use them.
const PRIMARY = [
  "command",
  "cmd",
  "file_path",
  "path",
  "pattern",
  "query",
  "url",
  "prompt",
  "description",
];

/** `name(argument)` for the first line, other arguments dimmed beneath it. */
export function toolCall(label: string, body: string) {
  const name = label.includes(" · ")
    ? label.slice(label.indexOf(" · ") + 3)
    : label;
  let args: unknown;
  try {
    args = JSON.parse(body);
  } catch {
    args = undefined;
  }
  if (typeof args !== "object" || args === null || Array.isArray(args))
    return { name, summary: "", rest: body ? outputLines(body) : [] };
  const values = args as Record<string, unknown>;
  const key = PRIMARY.find((k) => typeof values[k] === "string");
  const primary = key ? String(values[key]).split("\n") : [];
  const rest: Span[][] = primary.slice(1).map((line) => [{ text: line }]);
  for (const [k, v] of Object.entries(values)) {
    if (k === key) continue;
    const value = typeof v === "string" ? v : JSON.stringify(v, null, 2);
    value
      .split("\n")
      .forEach((line, i) =>
        rest.push([{ text: i ? `  ${line}` : `${k}: ${line}`, style: DIM }]),
      );
  }
  return { name, summary: primary[0] || "", rest };
}

export type Marker = { symbol: string; style: CSSProperties; indent: number };
/** The gutter symbol and indent for an entry, as the agent's terminal shows them. */
export function markerOf(entry: Entry): Marker | undefined {
  if (entry.type !== "message") return undefined;
  switch (entry.kind) {
    case "assistant":
      return { symbol: "●", style: { color: ansi(15) }, indent: 2 };
    case "user":
      return { symbol: ">", style: DIM, indent: 2 };
    case "call":
      return { symbol: "●", style: { color: ansi(2) }, indent: 2 };
    case "output":
      return { symbol: "⎿", style: DIM, indent: 5 };
    default:
      return entry.label.startsWith("Reasoning")
        ? { symbol: "✻", style: { color: ansi(5) }, indent: 2 }
        : { symbol: "·", style: DIM, indent: 2 };
  }
}

/** The lines an entry draws, before any folding. */
export function entryLines(entry: Entry): Span[][] {
  if (entry.type === "file") {
    const rule = [{ text: `── ${entry.label} ──`, style: DIM }];
    return [
      rule,
      ...(entry.body
        ? outputLines(entry.body).map((l) =>
            l.map((s) => ({ ...s, style: { ...DIM, ...s.style } })),
          )
        : []),
    ];
  }
  if (entry.type === "text") return outputLines(entry.body);
  switch (entry.kind) {
    case "assistant":
      return markdownLines(entry.body);
    case "user":
      return markdownLines(entry.body, { color: ansi(7) });
    case "call": {
      const call = toolCall(entry.label, entry.body);
      const head: Span[] = [{ text: call.name, style: BOLD }];
      if (call.summary) head.push({ text: `(${call.summary})` });
      return [head, ...call.rest];
    }
    case "output":
      return outputLines(entry.body);
    default:
      return entry.label.startsWith("Reasoning")
        ? markdownLines(entry.body, { fontStyle: "italic", color: ansi(8) })
        : markdownLines(entry.body, DIM);
  }
}

/** Wrapper records with nothing to show (a role around a tool block) are skipped. */
export function visible(entry: Entry) {
  return (
    entry.type !== "message" || entry.kind === "call" || !!entry.body.trim()
  );
}
