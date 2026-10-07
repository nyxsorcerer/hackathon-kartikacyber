import { expect, it } from "vitest";
import {
  entryLines,
  markdownLines,
  markerOf,
  outputLines,
  toolCall,
  visible,
} from "./transcriptRender";
import type { Span } from "./terminalText";

const text = (lines: Span[][]) =>
  lines.map((line) => line.map((span) => span.text).join(""));

it("styles markdown as a terminal does instead of rendering HTML", () => {
  const lines = markdownLines(
    [
      "## Findings",
      "The **parent** calls `h()` here, see [docs](https://x.test).",
      "- first",
      "1. step",
      "> quoted",
      "```diff",
      "+ added",
      "- removed",
      "```",
    ].join("\n"),
  );
  expect(text(lines)).toEqual([
    "Findings",
    "The parent calls h() here, see docs.",
    "• first",
    "1. step",
    "▎ quoted",
    "```diff",
    "+ added",
    "- removed",
    "```",
  ]);
  expect(lines[0][0].style).toMatchObject({ fontWeight: 700 });
  expect(lines[1].find((s) => s.text === "parent")?.style).toEqual({
    fontWeight: 700,
  });
  expect(lines[1].find((s) => s.text === "h()")?.style).toEqual({
    color: "var(--ansi-12)",
  });
  expect(lines[6][0].style).toEqual({ color: "var(--ansi-2)" });
  expect(lines[7][0].style).toEqual({ color: "var(--ansi-1)" });
  // Underscores in identifiers and dunder names are never emphasis.
  const dunder = markdownLines("set my_value_here from Path(__file__).parent");
  expect(text(dunder)).toEqual([
    "set my_value_here from Path(__file__).parent",
  ]);
  expect(dunder[0].every((span) => !span.style)).toBe(true);
});

it("keeps a program's own colors and marks failed exits", () => {
  expect(outputLines("\x1b[32mok\x1b[0m")[0]).toEqual([
    { text: "ok", style: { color: "var(--ansi-2)" } },
  ]);
  expect(outputLines("exit=2\nboom")[0][0].style).toEqual({
    color: "var(--ansi-1)",
  });
  expect(outputLines("exit=0")[0][0].style).toEqual({ color: "var(--ansi-8)" });
});

it("shows a tool call as name(argument) with other arguments beneath", () => {
  const call = toolCall(
    "Tool call · Bash",
    JSON.stringify({
      command: "ls -la /workspace",
      description: "List workspace",
    }),
  );
  expect(call.name).toBe("Bash");
  expect(call.summary).toBe("ls -la /workspace");
  expect(text(call.rest)).toEqual(["description: List workspace"]);
  const head = entryLines({
    type: "message",
    kind: "call",
    label: "Tool call · Bash",
    body: JSON.stringify({ command: "ls" }),
  })[0];
  expect(head).toEqual([
    { text: "Bash", style: { fontWeight: 700 } },
    { text: "(ls)" },
  ]);
});

it("gives each kind of entry its terminal marker and skips empty wrappers", () => {
  const entry = (
    kind: "assistant" | "user" | "call" | "output" | "note",
    label = "",
  ) => ({ type: "message", kind, label, body: "x" }) as const;
  expect(markerOf(entry("assistant"))?.symbol).toBe("●");
  expect(markerOf(entry("call"))?.style).toEqual({ color: "var(--ansi-2)" });
  expect(markerOf(entry("output"))).toMatchObject({ symbol: "⎿", indent: 5 });
  expect(markerOf(entry("note", "Reasoning"))?.symbol).toBe("✻");
  expect(
    visible({ type: "message", kind: "user", label: "User", body: "  " }),
  ).toBe(false);
  expect(
    visible({
      type: "message",
      kind: "call",
      label: "Tool call · x",
      body: "",
    }),
  ).toBe(true);
});
