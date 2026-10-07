import { expect, it } from "vitest";
import {
  ansiLines,
  splitSession,
  stripAnsi,
  transcriptEntries,
} from "./terminalText";

it("keeps Herdr's terminal colors, intensity, and inverse video", () => {
  // Captured from `pane.read` with `format: "ansi"` on Herdr 0.9.3.
  const herdr =
    "\x1b[0m\x1b[1m\x1b[38;5;1mRED BOLD\x1b[0m plain \x1b[0m\x1b[38;5;46mgreen256\x1b[0m \x1b[0m\x1b[38;2;255;128;0mtruecolor\x1b[0m \x1b[0m\x1b[7mreverse\x1b[0m";
  expect(ansiLines(herdr)).toEqual([
    [
      { text: "RED BOLD", style: { color: "var(--ansi-1)", fontWeight: 700 } },
      { text: " plain " },
      { text: "green256", style: { color: "rgb(0, 255, 0)" } },
      { text: " " },
      { text: "truecolor", style: { color: "rgb(255, 128, 0)" } },
      { text: " " },
      {
        text: "reverse",
        style: {
          color: "var(--term-bg)",
          backgroundColor: "var(--term-fg)",
        },
      },
    ],
  ]);
});

it("carries style across lines, honours colon colors, and overwrites on carriage return", () => {
  const lines = ansiLines(
    "\x1b[32mok\nstill green\x1b[39m\n\x1b[38:2::1:2:3mx\x1b[m\n10%\r50%\r100%",
  );
  expect(lines[1]).toEqual([
    { text: "still green", style: { color: "var(--ansi-2)" } },
  ]);
  expect(lines[2]).toEqual([{ text: "x", style: { color: "rgb(1, 2, 3)" } }]);
  expect(lines[3]).toEqual([{ text: "100%" }]);
});

it("drops cursor control and titles instead of printing them", () => {
  expect(stripAnsi("a\x1b[2Kb\x1b]0;title\x07c\x1b[1mD\x1b[0m")).toBe("abcD");
  expect(ansiLines("a\x1b[2Kb\x1b]0;title\x07c")).toEqual([
    [{ text: "a" }, { text: "b" }, { text: "c" }],
  ]);
});

it("separates the conversation from the latest terminal view", () => {
  const transcript = [
    "=== session-transcripts/pi/run.jsonl ===",
    "[user]",
    "Analyze the commit",
    "",
    "[tool call · numen_shell]",
    '{"command": "echo \\"=== controller ===\\""}',
    "",
    "[toolResult · numen_shell]",
    "=== controller ===",
    "class Controller {}",
    "",
    "[assistant]",
    "Done.",
  ].join("\n");
  const session = splitSession(
    `${transcript}\n\n=== Latest terminal view ===\n\x1b[1m> \x1b[0mready`,
  );
  expect(session.terminal).toBe("\x1b[1m> \x1b[0mready");
  expect(transcriptEntries(session.transcript || "")).toEqual([
    { type: "file", label: "session-transcripts/pi/run.jsonl", body: "" },
    {
      type: "message",
      kind: "user",
      label: "User",
      body: "Analyze the commit",
    },
    {
      type: "message",
      kind: "call",
      label: "Tool call · numen_shell",
      body: '{"command": "echo \\"=== controller ===\\""}',
    },
    {
      type: "message",
      kind: "output",
      label: "Tool result · numen_shell",
      body: "=== controller ===\nclass Controller {}",
    },
    { type: "message", kind: "assistant", label: "Assistant", body: "Done." },
  ]);
  expect(splitSession("plain output")).toEqual({ terminal: "plain output" });
});
