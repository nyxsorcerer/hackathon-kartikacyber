import { describe, expect, it } from "vitest";
import { openQuestions, organizeDocs } from "./AuditContext";
const artifact = (path: string) => ({
  id: path,
  path,
  size: 10,
  sha256: "a".repeat(64),
});
describe("audit context reading", () => {
  it("extracts bullets under the Open questions heading only", () => {
    const report = [
      "# Audit context building",
      "- [wp_kses_attr](functions/001.md)",
      "## Open questions",
      "- Does `wp_kses_hair` lower-case names?",
      "1. Which filters run on REST content?",
      "## Next section",
      "- Not a question",
    ].join("\n");
    expect(openQuestions(report)).toEqual([
      "Does `wp_kses_hair` lower-case names?",
      "Which filters run on REST content?",
    ]);
  });
  it("names function documents from orientation and marks failed and unreached units", () => {
    const groups = organizeDocs(
      [
        artifact("audit-context-building.md"),
        artifact("audit-context/DOSSIER.md"),
        artifact("functions/001.md"),
        artifact("coverage.json"),
        artifact("audit-functions.json"),
      ],
      {
        failed_units: [
          {
            unit: { id: "b", name: "esc_url", path: "f.php" },
            error: "Path missing",
          },
        ],
      },
      {
        functions: [
          { id: "a", name: "wp_kses_attr", path: "kses.php" },
          { id: "b", name: "esc_url", path: "f.php" },
          { id: "c", name: "wp_insert_post", path: "post.php" },
        ],
      },
      undefined,
    );
    expect(groups.overview.map((d) => d.label)).toEqual([
      "Entry report",
      "System dossier",
    ]);
    expect(
      groups.functions.map((d) => [d.label, d.detail, d.state, d.error]),
    ).toEqual([
      ["wp_kses_attr", "kses.php", "ready", undefined],
      ["esc_url", "f.php", "failed", "Path missing"],
      ["wp_insert_post", "post.php", "pending", undefined],
    ]);
    expect(groups.supporting.map((d) => d.label)).toEqual(["coverage.json"]);
  });
  it("falls back to entry-report link text when orientation is unavailable", () => {
    const groups = organizeDocs(
      [artifact("functions/001.md")],
      {},
      {},
      "- [AccessManager::check](functions/001.md)",
    );
    expect(groups.functions.map((d) => d.label)).toEqual([
      "AccessManager::check",
    ]);
  });
});
