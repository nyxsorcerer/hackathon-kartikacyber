import { describe, expect, it } from "vitest";
import { commitSchema } from "./types";
import { splitDiff } from "./pages/Commits";
import { cveRows } from "./pages/CVEs";
import { failureGroups } from "./pages/Jobs";
import { matches, severityOf } from "./components/ui";
const commit = {
  id: "c",
  application_id: "p",
  revision: "abc",
  message: "m",
  diff_complete: true,
  triage_status: "baseline",
  triage_result: null,
  review_decision: "pending",
};
describe("commit records", () => {
  it("accepts changed files as source-import objects or bare paths", () => {
    const imported = commitSchema.parse({
      ...commit,
      files: [{ path: "a.js", status: "modified", previous_path: null }],
    });
    const bare = commitSchema.parse({ ...commit, files: ["b.js"] });
    expect(imported.files[0]).toEqual({
      path: "a.js",
      status: "modified",
      previous_path: null,
    });
    expect(bare.files[0]).toEqual({
      path: "b.js",
      status: null,
      previous_path: null,
    });
  });
});
describe("diff navigation", () => {
  it("splits GitHub patches joined with ---/+++ headers", () => {
    const files = splitDiff(
      [
        "--- src/a.php",
        "+++ src/a.php",
        "@@ -1 +1 @@",
        "-old",
        "+new",
        "--- /dev/null",
        "+++ src/b.php",
        "@@ -0,0 +1 @@",
        "+added",
      ].join("\n"),
    );
    expect(files.map((f) => [f.path, f.adds, f.dels])).toEqual([
      ["src/a.php", 1, 1],
      ["src/b.php", 1, 0],
    ]);
  });
  it("keeps a git header and its ---/+++ pair in one section", () => {
    const files = splitDiff(
      [
        "diff --git a/x.py b/x.py",
        "index 1..2 100644",
        "--- a/x.py",
        "+++ b/x.py",
        "@@ -1 +1 @@",
        "+y",
      ].join("\n"),
    );
    expect(files).toHaveLength(1);
    expect(files[0].path).toBe("x.py");
  });
});
describe("CVE exploring", () => {
  it("rates severity from v3/v4 scores only, treating v2-only as unscored", () => {
    const base = {
      application_id: "p",
      title: "t",
      description: "d",
      match_status: "confirmed",
      eligible: false,
      applicability: "unknown",
      affected_versions: [],
      fixed_versions: [],
      references: [],
      analyses: [],
    };
    const [legacy, modern] = cveRows([
      {
        ...base,
        id: "CVE-2014-1",
        scores: [{ version: "2.0", base_score: 9.3, vector: "v", source: "s" }],
      },
      {
        ...base,
        id: "CVE-2024-1",
        scores: [
          { version: "2.0", base_score: 5, vector: "v", source: "s" },
          { version: "3.1", base_score: 9.8, vector: "v", source: "s" },
        ],
      },
    ]);
    expect(legacy.severity).toBe("none");
    expect(modern.best).toBe(9.8);
    expect(modern.severity).toBe("critical");
    expect(severityOf(7)).toBe("high");
  });
  it("matches every search term across fields, ignoring case", () => {
    expect(matches("xss concrete", "Stored XSS", "in Concrete CMS")).toBe(true);
    expect(matches("xss sqli", "Stored XSS")).toBe(false);
    expect(matches("  ", "anything")).toBe(true);
  });
});
describe("job failures", () => {
  it("groups failed jobs by reported reason, most frequent first", () => {
    const job = (id: string, status: string, message?: string) => ({
      id,
      kind: "cve_analysis",
      status,
      progress: {},
      created_at: `2026-10-0${id}T00:00:00Z`,
      error: message ? { message } : null,
      result: null,
      events: [],
    });
    const groups = failureGroups([
      job("1", "failed", "Snapshot limit"),
      job("2", "failed", "Source check required"),
      job("3", "failed", "Source check required"),
      job("4", "succeeded"),
    ]);
    expect(groups.map((g) => [g.reason, g.count])).toEqual([
      ["Source check required", 2],
      ["Snapshot limit", 1],
    ]);
    expect(groups[0].latest).toBe("2026-10-03T00:00:00Z");
  });
});
