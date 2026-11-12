import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { VersionTab } from "./ApplicationDetail";
import type { Application } from "../types";

afterEach(() => vi.unstubAllGlobals());
const application = {
  id: "application-1",
  asset_name: "Customer portal",
  asset_url: "https://portal.example.test",
  product_kind: "cms",
  product_name: "Example CMS",
  source_kind: "github",
  source_url: "https://github.com/example/cms",
  source_ref: "main",
  monitor_interval_seconds: 604800,
  monitor_enabled: true,
  archived: false,
  source_generation: 1,
  last_check_at: null,
  next_check_at: null,
  last_error: null,
  version: null,
  config: {
    profiles: {},
    triage_mode: "disabled",
    cve_selectors: [],
    cve_versions: [],
    cve_auto_analyze: false,
    active_recipe_id: "recipe-old",
  },
} as unknown as Application;
const coverage = (versions: string[], resolution: string[][]) => ({
  corpus_coverage: {
    releases: versions.map((version) => ({ version })),
    distinguishing_paths: versions.length ? 32 : 0,
    resolution,
    limitations: [],
    complete: false,
  },
});
function serve(activeRecipe: string) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const items = url.endsWith("/version-recipes")
        ? [
            {
              id: "recipe-new",
              created_at: "2026-10-06T00:00:00Z",
              status: activeRecipe === "recipe-new" ? "active" : "superseded",
              artifacts: [],
              metadata: coverage(
                ["9.5.4", "9.5.2", "9.5.1"],
                [["9.5.4"], ["9.5.2", "9.5.1"]],
              ),
            },
            {
              id: "recipe-old",
              created_at: "2026-10-04T00:00:00Z",
              status: activeRecipe === "recipe-old" ? "active" : "superseded",
              artifacts: [],
              metadata: coverage([], []),
            },
          ]
        : [
            {
              id: "observation-1",
              status: "ambiguous",
              version: null,
              candidates: ["9.5.2", "9.5.1"],
              method: "html_markers+release_fingerprints",
              origin: "script",
              checked_at: "2026-10-06T00:00:00Z",
              limitations: [],
              evidence: [
                "GET https://portal.example.test -> HTTP 200",
                {
                  url: "https://portal.example.test/concrete/js/cms.js",
                  path: "concrete/js/cms.js",
                  status: 200,
                  sha256: "a".repeat(64),
                  versions: ["9.5.2", "9.5.1"],
                },
                {
                  url: "https://portal.example.test/concrete/js/legacy.js",
                  path: "concrete/js/legacy.js",
                  status: 404,
                },
              ],
            },
          ];
      return new Response(JSON.stringify({ items, next_cursor: null }));
    }),
  );
}
function renderTab(activeRecipe: string) {
  serve(activeRecipe);
  render(
    <MemoryRouter>
      <VersionTab
        application={{
          ...application,
          config: { ...application.config, active_recipe_id: activeRecipe },
        }}
        onGenerate={() => {}}
        onManual={() => {}}
      />
    </MemoryRouter>,
  );
}

it("warns when the active recipe has no release fingerprints and shows each recipe's coverage", async () => {
  renderTab("recipe-old");
  expect(
    await screen.findByText("The active recipe has no release fingerprints"),
  ).toBeInTheDocument();
  expect(screen.getByText("No release fingerprints")).toBeInTheDocument();
  expect(
    screen.getByText("3 releases fingerprinted · 32 distinguishing files"),
  ).toBeInTheDocument();
  expect(
    screen.getByText(/9\.5\.2 and 9\.5\.1 publish identical files/),
  ).toBeInTheDocument();
});

it("lists which fetched files matched which releases", async () => {
  renderTab("recipe-new");
  const matches = await screen.findByText("Release fingerprints");
  const list = within(matches.parentElement!);
  expect(list.getByText("concrete/js/cms.js").parentElement).toHaveTextContent(
    "matches 9.5.2, 9.5.1",
  );
  expect(
    list.getByText("concrete/js/legacy.js").parentElement,
  ).toHaveTextContent("not served (HTTP 404)");
  expect(
    screen.queryByText("The active recipe has no release fingerprints"),
  ).not.toBeInTheDocument();
  expect(screen.getByText("9.5.2 / 9.5.1")).toBeInTheDocument();
});
