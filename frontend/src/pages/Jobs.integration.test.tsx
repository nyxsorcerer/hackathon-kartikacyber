import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { JobDetail } from "./Jobs";
import { AnalysisHistory } from "./Commits";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it.each(["succeeded", "failed"])(
  "links a %s CVE job to its report and retained finding bundle",
  async (status) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        const body = url.endsWith("/events")
          ? { items: [], next_cursor: null }
          : {
              id: "job-1",
              kind: "cve_analysis",
              program_id: "program-1",
              status,
              progress: {},
              created_at: "2026-10-04T00:00:00Z",
              error: status === "failed" ? { message: "Missing PoC" } : null,
              result: {
                cve_id: "CVE-2026-12345",
                analysis_id: "analysis-1",
                finding_id: "finding-1",
              },
            };
        return new Response(JSON.stringify(body), {
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    render(
      <MemoryRouter initialEntries={["/jobs/job-1"]}>
        <Routes>
          <Route path="/jobs/:id" element={<JobDetail />} />
        </Routes>
      </MemoryRouter>,
    );
    expect(
      await screen.findByRole("link", { name: "View CVE analysis and report" }),
    ).toHaveAttribute(
      "href",
      "/cves?program_id=program-1&cve_id=CVE-2026-12345",
    );
    expect(
      screen.getByRole("link", { name: "View finding artifacts" }),
    ).toHaveAttribute("href", "/findings/finding-1");
  },
);

it("links the CVE analysis history to its generated finding", () => {
  render(
    <MemoryRouter>
      <AnalysisHistory
        programId="program-1"
        analyses={[
          {
            id: "analysis-1",
            result: { summary: "CVE investigation", finding_id: "finding-1" },
          },
        ]}
      />
    </MemoryRouter>,
  );
  expect(
    screen.getByRole("link", { name: "View finding artifacts" }),
  ).toHaveAttribute("href", "/findings/finding-1");
});
