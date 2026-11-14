import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { ArtifactBrowser } from "./ArtifactPreview";
afterEach(() => vi.unstubAllGlobals());
it("opens the audit entry report and resolves supporting document links inside its artifact revision", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (url: string) =>
        new Response(
          url.includes("/entry/")
            ? "# Audit context\n\n[Inspect function](functions/check.md)"
            : "# Function assumptions\n\nPinned source evidence",
          { headers: { "Content-Type": "text/plain" } },
        ),
    ),
  );
  render(
    <ArtifactBrowser
      artifacts={[
        {
          id: "function",
          path: "functions/check.md",
          size: 40,
          sha256: "b".repeat(64),
        },
        {
          id: "entry",
          path: "audit-context-building.md",
          size: 50,
          sha256: "a".repeat(64),
        },
      ]}
    />,
  );
  expect(
    await screen.findByRole("heading", { name: "Audit context" }),
  ).toBeInTheDocument();
  await userEvent
    .setup()
    .click(screen.getByRole("link", { name: "Inspect function" }));
  expect(
    await screen.findByRole("heading", { name: "Function assumptions" }),
  ).toBeInTheDocument();
  expect(screen.getByText("Pinned source evidence")).toBeInTheDocument();
});

it("opens the main report and finds files in a large app without rendering the whole bundle", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (url: string) =>
        new Response(
          url.includes("/report/") ? "# Main report" : "<?php echo 'proof';",
        ),
    ),
  );
  const file = (id: string, path: string) => ({
    id,
    path,
    size: 30,
    sha256: "a".repeat(64),
  });
  render(
    <ArtifactBrowser
      grouped
      artifacts={[
        file("nested-report", "vulnerable-app/docs/report.md"),
        ...Array.from({ length: 300 }, (_, i) =>
          file(`file-${i}`, `vulnerable-app/src/file-${i}.php`),
        ),
        file("report", "report.md"),
      ]}
    />,
  );
  expect(
    await screen.findByRole("heading", { name: "Main report" }),
  ).toBeInTheDocument();
  const user = userEvent.setup();
  await user.click(screen.getByRole("tab", { name: /Vulnerable app/ }));
  expect(
    screen.queryByRole("button", { name: "vulnerable-app/src/file-299.php" }),
  ).not.toBeInTheDocument();
  await user.type(
    screen.getByRole("searchbox", { name: "Search artifact files" }),
    "file-299",
  );
  await user.click(
    screen.getByRole("button", { name: "vulnerable-app/src/file-299.php" }),
  );
  expect(await screen.findByText("<?php echo 'proof';")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Download file" })).toHaveAttribute(
    "href",
    "/api/artifacts/file-299/content",
  );
});

it("follows report links across artifact groups and exposes supporting files", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (url: string) =>
        new Response(
          url.includes("/report/")
            ? "# Report\n\n[Run the app](vulnerable-app/README.md)"
            : "# Reproduction steps",
        ),
    ),
  );
  render(
    <ArtifactBrowser
      grouped
      artifacts={[
        { id: "report", path: "report.md", size: 100, sha256: "a".repeat(64) },
        {
          id: "readme",
          path: "vulnerable-app/README.md",
          size: 30,
          sha256: "b".repeat(64),
        },
        {
          id: "manifest",
          path: "manifest.json",
          size: 20,
          sha256: "c".repeat(64),
        },
      ]}
    />,
  );
  await userEvent
    .setup()
    .click(await screen.findByRole("link", { name: "Run the app" }));
  expect(
    await screen.findByRole("heading", { name: "Reproduction steps" }),
  ).toBeInTheDocument();
  expect(screen.getByRole("tab", { name: /Vulnerable app/ })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  expect(
    screen.getByRole("tab", { name: /Supporting files/ }),
  ).toBeInTheDocument();
});

it("retries a failed preview and lets the reader inspect Markdown source", async () => {
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(new Response("Unavailable", { status: 503 }))
    .mockResolvedValue(new Response("# Saved report\n\nFull **evidence**"));
  vi.stubGlobal("fetch", fetch);
  render(
    <ArtifactBrowser
      artifacts={[
        { id: "report", path: "report.md", size: 40, sha256: "a".repeat(64) },
      ]}
    />,
  );
  const user = userEvent.setup();
  await user.click(
    await screen.findByRole("button", { name: "Retry preview" }),
  );
  expect(
    await screen.findByRole("heading", { name: "Saved report" }),
  ).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Source" }));
  expect(screen.getByText(/# Saved report/)).toBeInTheDocument();
  expect(
    screen.queryByRole("heading", { name: "Saved report" }),
  ).not.toBeInTheDocument();
});

it("never offers an Upstream Proof for download and previews only its reports (A15)", async () => {
  const fetch = vi.fn(
    async (url: string) =>
      new Response(url.includes("/report/") ? "# Upstream report" : "print()"),
  );
  vi.stubGlobal("fetch", fetch);
  render(
    <ArtifactBrowser
      exportable={false}
      artifacts={[
        { id: "report", path: "report.md", size: 40, sha256: "a".repeat(64) },
        { id: "poc", path: "poc.py", size: 20, sha256: "b".repeat(64) },
        {
          id: "readme",
          path: "vulnerable-app/README.md",
          size: 20,
          sha256: "c".repeat(64),
        },
      ]}
    />,
  );
  expect(
    await screen.findByRole("heading", { name: "Upstream report" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("link", { name: "Download file" }),
  ).not.toBeInTheDocument();
  const user = userEvent.setup();
  // Only its reports: not even the bundle's Markdown README is read.
  for (const name of ["poc.py", "vulnerable-app/README.md"]) {
    await user.click(screen.getByRole("button", { name }));
    expect(
      await screen.findByText(
        "Upstream Proofs are never exported, so only their reports are shown.",
      ),
    ).toBeInTheDocument();
  }
  expect(
    screen.queryByRole("link", { name: "Download file" }),
  ).not.toBeInTheDocument();
  expect(fetch.mock.calls.map(([url]) => url)).toEqual([
    "/api/artifacts/report/content",
  ]);
});
