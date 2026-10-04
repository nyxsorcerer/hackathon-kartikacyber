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
