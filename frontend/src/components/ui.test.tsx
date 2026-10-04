import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DataState, Empty, Markdown } from "./ui";
describe("shared response states", () => {
  it("reports an API failure without claiming the inventory is empty", () => {
    render(
      <DataState loading={false} error="Source unavailable" retry={vi.fn()}>
        <Empty title="No records" />
      </DataState>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Source unavailable");
    expect(screen.queryByText("No records")).not.toBeInTheDocument();
  });
  it("renders untrusted report HTML as text and rejects active link destinations", () => {
    render(
      <Markdown>
        {"<script>alert(1)</script>\n\n[Bad link](javascript:alert(1))"}
      </Markdown>,
    );
    expect(document.querySelector("script")).toBeNull();
    expect(
      screen.queryByRole("link", { name: "Bad link" }),
    ).not.toBeInTheDocument();
  });
});
describe("report Markdown", () => {
  it("renders GitHub tables, strikethrough, and task lists", () => {
    render(
      <Markdown>
        {[
          "| Item | Value |",
          "|---|---|",
          "| Affected | 6.5.3 |",
          "| Fixed | 6.5.4 |",
          "",
          "~~Old claim~~",
          "",
          "- [x] Reproduced",
        ].join("\n")}
      </Markdown>,
    );
    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(
      screen.getAllByRole("columnheader").map((cell) => cell.textContent),
    ).toEqual(["Item", "Value"]);
    expect(screen.getByRole("cell", { name: "6.5.4" })).toBeInTheDocument();
    expect(screen.getByText("Old claim").tagName).toBe("DEL");
    expect(screen.getByRole("checkbox")).toBeChecked();
    expect(screen.queryByText(/\|---\|/)).not.toBeInTheDocument();
  });
  it("opens bare URLs externally and keeps footnote links on the page", () => {
    render(
      <Markdown>
        {
          "See https://wordpress.org/news/ for details.[^1]\n\n[^1]: Vendor advisory."
        }
      </Markdown>,
    );
    const external = screen.getByRole("link", { name: /wordpress\.org/ });
    expect(external).toHaveAttribute("target", "_blank");
    expect(external).toHaveAttribute("rel", "noreferrer");
    const footnote = screen.getByRole("link", { name: "1" });
    expect(footnote.getAttribute("href")).toMatch(/^#/);
    expect(footnote).not.toHaveAttribute("target");
  });
});
