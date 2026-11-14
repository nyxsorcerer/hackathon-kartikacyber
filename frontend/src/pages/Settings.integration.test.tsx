import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { Settings } from "./Settings";

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

it("lists the pinned Pi plugins with no install, enable, upload or remove action", async () => {
  const integrity = "sha512-fixtureIntegrityHashOfThePinnedPackage==";
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            items: [
              {
                id: "pi-commandcode-provider",
                name: "Command Code provider",
                version: "0.7.8",
                source: "https://github.com/patlux/pi-commandcode-provider",
                health: "ready",
                provider_contribution: "commandcode",
                integrity,
              },
            ],
            next_cursor: null,
          }),
        ),
    ),
  );
  render(
    <MemoryRouter initialEntries={["/settings?tab=plugins"]}>
      <Settings />
    </MemoryRouter>,
  );
  const card = (
    await screen.findByRole("heading", { name: "Command Code provider" })
  ).closest("article")!;
  expect(within(card).getByText("0.7.8")).toBeInTheDocument();
  expect(within(card).getByText(integrity)).toBeInTheDocument();
  expect(within(card).queryAllByRole("button")).toEqual([]);
  expect(
    screen.queryByRole("button", {
      name: /install|enable|disable|upload|remove/i,
    }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByText(/editing runner\/plugins\.lock\.json and rebuilding/),
  ).toBeInTheDocument();
});
