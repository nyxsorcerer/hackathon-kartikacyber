import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { PromptTemplates } from "./PromptTemplates";

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});
function template(
  name: string,
  kind: "operation" | "section",
  source: string,
  extra: Record<string, unknown> = {},
) {
  return {
    name,
    kind,
    description: `${name} description`,
    source,
    default_source: source,
    customized: false,
    updated_at: null,
    default_changed: false,
    includes: [],
    used_by: [],
    ...extra,
  };
}
function fixture() {
  const items = [
    template("attack-path", "section", "## Attack path\nTrace the source.", {
      used_by: ["commit_analysis", "cve_analysis"],
    }),
    template("commit_analysis", "operation", '{% include "attack-path" %}', {
      includes: ["attack-path"],
    }),
    template("cve_analysis", "operation", '{% include "attack-path" %}', {
      includes: ["attack-path"],
    }),
  ];
  const requests: { method: string; url: string; body?: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method || "GET";
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      requests.push({ method, url, body });
      if (url === "/api/prompts/preview")
        return new Response(
          JSON.stringify({
            prompt: `Rendered ${body.operation}: ${body.source}`,
            templates: ["attack-path", body.operation],
            build: true,
          }),
        );
      if (url.startsWith("/api/prompts/")) {
        const name = decodeURIComponent(url.split("/").at(-1)!);
        const index = items.findIndex((t) => t.name === name);
        items[index] =
          method === "DELETE"
            ? { ...items[index], source: items[index].default_source }
            : { ...items[index], source: body.source };
        items[index].customized = method !== "DELETE";
        return new Response(JSON.stringify(items[index]));
      }
      return new Response(
        JSON.stringify({
          items,
          variables: { operation: "The operation's name." },
        }),
      );
    }),
  );
  return requests;
}

it("edits a shared section, previews the draft in an operation, and saves it", async () => {
  const requests = fixture();
  render(
    <MemoryRouter initialEntries={["/settings?tab=prompts"]}>
      <PromptTemplates />
    </MemoryRouter>,
  );
  const user = userEvent.setup();
  // The first operation opens by default; its sections are one click away.
  expect(
    await screen.findByRole("heading", { name: "Commit analysis" }),
  ).toBeInTheDocument();
  const nav = screen.getByRole("navigation", { name: "Prompt templates" });
  await user.click(within(nav).getByRole("button", { name: "attack-path" }));
  expect(
    screen.getByRole("heading", { name: "attack-path" }),
  ).toBeInTheDocument();
  const editor = screen.getByLabelText("Template");
  await user.type(editor, "\nName the CWE.");
  expect(within(nav).getByText("Unsaved")).toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText("Render in"), "cve_analysis");
  await user.click(screen.getByRole("button", { name: "Preview" }));
  expect(
    await screen.findByText(/Rendered cve_analysis: .*Name the CWE\./s),
  ).toBeInTheDocument();
  // Switching away keeps the draft.
  await user.click(within(nav).getByRole("button", { name: /CVE analysis/ }));
  await user.click(within(nav).getByRole("button", { name: /attack-path/ }));
  expect(screen.getByLabelText("Template")).toHaveValue(
    "## Attack path\nTrace the source.\nName the CWE.",
  );
  await user.click(screen.getByRole("button", { name: "Save template" }));
  expect(await within(nav).findByText("Customized")).toBeInTheDocument();
  expect(within(nav).queryByText("Unsaved")).not.toBeInTheDocument();
  expect(requests).toContainEqual({
    method: "PUT",
    url: "/api/prompts/attack-path",
    body: { source: "## Attack path\nTrace the source.\nName the CWE." },
  });
  expect(requests).toContainEqual({
    method: "POST",
    url: "/api/prompts/preview",
    body: {
      operation: "cve_analysis",
      name: "attack-path",
      source: "## Attack path\nTrace the source.\nName the CWE.",
    },
  });
  // Reset asks for a second click before discarding the operator's version.
  await user.click(screen.getByRole("button", { name: "Reset to default" }));
  await user.click(screen.getByRole("button", { name: "Reset to default?" }));
  expect(await screen.findByText("Default")).toBeInTheDocument();
  expect(screen.getByLabelText("Template")).toHaveValue(
    "## Attack path\nTrace the source.",
  );
  expect(requests.at(-2)).toMatchObject({
    method: "DELETE",
    url: "/api/prompts/attack-path",
  });
});

it("keeps an unsaved draft when the editor is left and opened again", async () => {
  fixture();
  const view = render(
    <MemoryRouter initialEntries={["/settings?tab=prompts&prompt=attack-path"]}>
      <PromptTemplates />
    </MemoryRouter>,
  );
  const user = userEvent.setup();
  await user.type(
    await screen.findByRole("textbox", { name: "Template" }),
    "\nKeep me.",
  );
  // Another Settings tab or page unmounts the editor.
  view.unmount();
  render(
    <MemoryRouter initialEntries={["/settings?tab=prompts&prompt=attack-path"]}>
      <PromptTemplates />
    </MemoryRouter>,
  );
  expect(await screen.findByRole("textbox", { name: "Template" })).toHaveValue(
    "## Attack path\nTrace the source.\nKeep me.",
  );
  const nav = screen.getByRole("navigation", { name: "Prompt templates" });
  expect(within(nav).getByText("Unsaved")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Discard changes" }));
  expect(sessionStorage.getItem("numen:prompt-drafts")).toBeNull();
});
