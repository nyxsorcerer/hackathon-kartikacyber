import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ProfileSelect } from "./ProfileSelect";
const accounts = [
  {
    id: "api",
    label: "OpenAI API",
    provider: "openai",
    auth_type: "api_key",
    supported_agents: ["pi", "codex"],
    status: "ready",
    credential_configured: true,
    models: [
      {
        id: "native-model",
        name: "Native model",
        reasoning_efforts: ["low", "xhigh"],
        default_effort: "xhigh",
      },
    ],
    usage: null,
    last_checked_at: null,
  },
  {
    id: "chatgpt",
    label: "ChatGPT",
    provider: "openai",
    auth_type: "native_oauth",
    supported_agents: ["codex"],
    status: "ready",
    credential_configured: true,
    models: [
      {
        id: "chat-model",
        name: "Chat model",
        reasoning_efforts: [],
        default_effort: null,
      },
    ],
    usage: null,
    last_checked_at: null,
  },
];
describe("ProfileSelect", () => {
  it("offers only compatible connections and preserves native effort values", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(
      <ProfileSelect
        accounts={accounts}
        value={{
          agent: "codex",
          connection_id: "api",
          model_id: "native-model",
          reasoning_effort: "xhigh",
        }}
        onChange={onChange}
      />,
    );
    expect(screen.getByLabelText("Reasoning effort")).toHaveValue("xhigh");
    expect(screen.getByRole("option", { name: "xhigh" })).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Account"), "chatgpt");
    expect(onChange).toHaveBeenLastCalledWith({
      agent: "codex",
      connection_id: "chatgpt",
      model_id: "chat-model",
      reasoning_effort: null,
    });
  });
  it("clears unavailable model selections when changing agent", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    const { rerender } = render(
      <ProfileSelect
        accounts={accounts}
        value={{
          agent: "codex",
          connection_id: "chatgpt",
          model_id: "chat-model",
          reasoning_effort: null,
        }}
        onChange={onChange}
      />,
    );
    await user.selectOptions(screen.getByLabelText("Agent runtime"), "claude");
    expect(onChange).toHaveBeenLastCalledWith({
      agent: "claude",
      connection_id: "",
      model_id: "",
      reasoning_effort: null,
    });
    rerender(
      <ProfileSelect
        accounts={accounts}
        value={{
          agent: "claude",
          connection_id: "",
          model_id: "",
          reasoning_effort: null,
        }}
        onChange={onChange}
      />,
    );
    expect(screen.getByText(/No ready connection/)).toBeInTheDocument();
  });
});

it("uses the selected runtime catalog instead of the union of account models", () => {
  const runtimeAccount = {
    ...accounts[0],
    agent_models: {
      pi: [
        {
          id: "pi-only",
          name: "Pi model",
          reasoning_efforts: [],
          default_effort: null,
        },
      ],
      codex: [
        {
          id: "codex-only",
          name: "Codex model",
          reasoning_efforts: ["xhigh"],
          default_effort: "xhigh",
        },
      ],
    },
  };
  render(
    <ProfileSelect
      accounts={[runtimeAccount]}
      value={{
        agent: "codex",
        connection_id: "api",
        model_id: "codex-only",
        reasoning_effort: "xhigh",
      }}
      onChange={vi.fn()}
    />,
  );
  expect(
    screen.getByRole("option", { name: "Codex model" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("option", { name: "Native model" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("option", { name: "Pi model" }),
  ).not.toBeInTheDocument();
});
