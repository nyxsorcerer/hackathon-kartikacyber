import type { Account, Profile } from "../types";
export const emptyProfile: Profile = {
  agent: "pi",
  connection_id: "",
  model_id: "",
  reasoning_effort: null,
};
function modelsFor(account: Account | undefined, agent: Profile["agent"]) {
  return account?.agent_models
    ? account.agent_models[agent] || []
    : account?.models || [];
}
export function isProfileReady(profile: Profile, accounts: Account[]) {
  const account = accounts.find(
    (a) =>
      a.id === profile.connection_id &&
      a.supported_agents.includes(profile.agent) &&
      a.status === "ready" &&
      a.credential_configured,
  );
  const model = modelsFor(account, profile.agent).find(
    (m) => m.id === profile.model_id,
  );
  return (
    !!model &&
    (model.reasoning_efforts.length
      ? !!profile.reasoning_effort &&
        model.reasoning_efforts.includes(profile.reasoning_effort)
      : profile.reasoning_effort === null)
  );
}
export function ProfileSelect({
  accounts,
  value,
  onChange,
  idPrefix = "",
}: {
  accounts: Account[];
  value: Profile;
  onChange: (value: Profile) => void;
  idPrefix?: string;
}) {
  const compatible = accounts.filter((a) =>
    a.supported_agents.includes(value.agent),
  );
  const ready = compatible.filter(
    (a) => a.status === "ready" && a.credential_configured,
  );
  const account = ready.find((a) => a.id === value.connection_id);
  const models = modelsFor(account, value.agent);
  const model = models.find((m) => m.id === value.model_id);
  function chooseAccount(connection_id: string, agent = value.agent) {
    const selected = accounts.find((a) => a.id === connection_id);
    const first = modelsFor(selected, agent)[0];
    onChange({
      agent,
      connection_id,
      model_id: first?.id || "",
      reasoning_effort:
        first?.default_effort ?? first?.reasoning_efforts[0] ?? null,
    });
  }
  return (
    <div className="profile-fields">
      <label htmlFor={`${idPrefix}agent`}>
        Agent runtime
        <select
          id={`${idPrefix}agent`}
          value={value.agent}
          onChange={(e) => {
            const agent = e.target.value;
            if (agent === "pi" || agent === "claude" || agent === "codex") {
              const next = accounts.find(
                (a) =>
                  a.status === "ready" &&
                  a.credential_configured &&
                  a.supported_agents.includes(agent),
              );
              chooseAccount(next?.id || "", agent);
            }
          }}
        >
          <option value="pi">Pi</option>
          <option value="claude">Claude Code</option>
          <option value="codex">Codex CLI</option>
        </select>
      </label>
      <label htmlFor={`${idPrefix}account`}>
        Account
        <select
          id={`${idPrefix}account`}
          value={account?.id || ""}
          onChange={(e) => chooseAccount(e.target.value)}
        >
          <option value="">Select a connection</option>
          {compatible.map((a) => (
            <option
              key={a.id}
              value={a.id}
              disabled={a.status !== "ready" || !a.credential_configured}
            >
              {a.label} · {a.provider}
              {a.auth_type === "native_oauth"
                ? a.provider === "claude"
                  ? " · native session"
                  : " · native login"
                : " · API key"}
              {a.status !== "ready" ? ` (${a.status})` : ""}
            </option>
          ))}
        </select>
      </label>
      <label htmlFor={`${idPrefix}model`}>
        Model
        <select
          id={`${idPrefix}model`}
          disabled={!account}
          value={model?.id || ""}
          onChange={(e) => {
            const next = models.find((m) => m.id === e.target.value);
            onChange({
              ...value,
              model_id: next?.id || "",
              reasoning_effort:
                next?.default_effort ?? next?.reasoning_efforts[0] ?? null,
            });
          }}
        >
          <option value="">Select an available model</option>
          {models.map((m) => (
            <option key={m.id} value={m.id}>
              {m.name}
            </option>
          ))}
        </select>
      </label>
      {model?.reasoning_efforts.length ? (
        <label htmlFor={`${idPrefix}effort`}>
          Reasoning effort
          <select
            id={`${idPrefix}effort`}
            value={value.reasoning_effort || ""}
            onChange={(e) =>
              onChange({ ...value, reasoning_effort: e.target.value })
            }
          >
            {model.reasoning_efforts.map((e) => (
              <option key={e} value={e}>
                {e}
              </option>
            ))}
          </select>
        </label>
      ) : (
        <div className="field">
          <span>Reasoning effort</span>
          <div className="field-static">
            {model ? "Provider managed" : "Select a model first"}
          </div>
        </div>
      )}
      {account && models.length === 0 && (
        <p className="hint warning full">
          This connection reports no available models for this runtime. Refresh
          its capabilities in Settings.
        </p>
      )}
      {ready.length === 0 && (
        <p className="hint warning full">
          No ready connection supports this runtime. Connect an account and
          refresh its capabilities in Settings.
        </p>
      )}
    </div>
  );
}
