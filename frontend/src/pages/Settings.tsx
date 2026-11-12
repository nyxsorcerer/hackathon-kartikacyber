import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  KeyRound,
  Plus,
  RefreshCw,
  Save,
  Send,
  ShieldCheck,
  Trash2,
  Upload,
} from "lucide-react";
import { z } from "zod";
import { ApiError, mutate } from "../api";
import { useResource } from "../hooks";
import {
  accountSchema,
  accountsSchema,
  loginStatusSchema,
  operationNames,
  operations,
  pluginsSchema,
  recordsSchema,
  settingsSchema,
} from "../types";
import type { Account, Profile, Settings as SettingsRecord } from "../types";
import { ProfileSelect, emptyProfile } from "../components/ProfileSelect";
import { queueJob } from "../components/JobLaunch";
import { NativeCacheImport } from "../components/NativeCacheImport";
import { PromptTemplates } from "./PromptTemplates";
import {
  ActionButton,
  Badge,
  DataState,
  DetailGrid,
  Empty,
  ErrorNote,
  Evidence,
  ExternalLink,
  IntervalInput,
  JobLink,
  Modal,
  notify,
  PageHeading,
  Panel,
  Tabs,
  Time,
} from "../components/ui";
const providerLabels: Record<string, string> = {
  commandcode: "Command Code",
  openai: "OpenAI",
  claude: "Claude / Anthropic",
  deepseek: "DeepSeek",
  jev: "Jev",
  github: "GitHub",
  nvd: "NVD",
};
function providerLabel(provider: string) {
  return providerLabels[provider] || provider;
}
const nativeLoginLabels: Record<string, string> = {
  openai: "Codex ChatGPT login",
  claude: "Claude subscription login",
  commandcode: "Command Code login",
};
/** Pasted sign-in input for native logins that cannot complete through a callback. */
const loginInputs: Record<
  string,
  { label: string; noun: string; placeholder: string; instructions: string }
> = {
  claude: {
    label: "Authorization code",
    noun: "authorization code",
    placeholder: "Paste the code shown after Claude sign-in",
    instructions:
      "Open the Claude sign-in link below, approve access, then paste the authorization code shown after sign-in. This window updates automatically.",
  },
  commandcode: {
    label: "API key",
    noun: "API key",
    placeholder: "Paste the API key shown by Command Code",
    instructions:
      "Open the Command Code sign-in link below and sign in. When Command Code shows your API key, copy it and paste it here. This window updates automatically.",
  },
};
export function Settings() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") || "accounts";
  return (
    <>
      <PageHeading
        eyebrow="Workspace configuration"
        title="Settings"
        description="Connect your accounts and define how this installation collects and investigates evidence."
      />
      <Tabs
        label="Settings sections"
        items={[
          { id: "accounts", label: "Accounts" },
          { id: "plugins", label: "Pi plugins" },
          { id: "defaults", label: "Defaults" },
          { id: "prompts", label: "Prompts" },
          { id: "integrations", label: "Integrations" },
          { id: "discord", label: "Discord" },
        ]}
        active={tab}
        onChange={(id) => setParams({ tab: id })}
      />
      {tab === "accounts" && <Accounts />}
      {tab === "plugins" && <Plugins />}
      {tab === "defaults" && <Defaults />}
      {tab === "prompts" && <PromptTemplates />}
      {tab === "integrations" && <Accounts integrations />}
      {tab === "discord" && <Discord />}
    </>
  );
}
function Accounts({ integrations = false }: { integrations?: boolean }) {
  const resource = useResource("/accounts", accountsSchema, 10000);
  const [editor, setEditor] = useState<Account | true>();
  const [login, setLogin] = useState<Account>();
  const [cacheImport, setCacheImport] = useState<Account>();
  const [inspected, setInspected] = useState<Account>();
  const items = resource.data?.items.filter(
    (a) => ["github", "nvd"].includes(a.provider) === integrations,
  );
  return (
    <>
      <Panel
        title={integrations ? "Source integrations" : "Provider connections"}
        description={
          integrations
            ? "GitHub and optional NVD credentials belong to source collection."
            : "API access and native subscription login are distinct connections."
        }
        actions={
          <button className="primary" onClick={() => setEditor(true)}>
            <Plus size={15} />
            Add connection
          </button>
        }
      >
        <DataState
          loading={resource.loading}
          error={resource.error}
          retry={resource.refresh}
          hasData={!!resource.data}
        >
          {items?.length ? (
            <div className="account-list">
              {items.map((account) => (
                <article className="account-card" key={account.id}>
                  <div className="account-title">
                    <span className="provider-icon">
                      <KeyRound size={18} />
                    </span>
                    <div>
                      <h3>{account.label}</h3>
                      <p>
                        {providerLabel(account.provider)} ·{" "}
                        {account.auth_type === "native_oauth"
                          ? nativeLoginLabels[account.provider]
                          : "API-key access"}
                      </p>
                    </div>
                    <Badge>{account.status}</Badge>
                  </div>
                  <div className="chip-row">
                    {account.supported_agents.map((agent) => (
                      <span className="runtime-chip" key={agent}>
                        {agent === "codex"
                          ? "Codex CLI"
                          : agent === "claude"
                            ? "Claude Code"
                            : agent === "pi"
                              ? "Pi"
                              : agent}
                      </span>
                    ))}
                    <span className="hint">
                      Credential{" "}
                      {account.credential_configured
                        ? "configured (masked)"
                        : "not configured"}
                    </span>
                  </div>
                  <div className="account-foot">
                    <span className="account-stats">
                      {account.models.length}{" "}
                      {account.models.length === 1 ? "model" : "models"} · Usage{" "}
                      {account.usage === null || account.usage === undefined
                        ? "unknown"
                        : "reported"}
                      <small>
                        {account.last_checked_at ? (
                          <>
                            Checked <Time value={account.last_checked_at} />
                          </>
                        ) : (
                          "Never checked — run Check to validate access"
                        )}
                      </small>
                    </span>
                    <div className="inline-actions">
                      <button
                        className="secondary"
                        onClick={() => setInspected(account)}
                      >
                        Details
                      </button>
                      <button
                        className="secondary"
                        onClick={() => setEditor(account)}
                      >
                        Edit
                      </button>
                      {account.auth_type === "native_oauth" && (
                        <button
                          className="secondary"
                          onClick={() => setLogin(account)}
                        >
                          Native login
                        </button>
                      )}
                      {account.auth_type === "native_oauth" && (
                        <button
                          className="secondary"
                          onClick={() => setCacheImport(account)}
                        >
                          <Upload size={14} />
                          Import native session
                        </button>
                      )}
                      <ActionButton
                        className="secondary"
                        onAction={() =>
                          queueJob(`/accounts/${account.id}/check`)
                        }
                      >
                        <ShieldCheck size={14} />
                        Check
                      </ActionButton>
                      {!integrations && (
                        <ActionButton
                          className="secondary"
                          onAction={() =>
                            queueJob(`/accounts/${account.id}/capabilities`)
                          }
                        >
                          <RefreshCw size={14} />
                          Capabilities
                        </ActionButton>
                      )}
                    </div>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <Empty
              title={
                integrations
                  ? "No source credentials connected"
                  : "No provider accounts connected"
              }
              description={
                integrations
                  ? "GitHub repositories are polled only with a fine-grained, read-only GitHub token (Contents and Metadata). WordPress.org plugins need no token."
                  : "Connect an operator-owned account, check access, and refresh its model catalog before starting agent jobs."
              }
              action={
                <button className="secondary" onClick={() => setEditor(true)}>
                  <Plus size={14} />
                  Add connection
                </button>
              }
            />
          )}
        </DataState>
      </Panel>
      {!integrations && (
        <div className="quiet-note">
          <KeyRound size={21} />
          <p>
            OpenAI API keys provide API access. Codex ChatGPT login uses its own
            native connection and model catalog. Subscription names do not
            establish API model access. Usage and billing remain Unknown when a
            provider does not expose them.
          </p>
        </div>
      )}
      {editor && (
        <AccountEditor
          account={editor === true ? undefined : editor}
          integrations={integrations}
          onClose={() => setEditor(undefined)}
          refresh={resource.refresh}
        />
      )}{" "}
      {login && (
        <NativeLogin
          account={login}
          onClose={() => {
            setLogin(undefined);
            resource.refresh();
          }}
        />
      )}
      {cacheImport && (
        <NativeCacheImport
          account={cacheImport}
          onClose={() => setCacheImport(undefined)}
          refresh={resource.refresh}
        />
      )}
      {inspected && (
        <Modal
          title={inspected.label}
          description="Redacted connection metadata"
          onClose={() => setInspected(undefined)}
        >
          <DetailGrid
            items={[
              ["Provider", providerLabel(inspected.provider)],
              ["Authentication", inspected.auth_type],
              ["Status", <Badge>{inspected.status}</Badge>],
              [
                "Credential",
                inspected.credential_configured
                  ? "Configured — masked"
                  : "Not configured",
              ],
            ]}
          />
          <Evidence
            value={inspected.models}
            label="Available models & native effort values"
          />
          <Evidence
            value={inspected.selection_error}
            label="Runtime selection availability"
          />
          <Evidence value={inspected.error} label="Connection failure" />
          <Evidence
            value={inspected.capability_errors}
            label="Capability discovery failures"
          />
          <Evidence
            value={inspected.usage ?? "Unknown — not reported by provider"}
            label="Provider usage / subscription"
          />
          <div className="form-actions split">
            <span className="hint">
              Removing a connection deletes its stored credential. Recorded jobs
              keep their profile.
            </span>
            <ActionButton
              className="danger-button"
              confirm="Confirm removal"
              onAction={async () => {
                await mutate(
                  `/accounts/${inspected.id}`,
                  z.unknown(),
                  {},
                  "DELETE",
                );
                notify("Connection removed.");
                setInspected(undefined);
                resource.refresh();
              }}
            >
              <Trash2 size={15} />
              Remove connection
            </ActionButton>
          </div>
        </Modal>
      )}
    </>
  );
}
function AccountEditor({
  account,
  integrations,
  onClose,
  refresh,
}: {
  account?: Account;
  integrations: boolean;
  onClose: () => void;
  refresh: () => void;
}) {
  const [label, setLabel] = useState(account?.label || "");
  const [provider, setProvider] = useState(
    account?.provider || (integrations ? "github" : "openai"),
  );
  const [auth, setAuth] = useState(account?.auth_type || "api_key");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <Modal
      title={account ? "Edit connection" : "Add connection"}
      description="Credential values are write-only and are never returned to the dashboard."
      onClose={onClose}
    >
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            await mutate(
              account ? `/accounts/${account.id}` : "/accounts",
              accountSchema,
              account
                ? { label, ...(key ? { api_key: key } : {}) }
                : {
                    label,
                    provider,
                    auth_type: auth,
                    ...(auth === "api_key" && key ? { api_key: key } : {}),
                  },
              account ? "PATCH" : "POST",
            );
            setKey("");
            notify(
              "Connection saved. Run a connection check to validate access.",
            );
            refresh();
            onClose();
          } catch (err) {
            setError(
              err instanceof Error ? err.message : "Could not save connection.",
            );
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Connection label
          <input
            required
            maxLength={200}
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="My OpenAI API account"
          />
        </label>
        <div className="form-grid">
          <label>
            Provider
            <select
              value={provider}
              disabled={!!account}
              onChange={(e) => {
                setProvider(e.target.value);
                setAuth("api_key");
              }}
            >
              {(integrations
                ? ["github", "nvd"]
                : ["deepseek", "commandcode", "openai", "claude", "jev"]
              ).map((p) => (
                <option key={p} value={p}>
                  {providerLabel(p)}
                </option>
              ))}
            </select>
          </label>
          <label>
            Authentication
            <select
              value={auth}
              disabled={!!account}
              onChange={(e) => setAuth(e.target.value)}
            >
              <option value="api_key">API key</option>
              {provider in nativeLoginLabels && (
                <option value="native_oauth">
                  {nativeLoginLabels[provider]}
                </option>
              )}
            </select>
          </label>
        </div>
        {auth === "api_key" ? (
          <label>
            {account ? "Replace API key (leave blank to retain)" : "API key"}
            <input
              type="password"
              autoComplete="new-password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={
                account?.credential_configured
                  ? "•••••••• · saved credential"
                  : "Enter credential"
              }
            />
          </label>
        ) : (
          <p className="hint">
            {provider === "claude"
              ? "Save this connection, then start Native login to sign in with your Claude subscription and paste the authorization code, or import your native Claude session JSON."
              : provider === "commandcode"
                ? "Save this connection, then start Native login to sign in to Command Code and paste the API key it shows, or import auth.json from pi or the Command Code CLI."
                : "Save this connection, then start Native login for the supported Codex device flow, or import your native Codex session JSON."}
          </p>
        )}
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy}>
            <Save size={15} />
            {busy ? "Saving…" : "Save connection"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
function NativeLogin({
  account,
  onClose,
}: {
  account: Account;
  onClose: () => void;
}) {
  const state = useResource(
    `/accounts/${account.id}/login`,
    loginStatusSchema,
    2000,
  );
  const active = ["queued", "running", "cancelling"].includes(
    state.data?.status || "",
  );
  const input = loginInputs[account.provider];
  const codeState = input ? loginCodeState(state.data?.events ?? []) : "none";
  return (
    <Modal
      title={`${account.label} — native login`}
      description="The login operation runs inside the managed runtime. Provider availability determines the supported flow."
      onClose={onClose}
    >
      <DataState
        loading={state.loading}
        error={state.error}
        retry={state.refresh}
        hasData={!!state.data}
      >
        {state.data && (
          <>
            <div className="chip-row">
              <Badge>{state.data.status}</Badge>
              {state.data.job_id && <JobLink id={state.data.job_id} />}
            </div>
            {state.data.status === "queued" && (
              <p role="status">
                Login is queued. Verification instructions will appear here when
                the provider is ready.
              </p>
            )}
            {state.data.status === "running" && (
              <p role="status">
                {input
                  ? input.instructions
                  : "Waiting for you to complete provider verification. Use the link and device code below when they appear. This window updates automatically."}
              </p>
            )}
            {state.data.status === "cancelling" && (
              <p role="status">Stopping the login attempt…</p>
            )}
            {state.data.status === "succeeded" && (
              <p role="status">
                Signed in. Account capabilities are being refreshed.
              </p>
            )}
            {active &&
              state.data.events.map((event, i) => (
                <LoginEvent event={event} key={i} />
              ))}
            {input &&
              state.data.status === "running" &&
              codeState === "awaiting" && (
                <LoginCodeForm
                  account={account}
                  input={input}
                  onSubmitted={state.refresh}
                />
              )}
            {input &&
              state.data.status === "running" &&
              codeState === "submitted" && (
                <p role="status">
                  {input.label} submitted. Finishing sign-in with{" "}
                  {providerLabel(account.provider)}…
                </p>
              )}
            {state.data.error && (
              <Evidence value={state.data.error} label="Login error" />
            )}
          </>
        )}
      </DataState>
      <div className="form-actions">
        <button className="secondary" onClick={onClose}>
          Close
        </button>
        {state.data?.job_id &&
          ["queued", "running"].includes(state.data.status) && (
            <ActionButton
              className="secondary"
              onAction={async () => {
                await queueJob(`/jobs/${state.data?.job_id}/cancel`);
                state.refresh();
              }}
            >
              Cancel login
            </ActionButton>
          )}
        <ActionButton
          className="primary"
          disabled={active || !state.data}
          onAction={async () => {
            await queueJob(`/accounts/${account.id}/login`);
            state.refresh();
          }}
        >
          Start native login
        </ActionButton>
      </div>
    </Modal>
  );
}
const loginCodeAcceptedSchema = z.object({
  job_id: z.string(),
  status: z.string(),
});
/** Pasted-input logins finish with operator input; events only carry its state. */
function loginCodeState(events: unknown[]): "none" | "awaiting" | "submitted" {
  let required = false;
  let last: unknown;
  for (const event of events) {
    const record = z.record(z.string(), z.unknown()).safeParse(event);
    if (!record.success) continue;
    if (record.data.input_required) required = true;
    if (
      ["code_received", "code_submitted", "code_delivery_failed"].includes(
        String(record.data.status),
      )
    )
      last = record.data.status;
  }
  if (!required) return "none";
  return last === undefined || last === "code_delivery_failed"
    ? "awaiting"
    : "submitted";
}
function LoginCodeForm({
  account,
  input,
  onSubmitted,
}: {
  account: Account;
  input: (typeof loginInputs)[string];
  onSubmitted: () => void;
}) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <form
      className="login-code"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(undefined);
        try {
          await mutate(
            `/accounts/${account.id}/login/code`,
            loginCodeAcceptedSchema,
            { code: code.trim() },
          );
          setCode("");
          onSubmitted();
        } catch (err) {
          setError(
            err instanceof ApiError && err.code === "validation_error"
              ? `Paste the complete ${input.noun} shown after ${providerLabel(account.provider)} sign-in.`
              : err instanceof Error
                ? err.message
                : `Could not submit the ${input.noun}.`,
          );
        } finally {
          setBusy(false);
        }
      }}
    >
      <label>
        {input.label}
        <input
          type="password"
          autoComplete="off"
          spellCheck={false}
          required
          maxLength={2048}
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder={input.placeholder}
        />
      </label>
      {error && <ErrorNote>{error}</ErrorNote>}
      <div className="form-actions">
        <button className="primary" disabled={busy || !code.trim()}>
          {busy ? "Submitting…" : `Submit ${input.noun}`}
        </button>
      </div>
    </form>
  );
}
function LoginEvent({ event }: { event: unknown }) {
  if (typeof event !== "object" || !event || Array.isArray(event))
    return <Evidence value={event} label="Login event" />;
  const record = z.record(z.string(), z.unknown()).parse(event);
  const nested = z.record(z.string(), z.unknown()).safeParse(record.data);
  const data = nested.success ? nested.data : record;
  const url =
    typeof data.verification_uri_complete === "string"
      ? data.verification_uri_complete
      : typeof data.verification_url === "string"
        ? data.verification_url
        : typeof data.verification_uri === "string"
          ? data.verification_uri
          : typeof data.url === "string"
            ? data.url
            : null;
  const code =
    typeof data.user_code === "string"
      ? data.user_code
      : typeof data.code === "string"
        ? data.code
        : null;
  return (
    <div className="login-event">
      {url && (
        <ExternalLink href={url}>Open provider verification</ExternalLink>
      )}
      {code && <p className="device-code">{code}</p>}
      <Evidence value={event} label="Login progress" />
    </div>
  );
}
function Plugins() {
  const resource = useResource("/plugins", pluginsSchema);
  return (
    <Panel
      title="Bundled Pi packages"
      description="Pinned code ships with the runner image. Enablement applies to subsequent jobs."
    >
      <DataState
        loading={resource.loading}
        error={resource.error}
        retry={resource.refresh}
      >
        {resource.data?.items.length ? (
          <div className="plugin-list">
            {resource.data.items.map((plugin) => (
              <article className="plugin-card" key={plugin.id}>
                <div>
                  <h3>{plugin.name || plugin.id}</h3>
                  <p className="mono">
                    {plugin.pinned_version ||
                      plugin.version ||
                      "Version unavailable"}
                  </p>
                  <ExternalLink href={plugin.source}>
                    {plugin.source}
                  </ExternalLink>
                  <div className="chip-row">
                    <Badge>
                      {typeof plugin.health === "string"
                        ? plugin.health
                        : "Health details available"}
                    </Badge>
                    {typeof plugin.provider_contribution === "string" && (
                      <span className="hint">
                        Provider: {plugin.provider_contribution}
                      </span>
                    )}
                  </div>
                  <Evidence value={plugin.health} label="Plugin health" />
                  {!!plugin.provider_contribution && (
                    <Evidence
                      value={plugin.provider_contribution}
                      label="Provider contribution"
                    />
                  )}
                </div>
                <div className="plugin-actions">
                  <Badge>{plugin.enabled ? "enabled" : "disabled"}</Badge>
                  <ActionButton
                    className="secondary"
                    onAction={async () => {
                      await mutate(
                        `/plugins/${plugin.id}`,
                        z.unknown(),
                        { enabled: !plugin.enabled },
                        "PATCH",
                      );
                      resource.refresh();
                      notify("Plugin configuration updated for new jobs.");
                    }}
                  >
                    {plugin.enabled ? "Disable" : "Enable"}
                  </ActionButton>
                </div>
              </article>
            ))}
          </div>
        ) : (
          <Empty
            title="No plugins reported"
            description="The runner’s pinned plugin manifest will appear when available."
          />
        )}
      </DataState>
    </Panel>
  );
}
function Defaults() {
  const resource = useResource("/settings", settingsSchema);
  const accounts = useResource("/accounts", accountsSchema);
  return (
    <DataState
      loading={resource.loading}
      error={resource.error}
      retry={resource.refresh}
    >
      {resource.data && (
        <DefaultsEditor
          settings={resource.data}
          accounts={accounts.data?.items || []}
          refresh={resource.refresh}
        />
      )}
    </DataState>
  );
}
function DefaultsEditor({
  settings,
  accounts,
  refresh,
}: {
  settings: SettingsRecord;
  accounts: Account[];
  refresh: () => void;
}) {
  const [seconds, setSeconds] = useState(settings.monitor_interval_seconds);
  const [profiles, setProfiles] = useState<Record<string, Profile>>(
    settings.default_profiles,
  );
  return (
    <>
      <Panel
        title="Monitoring cadence"
        description="New applications inherit this interval unless they set an explicit override. The minimum is 5 minutes."
      >
        <form className="cadence-form" onSubmit={(e) => e.preventDefault()}>
          <label>
            Global monitoring interval
            <IntervalInput
              label="Global monitoring interval"
              value={seconds}
              onChange={setSeconds}
            />
          </label>
          <ActionButton
            className="primary"
            disabled={seconds === null || !Number.isInteger(seconds)}
            onAction={async () => {
              await mutate(
                "/settings",
                settingsSchema,
                { monitor_interval_seconds: seconds },
                "PATCH",
              );
              refresh();
              notify("Monitoring default saved.");
              window.dispatchEvent(new Event("numen:settings-updated"));
            }}
          >
            <Save size={15} />
            Save interval
          </ActionButton>
        </form>
      </Panel>
      <Panel
        title="Default execution profiles"
        description="Defaults prefill the job dialog. Application overrides and job selections take precedence."
      >
        {operations.map((operation) => (
          <div className="default-operation" key={operation}>
            <div className="default-header">
              <h3>{operationNames[operation]}</h3>
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={!!profiles[operation]}
                  onChange={(e) =>
                    setProfiles((previous) => {
                      const next = { ...previous };
                      if (e.target.checked)
                        next[operation] = { ...emptyProfile };
                      else delete next[operation];
                      return next;
                    })
                  }
                />
                Configure default
              </label>
            </div>
            {profiles[operation] ? (
              <ProfileSelect
                idPrefix={`default-${operation}-`}
                accounts={accounts}
                value={profiles[operation]}
                onChange={(profile) =>
                  setProfiles({ ...profiles, [operation]: profile })
                }
              />
            ) : (
              <p className="hint">
                Select a profile when submitting this operation.
              </p>
            )}
          </div>
        ))}
        <div className="form-actions">
          <ActionButton
            className="primary"
            onAction={async () => {
              await mutate(
                "/settings",
                settingsSchema,
                { default_profiles: profiles },
                "PATCH",
              );
              refresh();
              notify(
                "Default profiles saved. Existing jobs retain their recorded profile.",
              );
            }}
          >
            <Save size={15} />
            Save profiles
          </ActionButton>
        </div>
      </Panel>
    </>
  );
}
function Discord() {
  const settings = useResource("/settings", settingsSchema);
  const deliveries = useResource("/notifications", recordsSchema, 10000);
  return (
    <>
      <DataState
        loading={settings.loading}
        error={settings.error}
        retry={settings.refresh}
      >
        {settings.data && (
          <DiscordEditor settings={settings.data} refresh={settings.refresh} />
        )}
      </DataState>
      <Panel
        title="Delivery history"
        description="Stable event identities and delivery attempts are retained, including failures."
      >
        <DataState
          loading={deliveries.loading}
          error={deliveries.error}
          retry={deliveries.refresh}
          hasData={!!deliveries.data}
        >
          {deliveries.data?.items.length ? (
            <div className="notification-list">
              {deliveries.data.items.map((delivery, i) => (
                <article
                  key={typeof delivery.id === "string" ? delivery.id : i}
                >
                  <div className="analysis-header">
                    <strong>
                      {typeof delivery.event_key === "string"
                        ? delivery.event_key
                        : `Notification ${i + 1}`}
                    </strong>
                    <Badge>
                      {typeof delivery.status === "string"
                        ? delivery.status
                        : "Recorded"}
                    </Badge>
                  </div>
                  <Evidence
                    value={delivery}
                    label="Attempts & delivery result"
                  />
                  {typeof delivery.id === "string" &&
                    delivery.status === "failed" && (
                      <ActionButton
                        className="secondary"
                        onAction={() =>
                          queueJob(`/notifications/${delivery.id}/retry`)
                        }
                      >
                        Retry delivery
                      </ActionButton>
                    )}
                </article>
              ))}
            </div>
          ) : (
            <Empty
              title="No notification attempts"
              description="Test deliveries and candidate/CVE events will be recorded here."
            />
          )}
        </DataState>
      </Panel>
    </>
  );
}
function DiscordEditor({
  settings,
  refresh,
}: {
  settings: SettingsRecord;
  refresh: () => void;
}) {
  const [enabled, setEnabled] = useState(settings.webhook_enabled);
  const [url, setUrl] = useState("");
  const [base, setBase] = useState(settings.dashboard_url || "");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Discord webhook"
      description="Notifications link to authenticated review pages. Analysis still requires your dashboard decision."
    >
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            await mutate(
              "/settings",
              settingsSchema,
              {
                webhook_enabled: enabled,
                dashboard_url: base,
                ...(url ? { webhook_url: url } : {}),
              },
              "PATCH",
            );
            setUrl("");
            notify("Discord configuration saved.");
            refresh();
          } catch (err) {
            setError(
              err instanceof Error ? err.message : "Could not save webhook.",
            );
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="form-grid">
          <label className="full">
            {settings.webhook_configured
              ? "Replace webhook URL (leave blank to retain)"
              : "Webhook URL"}
            <input
              type="password"
              autoComplete="new-password"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={
                settings.webhook_configured
                  ? settings.webhook_masked || "•••••••• · configured"
                  : "https://discord.com/api/webhooks/…"
              }
            />
            <span className="hint">
              {settings.webhook_configured
                ? "A webhook is configured. Its token is masked."
                : "No webhook configured."}
            </span>
          </label>
          <label className="full">
            Dashboard base URL
            <input
              type="url"
              value={base}
              onChange={(e) => setBase(e.target.value)}
              placeholder="https://numen.example.com"
            />
          </label>
          <label className="check-label full">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            Enable candidate and eligible CVE notifications
          </label>
        </div>
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <ActionButton
            className="secondary"
            disabled={!settings.webhook_configured}
            onAction={() => queueJob("/settings/webhook/test")}
          >
            <Send size={15} />
            Test notification
          </ActionButton>
          <button className="primary" disabled={busy}>
            <Save size={15} />
            {busy ? "Saving…" : "Save webhook"}
          </button>
        </div>
      </form>
    </Panel>
  );
}
