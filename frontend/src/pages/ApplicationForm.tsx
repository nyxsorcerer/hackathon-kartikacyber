import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Save } from "lucide-react";
import { ApiError, mutate } from "../api";
import { useResource } from "../hooks";
import {
  accountsSchema,
  operationNames,
  operations,
  applicationSchema,
  settingsSchema,
} from "../types";
import type { Profile, Application } from "../types";
import {
  ProfileSelect,
  emptyProfile,
  isProfileReady,
} from "../components/ProfileSelect";
import {
  DataState,
  ErrorNote,
  IntervalInput,
  PageHeading,
  Panel,
  formatInterval,
  notify,
} from "../components/ui";
export function ApplicationForm() {
  const { id } = useParams();
  const settings = useResource("/settings", settingsSchema);
  return id ? (
    <EditApplication id={id} />
  ) : (
    <DataState
      loading={settings.loading}
      error={settings.error}
      retry={settings.refresh}
    >
      {settings.data && (
        <ApplicationEditor
          defaultSeconds={settings.data.monitor_interval_seconds}
        />
      )}
    </DataState>
  );
}
function EditApplication({ id }: { id: string }) {
  const resource = useResource(
    `/applications/${encodeURIComponent(id)}`,
    applicationSchema,
  );
  return (
    <DataState
      loading={resource.loading}
      error={resource.error}
      retry={resource.refresh}
    >
      {resource.data && (
        <ApplicationEditor
          key={resource.data.id}
          application={resource.data}
          defaultSeconds={null}
        />
      )}
    </DataState>
  );
}
function ApplicationEditor({
  application,
  defaultSeconds,
}: {
  application?: Application;
  defaultSeconds: number | null;
}) {
  const navigate = useNavigate();
  const accounts = useResource("/accounts", accountsSchema);
  const settings = useResource("/settings", settingsSchema);
  const [name, setName] = useState(application?.asset_name || "");
  const [url, setUrl] = useState(application?.asset_url || "");
  const [kind, setKind] = useState(application?.product_kind || "CMS");
  const [product, setProduct] = useState(application?.product_name || "");
  const [inherit, setInherit] = useState(
    application
      ? application.config.monitor_interval_inherited === true ||
          application.monitor_interval_seconds === null
      : true,
  );
  const [seconds, setSeconds] = useState(
    application?.monitor_interval_seconds || defaultSeconds || null,
  );
  const globalSeconds = settings.data?.monitor_interval_seconds ?? null;
  const [enabled, setEnabled] = useState(application?.monitor_enabled ?? true);
  const [triage, setTriage] = useState(
    application?.config.triage_mode || "disabled",
  );
  const [profiles, setProfiles] = useState<Record<string, Profile>>(
    application?.config.profiles || {},
  );
  const [minScore, setMinScore] = useState(
    String(application?.config.cve_min_score ?? ""),
  );
  const [versions, setVersions] = useState(
    application?.config.cve_versions || [],
  );
  const [auto, setAuto] = useState(
    application?.config.cve_auto_analyze || false,
  );
  const [auditRefresh, setAuditRefresh] = useState(
    application?.config.audit_auto_refresh || false,
  );
  const [selectors, setSelectors] = useState(() =>
    Array.isArray(application?.config.cve_selectors)
      ? application.config.cve_selectors
          .map((s) =>
            typeof s === "object" && s && "value" in s ? String(s.value) : "",
          )
          .join("\n")
      : "",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [fields, setFields] = useState<Record<string, unknown>>({});
  const [scheme, setScheme] = useState<string>(
    typeof application?.config.version_scheme === "string"
      ? application.config.version_scheme
      : "unknown",
  );
  const [versionEnabled, setVersionEnabled] = useState(
    application?.config.version_monitor_enabled !== false,
  );
  const [origins, setOrigins] = useState(
    Array.isArray(application?.config.asset_origins)
      ? application.config.asset_origins.join("\n")
      : "",
  );
  const [jev, setJev] = useState(
    typeof application?.config.jev_connection_id === "string"
      ? application.config.jev_connection_id
      : "",
  );
  const [jevModel, setJevModel] = useState(
    application?.config.jev_model_id || "",
  );
  const jevModels =
    accounts.data?.items.find((a) => a.id === jev)?.models || [];
  const cveProfile =
    profiles.cve_analysis || settings.data?.default_profiles.cve_analysis;
  const autoMissing = [
    !selectors.trim() && "product selectors",
    minScore === "" && "a minimum Base score",
    versions.length === 0 && "at least one CVSS version",
    !(cveProfile && isProfileReady(cveProfile, accounts.data?.items || [])) &&
      "a ready CVE analysis profile",
  ].filter((item): item is string => !!item);
  const autoConfigured = autoMissing.length === 0;
  const triageProfile =
    profiles.commit_triage || settings.data?.default_profiles.commit_triage;
  const triageConfigured =
    !!triageProfile &&
    triageProfile.agent === triage &&
    isProfileReady(triageProfile, accounts.data?.items || []);
  function fieldError(name: string) {
    const entry = fields[name];
    return entry ? (
      <span className="field-error" id={`field-error-${name}`}>
        {String(entry)}
      </span>
    ) : null;
  }
  return (
    <>
      <PageHeading
        back={{
          to: application ? `/applications/${application.id}` : "/applications",
          label: application ? "Back to application" : "All applications",
        }}
        eyebrow={application ? "Application configuration" : "Asset inventory"}
        title={application ? "Edit application" : "Insert application"}
        description="Define the deployed asset, its upstream software, and the evidence you want to collect."
      />
      <form
        className="application-form"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          setFields({});
          const config = {
            ...application?.config,
            triage_mode: triage,
            profiles,
            cve_selectors: selectors
              .split("\n")
              .map((v) => v.trim())
              .filter(Boolean)
              .map((value) => ({
                type: value.startsWith("cpe:") ? "cpe" : "keyword",
                value,
              })),
            cve_min_score: minScore === "" ? null : Number(minScore),
            cve_versions: versions,
            cve_auto_analyze: auto,
            audit_auto_refresh: auditRefresh,
            version_scheme: scheme,
            version_monitor_enabled: versionEnabled,
            asset_origins: origins
              .split("\n")
              .map((v) => v.trim())
              .filter(Boolean),
            jev_connection_id: jev || null,
            jev_model_id: jevModel || null,
          };
          try {
            const saved = await mutate(
              application ? `/applications/${application.id}` : "/applications",
              applicationSchema,
              {
                asset_name: name,
                asset_url: url,
                product_kind: kind,
                product_name: product,
                monitor_interval_seconds: inherit ? null : seconds,
                monitor_enabled: enabled,
                archived: application?.archived || false,
                config,
              },
              application ? "PATCH" : "POST",
            );
            notify(
              application ? "Application updated." : "Application created.",
            );
            navigate(`/applications/${saved.id}`);
          } catch (err) {
            setError(
              err instanceof Error
                ? err.message
                : "Unable to save the application.",
            );
            if (err instanceof ApiError) setFields(err.fields);
          } finally {
            setBusy(false);
          }
        }}
      >
        <Panel
          title="Asset & software"
          description="One application represents one deployed asset / software pair."
        >
          <div className="form-grid">
            <label>
              Name
              <input
                required
                maxLength={200}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Customer portal"
              />
              {fieldError("asset_name")}
            </label>
            <label>
              Asset URL
              <input
                required
                type="url"
                aria-label="Asset URL"
                aria-invalid={!!fields.asset_url}
                aria-describedby={
                  fields.asset_url ? "field-error-asset_url" : undefined
                }
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://portal.example.com"
              />
              {fieldError("asset_url")}
            </label>
            <label>
              Software kind
              <input
                required
                list="software-kinds"
                value={kind}
                onChange={(e) => setKind(e.target.value)}
              />
              <datalist id="software-kinds">
                <option value="CMS" />
                <option value="plugin" />
              </datalist>
            </label>
            <label>
              Product name
              <input
                required
                value={product}
                onChange={(e) => setProduct(e.target.value)}
                placeholder="Software or plugin name"
              />
            </label>
          </div>
        </Panel>
        <Panel
          title="Monitoring"
          description="Check every 5 minutes or longer, in minutes, hours or days. Manual checks remain available when paused."
        >
          <div className="form-grid">
            <div className="field-stack">
              <label>
                Check interval
                <IntervalInput
                  key={inherit ? `global-${globalSeconds}` : "own"}
                  label="Check interval"
                  value={inherit ? globalSeconds : seconds}
                  onChange={setSeconds}
                  disabled={inherit}
                  invalid={!!fields.monitor_interval_seconds}
                />
                {fieldError("monitor_interval_seconds")}
              </label>
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={inherit}
                  onChange={(e) => setInherit(e.target.checked)}
                />
                Use the global default (
                {globalSeconds ? formatInterval(globalSeconds) : "not configured"})
              </label>
            </div>
            <div className="field-stack">
              <span className="field-label">Scheduled monitoring</span>
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                />
                Check this application on its interval
              </label>
              <span className="hint">
                When paused, manual checks remain available.
              </span>
            </div>
            <div className="field-stack full">
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={auditRefresh}
                  onChange={(e) => setAuditRefresh(e.target.checked)}
                />
                Keep the audit context current
              </label>
              <span className="hint">
                After a source check moves the source head, refresh the latest
                audit context: functions in changed files are analysed again
                with the Audit context profile, the rest are reused.
              </span>
            </div>
            <label>
              Triage mode
              <select
                value={triage}
                onChange={(e) => setTriage(e.target.value)}
              >
                <option value="disabled">Disabled — manual review</option>
                <option value="jev">Jev — typed security classification</option>
                <option value="pi">Pi</option>
                <option value="claude">Claude Code</option>
                <option value="codex">Codex CLI</option>
              </select>
            </label>
            {["pi", "claude", "codex"].includes(triage) &&
              !triageConfigured && (
                <p className="hint warning full">
                  The selected triage runtime needs a matching ready Commit
                  triage profile. Configure an application override below or the
                  global default.
                </p>
              )}
            {triage === "jev" && (
              <label>
                Jev account
                <select
                  value={jev}
                  onChange={(e) => {
                    setJev(e.target.value);
                    setJevModel("");
                  }}
                >
                  <option value="">Select Jev connection</option>
                  {accounts.data?.items
                    .filter((a) => a.provider === "jev")
                    .map((a) => (
                      <option value={a.id} key={a.id}>
                        {a.label} · {a.status}
                      </option>
                    ))}
                </select>
              </label>
            )}
            {triage === "jev" && (
              <label>
                Jev triage model
                <select
                  value={jevModel}
                  disabled={!jevModels.length}
                  onChange={(e) => setJevModel(e.target.value)}
                >
                  <option value="">
                    {jevModels.length
                      ? "Use service-reported selection"
                      : "Model access unavailable until service reports it"}
                  </option>
                  {jevModels.map((model) => (
                    <option key={model.id} value={model.id}>
                      {model.name}
                    </option>
                  ))}
                </select>
                <span className="hint">
                  Jev is a typed triage service and uses its own model metadata.
                </span>
              </label>
            )}
          </div>
        </Panel>
        <Panel
          title="Version determination"
          description="Generate and inspect reusable recipes from the application’s Version tab after saving."
        >
          <div className="form-grid">
            <label>
              Version comparison scheme
              <select
                value={scheme}
                onChange={(e) => setScheme(e.target.value)}
              >
                <option value="unknown">
                  Unknown — keep applicability unknown
                </option>
                <option value="semver">Semantic versioning</option>
                <option value="php">PHP / WordPress version comparison</option>
              </select>
            </label>
            <label className="check-label">
              <input
                type="checkbox"
                checked={versionEnabled}
                onChange={(e) => setVersionEnabled(e.target.checked)}
              />
              Reuse configured recipe during monitoring
            </label>
            <label className="full">
              Additional asset origins (one HTTP(S) origin per line)
              <textarea
                value={origins}
                onChange={(e) => setOrigins(e.target.value)}
                placeholder="https://assets.example.com"
              />
            </label>
          </div>
        </Panel>
        <Panel
          title="CVE identity & score criteria"
          description="CPE identities are exact selectors. Keyword matches require confirmation before analysis."
        >
          <div className="form-grid">
            <label className="full">
              Product selectors (one CPE 2.3 identity or keyword per line)
              <textarea
                value={selectors}
                onChange={(e) => setSelectors(e.target.value)}
                placeholder="cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
              />
              {fieldError("config.cve_selectors")}
            </label>
            <label>
              Minimum CVSS Base score
              <input
                type="number"
                min={0}
                max={10}
                step={0.1}
                value={minScore}
                onChange={(e) => setMinScore(e.target.value)}
                placeholder="Not configured"
              />
            </label>
            <fieldset>
              <legend>Allowed scoring versions</legend>
              <div className="checkboxes">
                {["3.0", "3.1", "4.0"].map((v) => (
                  <label key={v} className="check-label">
                    <input
                      type="checkbox"
                      checked={versions.includes(v)}
                      onChange={(e) =>
                        setVersions(
                          e.target.checked
                            ? [...versions, v]
                            : versions.filter((x) => x !== v),
                        )
                      }
                    />
                    {v}
                  </label>
                ))}
              </div>
            </fieldset>
            <div className="field-stack full">
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={auto}
                  disabled={!autoConfigured && !auto}
                  aria-describedby={
                    autoConfigured ? undefined : "auto-cve-missing"
                  }
                  onChange={(e) => setAuto(e.target.checked)}
                />
                Automatically analyze eligible CVEs with the resolved CVE
                profile
              </label>
              {!autoConfigured && (
                <p className="hint warning" id="auto-cve-missing">
                  Unavailable until you add {joinList(autoMissing)}.
                </p>
              )}
            </div>
            <p className="hint full">
              Analysis requires saved criteria, a confirmed product match, and a
              compatible account profile. Missing or v2-only scores remain
              visible as unscored.
            </p>
          </div>
        </Panel>
        <Panel
          title="Agent profile overrides"
          description="Leave an operation unchecked to inherit its global default. Job dialogs allow one-time overrides."
        >
          {operations.map((operation) => (
            <details className="profile-override" key={operation}>
              <summary>
                {operationNames[operation]}
                <span>
                  {profiles[operation]
                    ? `${profiles[operation].agent} · ${profiles[operation].model_id || "not configured"}`
                    : "Global default"}
                </span>
              </summary>
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={!!profiles[operation]}
                  onChange={(e) =>
                    setProfiles((previous) => {
                      const next = { ...previous };
                      if (e.target.checked)
                        next[operation] = settings.data?.default_profiles[
                          operation
                        ] || { ...emptyProfile };
                      else delete next[operation];
                      return next;
                    })
                  }
                />
                Override this operation for this application
              </label>
              {profiles[operation] && (
                <ProfileSelect
                  idPrefix={`${operation}-`}
                  accounts={accounts.data?.items || []}
                  value={profiles[operation]}
                  onChange={(profile) =>
                    setProfiles({ ...profiles, [operation]: profile })
                  }
                />
              )}
            </details>
          ))}
        </Panel>
        {error && (
          <ErrorNote>
            {error}
            {Object.keys(fields).length > 0 && (
              <ul>
                {Object.entries(fields).map(([key, value]) => (
                  <li key={key}>
                    {key}: {String(value)}
                  </li>
                ))}
              </ul>
            )}
          </ErrorNote>
        )}
        <div className="form-actions sticky-actions">
          <span className="hint form-actions-note">
            Saving does not run an agent.{" "}
            {enabled
              ? "The initial source check is queued when monitoring is enabled."
              : "Monitoring is paused, so no check is scheduled."}
          </span>
          <Link
            className="secondary button"
            to={
              application ? `/applications/${application.id}` : "/applications"
            }
          >
            Cancel
          </Link>
          <button className="primary" disabled={busy}>
            <Save size={16} />
            {busy ? "Saving…" : "Save application"}
          </button>
        </div>
      </form>
    </>
  );
}
function joinList(items: string[]) {
  return items.length < 2
    ? items.join("")
    : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}
