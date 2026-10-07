import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Save } from "lucide-react";
import { ApiError, mutate } from "../api";
import { useResource } from "../hooks";
import {
  accountsSchema,
  operationNames,
  operations,
  programSchema,
  settingsSchema,
} from "../types";
import type { Profile, Program } from "../types";
import {
  ProfileSelect,
  emptyProfile,
  isProfileReady,
} from "../components/ProfileSelect";
import {
  DataState,
  ErrorNote,
  PageHeading,
  Panel,
  notify,
} from "../components/ui";
export function ProgramForm() {
  const { id } = useParams();
  const settings = useResource("/settings", settingsSchema);
  return id ? (
    <EditProgram id={id} />
  ) : (
    <DataState
      loading={settings.loading}
      error={settings.error}
      retry={settings.refresh}
    >
      {settings.data && (
        <ProgramEditor defaultDays={settings.data.monitor_interval_days} />
      )}
    </DataState>
  );
}
function EditProgram({ id }: { id: string }) {
  const resource = useResource(
    `/programs/${encodeURIComponent(id)}`,
    programSchema,
  );
  return (
    <DataState
      loading={resource.loading}
      error={resource.error}
      retry={resource.refresh}
    >
      {resource.data && (
        <ProgramEditor
          key={resource.data.id}
          program={resource.data}
          defaultDays={null}
        />
      )}
    </DataState>
  );
}
function ProgramEditor({
  program,
  defaultDays,
}: {
  program?: Program;
  defaultDays: number | null;
}) {
  const navigate = useNavigate();
  const accounts = useResource("/accounts", accountsSchema);
  const settings = useResource("/settings", settingsSchema);
  const [name, setName] = useState(program?.asset_name || "");
  const [url, setUrl] = useState(program?.asset_url || "");
  const [kind, setKind] = useState(program?.product_kind || "CMS");
  const [product, setProduct] = useState(program?.product_name || "");
  const [source, setSource] = useState(program?.source_kind || "github");
  const [repo, setRepo] = useState(program?.source_url || "");
  const [ref, setRef] = useState(program?.source_ref || "");
  const [path, setPath] = useState(program?.source_path || "");
  const [slug, setSlug] = useState(program?.plugin_slug || "");
  const [inherit, setInherit] = useState(
    program
      ? program.config.monitor_interval_inherited === true ||
          program.monitor_interval_days === null
      : true,
  );
  const [days, setDays] = useState(
    String(program?.monitor_interval_days || defaultDays || ""),
  );
  const [enabled, setEnabled] = useState(program?.monitor_enabled ?? true);
  const [triage, setTriage] = useState(
    program?.config.triage_mode || "disabled",
  );
  const [profiles, setProfiles] = useState<Record<string, Profile>>(
    program?.config.profiles || {},
  );
  const [minScore, setMinScore] = useState(
    String(program?.config.cve_min_score ?? ""),
  );
  const [versions, setVersions] = useState(program?.config.cve_versions || []);
  const [auto, setAuto] = useState(program?.config.cve_auto_analyze || false);
  const [auditRefresh, setAuditRefresh] = useState(
    program?.config.audit_auto_refresh || false,
  );
  const [selectors, setSelectors] = useState(() =>
    Array.isArray(program?.config.cve_selectors)
      ? program.config.cve_selectors
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
    typeof program?.config.version_scheme === "string"
      ? program.config.version_scheme
      : "unknown",
  );
  const [versionEnabled, setVersionEnabled] = useState(
    program?.config.version_monitor_enabled !== false,
  );
  const [origins, setOrigins] = useState(
    Array.isArray(program?.config.asset_origins)
      ? program.config.asset_origins.join("\n")
      : "",
  );
  const [jev, setJev] = useState(
    typeof program?.config.jev_connection_id === "string"
      ? program.config.jev_connection_id
      : "",
  );
  const [jevModel, setJevModel] = useState(program?.config.jev_model_id || "");
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
          to: program ? `/programs/${program.id}` : "/programs",
          label: program ? "Back to program" : "All programs",
        }}
        eyebrow={program ? "Program configuration" : "Asset inventory"}
        title={program ? "Edit program" : "Insert program"}
        description="Define the deployed asset, its upstream software, and the evidence you want to collect."
      />
      <form
        className="program-form"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          setFields({});
          const config = {
            ...program?.config,
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
              program ? `/programs/${program.id}` : "/programs",
              programSchema,
              {
                asset_name: name,
                asset_url: url,
                product_kind: kind,
                product_name: product,
                source_kind: source,
                source_url: source === "github" ? repo : null,
                source_ref: ref || null,
                source_path: path || null,
                plugin_slug: source === "wordpress" ? slug : null,
                monitor_interval_days: inherit ? null : Number(days),
                monitor_enabled: enabled,
                archived: program?.archived || false,
                config,
              },
              program ? "PATCH" : "POST",
            );
            notify(program ? "Program updated." : "Program created.");
            navigate(`/programs/${saved.id}`);
          } catch (err) {
            setError(
              err instanceof Error
                ? err.message
                : "Unable to save the program.",
            );
            if (err instanceof ApiError) setFields(err.fields);
          } finally {
            setBusy(false);
          }
        }}
      >
        <Panel
          title="Asset & software"
          description="One program represents one deployed asset / software pair."
        >
          <div className="form-grid">
            <label>
              Asset name
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
          title="Upstream source"
          description="Choose the source history to monitor. WordPress sources do not require a GitHub repository."
        >
          <div className="form-grid">
            <label>
              Source type
              <select
                value={source}
                onChange={(e) => {
                  if (
                    e.target.value === "github" ||
                    e.target.value === "wordpress"
                  )
                    setSource(e.target.value);
                }}
              >
                <option value="github">GitHub repository</option>
                <option value="wordpress">
                  WordPress plugin release history
                </option>
              </select>
            </label>
            {source === "github" ? (
              <label>
                GitHub repository
                <input
                  required
                  type="url"
                  value={repo}
                  onChange={(e) => setRepo(e.target.value)}
                  placeholder="https://github.com/owner/repository"
                />
                {fieldError("source_url")}
              </label>
            ) : (
              <label>
                WordPress plugin slug
                <input
                  required
                  pattern="[a-z0-9][a-z0-9-]*"
                  value={slug}
                  onChange={(e) => setSlug(e.target.value)}
                  placeholder="plugin-slug"
                />
                {fieldError("plugin_slug")}
              </label>
            )}
            <label>
              {source === "github" ? "Branch / ref" : "SVN subtree"}
              <input
                value={ref}
                onChange={(e) => setRef(e.target.value)}
                placeholder={source === "github" ? "Default branch" : "trunk"}
              />
            </label>
            <label>
              Source path (optional)
              <input
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="src/"
              />
              {fieldError("source_path")}
            </label>
            {source === "wordpress" && (
              <p className="hint full">
                Release source: https://plugins.svn.wordpress.org/
                {slug || "{plugin-slug}"}/{ref || "trunk"}
              </p>
            )}
          </div>
        </Panel>
        <Panel
          title="Monitoring"
          description="The interval is elapsed whole days. Manual checks remain available when paused."
        >
          <div className="form-grid">
            <div className="field-stack">
              <label>
                Check interval in days
                <input
                  type="number"
                  required={!inherit}
                  disabled={inherit}
                  min={1}
                  max={3650}
                  step={1}
                  value={
                    inherit
                      ? String(settings.data?.monitor_interval_days ?? "")
                      : days
                  }
                  onChange={(e) => setDays(e.target.value)}
                />
                {fieldError("monitor_interval_days")}
              </label>
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={inherit}
                  onChange={(e) => setInherit(e.target.checked)}
                />
                Use the global default (
                {settings.data?.monitor_interval_days ?? "not configured"} days)
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
                Check this program on its interval
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
                  triage profile. Configure a program override below or the
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
          description="Generate and inspect reusable recipes from the program’s Version tab after saving."
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
                Override this operation for this program
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
            to={program ? `/programs/${program.id}` : "/programs"}
          >
            Cancel
          </Link>
          <button className="primary" disabled={busy}>
            <Save size={16} />
            {busy ? "Saving…" : "Save program"}
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
