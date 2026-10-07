import { useState } from "react";
import type { ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import {
  Archive,
  ArchiveRestore,
  ArrowRight,
  Check,
  FileSearch,
  Pause,
  PencilLine,
  Play,
  RefreshCw,
  Sparkles,
} from "lucide-react";
import { mutate } from "../api";
import type { Collection } from "../hooks";
import { useCollection, useResource } from "../hooks";
import {
  auditsSchema,
  programSchema,
  programState,
  recipesSchema,
  versionSchema,
  versionsSchema,
} from "../types";
import {
  commitsSchema,
  cvesSchema,
  findingSummariesSchema,
  jobsSchema,
} from "../types";
import type {
  Commit,
  CVE,
  FindingSummary,
  Job,
  Operation,
  Program,
} from "../types";
import { JobLaunch, queueJob } from "../components/JobLaunch";
import { ArtifactBrowser } from "../components/ArtifactPreview";
import {
  ActionButton,
  Badge,
  Callout,
  DataState,
  describeError,
  DetailGrid,
  Empty,
  ErrorNote,
  Evidence,
  ExternalLink,
  Modal,
  notify,
  PageHeading,
  Panel,
  Tabs,
  sentence,
  Time,
} from "../components/ui";
import { AuditTab } from "./AuditContext";
import { CommitList, sortCommits } from "./Commits";
import { CVEList, cveRows } from "./CVEs";
import { FindingsList } from "./Findings";
import { failureGroups } from "./Jobs";
import { jobName, jobOutcome } from "../jobSummary";
type VersionRecord = NonNullable<Program["version"]>;
export function ProgramDetail() {
  const { id } = useParams();
  const resource = useResource(
    `/programs/${encodeURIComponent(id || "")}`,
    programSchema,
    30000,
  );
  return (
    <DataState
      loading={resource.loading}
      error={resource.error}
      retry={resource.refresh}
      hasData={!!resource.data}
    >
      {resource.data && (
        <ProgramBody program={resource.data} refresh={resource.refresh} />
      )}
    </DataState>
  );
}
function runCheck(program: Program) {
  return queueJob(
    `/programs/${program.id}/checks`,
    {},
    undefined,
    "Source check queued.",
  );
}
function runVersionCheck(program: Program) {
  return queueJob(
    `/programs/${program.id}/version-checks`,
    {},
    undefined,
    "Version check queued.",
  );
}
function ProgramBody({
  program,
  refresh,
}: {
  program: Program;
  refresh: () => void;
}) {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") || "overview";
  const [launch, setLaunch] = useState<Operation>();
  // The audit context a launched audit job refreshes, when it refreshes one.
  const [refreshContext, setRefreshContext] = useState<{
    id: string;
    revision: string;
  }>();
  const [manual, setManual] = useState(false);
  const failure = program.last_error;
  const data = useProgramData(program);
  const count = (c: { data?: { items: unknown[] } }) => c.data?.items.length;
  return (
    <>
      <PageHeading
        back={{ to: "/programs", label: "All programs" }}
        eyebrow={`${program.product_name} · ${program.product_kind}`}
        title={program.asset_name}
        description={
          <ExternalLink href={program.asset_url}>
            {program.asset_url}
          </ExternalLink>
        }
        actions={
          <>
            <Link
              className="secondary button"
              to={`/programs/${program.id}/edit`}
            >
              <PencilLine size={15} aria-hidden="true" />
              Edit
            </Link>
            <ActionButton
              className="secondary"
              disabled={program.archived}
              onAction={async () => {
                await mutate(
                  `/programs/${program.id}`,
                  programSchema,
                  { monitor_enabled: !program.monitor_enabled },
                  "PATCH",
                );
                notify(
                  program.monitor_enabled
                    ? "Scheduled monitoring paused. Manual checks remain available."
                    : "Scheduled monitoring resumed.",
                );
                refresh();
              }}
            >
              {program.monitor_enabled ? (
                <Pause size={15} aria-hidden="true" />
              ) : (
                <Play size={15} aria-hidden="true" />
              )}
              {program.monitor_enabled ? "Pause" : "Resume"}
            </ActionButton>
            <ActionButton
              className="primary"
              onAction={() => runCheck(program)}
            >
              <RefreshCw size={15} aria-hidden="true" />
              Check now
            </ActionButton>
          </>
        }
        meta={
          <>
            <Badge>{programState(program)}</Badge>
            <span>
              Every {program.monitor_interval_days ?? "default"} days
              {program.config.monitor_interval_inherited
                ? " (global default)"
                : ""}
            </span>
            <span>
              Last check <Time value={program.last_check_at} />
            </span>
            <span>
              {program.monitor_enabled && !program.archived ? (
                <>
                  Next check{" "}
                  <Time value={program.next_check_at} fallback="pending" />
                </>
              ) : (
                "Scheduled checks paused"
              )}
            </span>
          </>
        }
      />
      {!!failure && (
        <ErrorNote>
          <strong>Last source check failed.</strong>{" "}
          {sentence(
            describeError(failure) || "The source could not be checked",
          )}{" "}
          {program.last_check_at && (
            <>
              Last attempt <Time value={program.last_check_at} />. Earlier
              evidence is retained.
            </>
          )}
          <div className="callout-actions">
            <ActionButton
              className="secondary"
              onAction={() => runCheck(program)}
            >
              <RefreshCw size={14} aria-hidden="true" />
              Retry check
            </ActionButton>
          </div>
          <Evidence value={failure} label="Failure details" />
        </ErrorNote>
      )}
      <Tabs
        label="Program sections"
        items={[
          { id: "overview", label: "Overview" },
          { id: "version", label: "Version" },
          { id: "commits", label: "Commits", count: count(data.commits) },
          { id: "audit", label: "Audit context", count: count(data.audits) },
          { id: "cves", label: "CVEs", count: count(data.cves) },
          { id: "findings", label: "Findings", count: count(data.findings) },
        ]}
        active={tab}
        onChange={(id) => setParams({ tab: id })}
      />
      {tab === "overview" && (
        <>
          <ProgramGlance program={program} data={data} />
          {!program.version && (data.cves.data?.items.length || 0) > 0 && (
            <Callout
              tone="warm"
              title={`Target applicability is unknown for all ${data.cves.data?.items.length} CVEs`}
              action={
                <div className="inline-actions">
                  <button
                    className="secondary"
                    onClick={() => setLaunch("version_recipe")}
                  >
                    Generate recipe
                  </button>
                  <button className="secondary" onClick={() => setManual(true)}>
                    Record manual version
                  </button>
                </div>
              }
            >
              The deployed version of {program.asset_url} has not been observed,
              so Numen cannot tell which CVEs affect it.
            </Callout>
          )}
          <div className="detail-columns">
            <div className="column-stack">
              <SetupChecklist
                program={program}
                data={data}
                onGenerateRecipe={() => setLaunch("version_recipe")}
                onManual={() => setManual(true)}
                onGenerateContext={() => setLaunch("audit_context")}
              />
              <VersionSummary
                program={program}
                onGenerate={() => setLaunch("version_recipe")}
                onManual={() => setManual(true)}
                onHistory={() => setParams({ tab: "version" })}
              />
            </div>
            <div className="column-stack">
              <RecentJobs program={program} data={data} />
              <ProgramConfiguration program={program} refresh={refresh} />
            </div>
          </div>
        </>
      )}
      {tab === "version" && (
        <VersionTab
          program={program}
          onGenerate={() => setLaunch("version_recipe")}
          onManual={() => setManual(true)}
        />
      )}
      {tab === "commits" && (
        <CommitList program={program} collection={data.commits} />
      )}
      {tab === "audit" && (
        <AuditTab
          program={program}
          onGenerate={() => setLaunch("audit_context")}
          onRefresh={(context) => {
            setRefreshContext({ id: context.id, revision: context.source_ref });
            setLaunch("audit_context");
          }}
        />
      )}
      {tab === "cves" && <CVEList program={program} collection={data.cves} />}
      {tab === "findings" && <FindingsList program={program} />}
      {launch && (
        <JobLaunch
          operation={launch}
          path={`/programs/${program.id}/${launch === "audit_context" ? "audit-contexts" : "version-recipes"}`}
          initialProfile={program.config.profiles[launch]}
          context={`${program.product_name} · ${program.source_ref || "default source ref"} · source generation ${program.source_generation}`}
          refresh={launch === "audit_context" ? refreshContext : undefined}
          onClose={() => {
            setLaunch(undefined);
            setRefreshContext(undefined);
          }}
          onSubmitted={refresh}
        />
      )}
      {manual && (
        <ManualVersion
          program={program}
          onClose={() => setManual(false)}
          refresh={refresh}
        />
      )}
    </>
  );
}
/** Confidence arrives as a level string or as `{level, basis}`. */
function confidenceOf(value: unknown) {
  if (typeof value === "string") return { level: value };
  const level =
    typeof value === "object" && value && "level" in value
      ? String(value.level)
      : undefined;
  const basis =
    typeof value === "object" && value && "basis" in value
      ? String(value.basis)
      : undefined;
  return { level, basis };
}
function versionLabel(version: VersionRecord) {
  return version.version || version.candidates?.join(" / ") || "Unknown";
}
function VersionFacts({ version }: { version: VersionRecord }) {
  return (
    <>
      <DetailGrid
        items={[
          [
            "Evidence method",
            version.origin === "manual"
              ? "Manual observation"
              : version.method || "Script observation",
          ],
          [
            "Confidence basis",
            confidenceOf(version.confidence).basis ||
              confidenceOf(version.confidence).level ||
              (version.confidence
                ? "See observation evidence"
                : "Not reported"),
          ],
          ["Checked", <Time value={version.checked_at} absolute />],
          [
            "Recipe revision",
            version.recipe_id ? (
              <span className="mono">{version.recipe_id.slice(0, 16)}</span>
            ) : version.origin === "manual" ? (
              "Not applicable"
            ) : (
              "Not recorded"
            ),
          ],
        ]}
      />
      {!!version.limitations?.length && (
        <ul className="limitations">
          {version.limitations.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
    </>
  );
}
function VersionSummary({
  program,
  onGenerate,
  onManual,
  onHistory,
}: {
  program: Program;
  onGenerate: () => void;
  onManual: () => void;
  onHistory: () => void;
}) {
  const version = program.version;
  const latest = program.latest_version_check;
  const hasRecipe = !!program.config.active_recipe_id;
  return (
    <Panel
      title="Deployed version"
      description="Observed on the remote asset"
      actions={
        <button className="secondary" onClick={onHistory}>
          Version history
        </button>
      }
      padded
    >
      {latest?.status === "error" && (
        <Callout
          tone="danger"
          title="Latest version check failed"
          action={
            hasRecipe && (
              <ActionButton
                className="secondary"
                onAction={() => runVersionCheck(program)}
              >
                Retry
              </ActionButton>
            )
          }
        >
          {sentence(
            describeError(latest.error) || "The check did not produce a result",
          )}{" "}
          {version ? (
            <>
              Last successful observation:{" "}
              <strong>{versionLabel(version)}</strong>
              , <Time value={version.checked_at} />.
            </>
          ) : (
            "No successful observation yet."
          )}
        </Callout>
      )}
      {version ? (
        <>
          <div className="version-hero">
            <span className="version-number">{versionLabel(version)}</span>
            <Badge>{version.status}</Badge>
            {version.origin === "manual" && (
              <Badge tone="neutral">Manual</Badge>
            )}
          </div>
          {version.status === "ambiguous" && (
            <Callout
              tone="warm"
              title={`${version.candidates?.length || "Several"} candidate versions`}
              action={
                <button className="secondary" onClick={onManual}>
                  Record manual version
                </button>
              }
            >
              The site&apos;s published files match more than one release, and
              these releases ship identical front-end files, so a remote check
              cannot tell them apart. Record a manual observation if you have
              independent evidence of the exact release.
            </Callout>
          )}
          <VersionFacts version={version} />
          <p className="hint">
            Confidence is a supported judgment, not a guarantee of the deployed
            identity.
          </p>
          <Evidence value={version} label="Observation evidence" />
        </>
      ) : hasRecipe ? (
        <Empty
          icon={FileSearch}
          title="Version not observed yet"
          description="A validated recipe is configured. Run a check to observe the deployed version."
          action={
            <ActionButton
              className="primary"
              onAction={() => runVersionCheck(program)}
            >
              <RefreshCw size={15} aria-hidden="true" />
              Run check
            </ActionButton>
          }
        />
      ) : (
        <Empty
          icon={FileSearch}
          title="Version check not configured"
          description="Generate a reusable recipe with an agent profile, or record an independent manual observation."
          action={
            <div className="inline-actions">
              <button className="primary" onClick={onGenerate}>
                <Sparkles size={15} aria-hidden="true" />
                Generate recipe
              </button>
              <button className="secondary" onClick={onManual}>
                Record manual version
              </button>
            </div>
          }
        />
      )}
    </Panel>
  );
}
function ProgramConfiguration({
  program,
  refresh,
}: {
  program: Program;
  refresh: () => void;
}) {
  const selectors = program.config.cve_selectors;
  return (
    <Panel title="Configuration" padded>
      <DetailGrid
        items={[
          [
            "Upstream source",
            program.source_kind === "wordpress" ? (
              <ExternalLink href={program.source_url}>
                WordPress · {program.plugin_slug}
              </ExternalLink>
            ) : (
              <ExternalLink href={program.source_url}>
                {program.source_url?.replace("https://github.com/", "") ||
                  "Not configured"}
              </ExternalLink>
            ),
          ],
          ["Source ref", program.source_ref || "Default branch"],
          ["Source path", program.source_path || "Entire source"],
          ["Source generation", program.source_generation],
          ["Triage", humanTriage(program.config.triage_mode)],
          [
            "CVE threshold",
            program.config.cve_min_score ?? (
              <span className="muted">Not configured</span>
            ),
          ],
          [
            "CVSS versions",
            program.config.cve_versions.join(", ") || (
              <span className="muted">Not configured</span>
            ),
          ],
          [
            "Auto CVE analysis",
            program.config.cve_auto_analyze ? "Enabled" : "Off",
          ],
          [
            "Audit context refresh",
            program.config.audit_auto_refresh
              ? "After each source change"
              : "Manual",
          ],
        ]}
      />
      <div className="field-block">
        <span className="field-label">CVE identity selectors</span>
        {selectors.length ? (
          <div className="chip-row">
            {selectors.map((selector) => (
              <code className="chip" key={selector.value}>
                {selector.type === "keyword" ? "keyword: " : ""}
                {selector.value}
              </code>
            ))}
          </div>
        ) : (
          <p className="muted">
            None. CVE sync needs a CPE identity or keyword.
          </p>
        )}
      </div>
      <div className="panel-footer">
        <p className="hint">
          Archiving suppresses scheduled work and keeps findings and evidence.
        </p>
        <ActionButton
          className="secondary"
          confirm={program.archived ? undefined : "Confirm archive"}
          onAction={async () => {
            await mutate(
              `/programs/${program.id}`,
              programSchema,
              { archived: !program.archived },
              "PATCH",
            );
            notify(
              program.archived ? "Program restored." : "Program archived.",
            );
            refresh();
          }}
        >
          {program.archived ? (
            <ArchiveRestore size={15} aria-hidden="true" />
          ) : (
            <Archive size={15} aria-hidden="true" />
          )}
          {program.archived ? "Restore program" : "Archive program"}
        </ActionButton>
      </div>
    </Panel>
  );
}
function humanTriage(mode: string) {
  return (
    {
      disabled: "Disabled — manual review",
      jev: "Jev typed classification",
      pi: "Pi",
      claude: "Claude Code",
      codex: "Codex CLI",
    }[mode] || mode
  );
}
type FingerprintCoverage = {
  releases: string[];
  distinguishing: number;
  groups: string[][];
};
function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}
/** What a recipe's release corpus can tell apart, from its saved metadata. */
function fingerprintCoverage(metadata: unknown): FingerprintCoverage {
  const coverage = record(record(metadata)?.corpus_coverage);
  const releases = Array.isArray(coverage?.releases)
    ? coverage.releases
        .map((release) => record(release)?.version)
        .filter((version): version is string => typeof version === "string")
    : [];
  const groups = Array.isArray(coverage?.resolution)
    ? coverage.resolution.filter(
        (group): group is string[] =>
          Array.isArray(group) && group.every((v) => typeof v === "string"),
      )
    : [];
  return {
    releases,
    distinguishing:
      typeof coverage?.distinguishing_paths === "number"
        ? coverage.distinguishing_paths
        : 0,
    groups,
  };
}
/** Which captured releases the fingerprints can and cannot tell apart. */
function RecipeResolution({ metadata }: { metadata: unknown }) {
  const coverage = fingerprintCoverage(metadata);
  if (!coverage.releases.length)
    return (
      <p className="hint">
        No release could be captured for this recipe, so it carries no
        fingerprints to compare with the site.
      </p>
    );
  const shared = coverage.groups.filter((group) => group.length > 1);
  return (
    <p className="hint">
      Fingerprints cover {coverage.releases[coverage.releases.length - 1]} to{" "}
      {coverage.releases[0]}.{" "}
      {coverage.groups.length
        ? shared.length
          ? `Their published files separate ${coverage.groups.length} groups; ${shared.map((group) => group.join(" and ")).join("; ")} publish identical files.`
          : "Their published files tell every captured release apart."
        : ""}
    </p>
  );
}
function RecipeCoverage({ metadata }: { metadata: unknown }) {
  const coverage = fingerprintCoverage(metadata);
  if (!coverage.releases.length)
    return <Badge tone="warm">No release fingerprints</Badge>;
  return (
    <span className="recipe-coverage">
      {coverage.releases.length} releases fingerprinted ·{" "}
      {coverage.distinguishing} distinguishing{" "}
      {coverage.distinguishing === 1 ? "file" : "files"}
    </span>
  );
}
type FingerprintProbe = {
  path: string;
  versions?: string[];
  status?: number;
  error?: string;
};
/** Files Numen's fingerprint stage fetched, from an observation's evidence. */
function fingerprintProbes(evidence: unknown): FingerprintProbe[] {
  if (!Array.isArray(evidence)) return [];
  return evidence.flatMap((item) => {
    const entry = record(item);
    if (
      !entry ||
      typeof entry.path !== "string" ||
      !("versions" in entry || "status" in entry || "error" in entry)
    )
      return [];
    return [
      {
        path: entry.path,
        versions: Array.isArray(entry.versions)
          ? entry.versions.filter((v): v is string => typeof v === "string")
          : undefined,
        status: typeof entry.status === "number" ? entry.status : undefined,
        error: typeof entry.error === "string" ? entry.error : undefined,
      },
    ];
  });
}
function FingerprintList({ evidence }: { evidence: unknown }) {
  const probes = fingerprintProbes(evidence);
  if (!probes.length) return null;
  return (
    <div className="fingerprint-list">
      <span className="field-label">Release fingerprints</span>
      <ul>
        {probes.map((probe, i) => (
          <li key={`${probe.path}-${i}`}>
            <code>{probe.path}</code>
            {probe.versions?.length ? (
              <span>matches {probe.versions.join(", ")}</span>
            ) : probe.status === 200 ? (
              <span className="warning">matches no captured release</span>
            ) : (
              <span className="muted">
                not served
                {probe.status
                  ? ` (HTTP ${probe.status})`
                  : probe.error
                    ? ` (${probe.error})`
                    : ""}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
export function VersionTab({
  program,
  onGenerate,
  onManual,
}: {
  program: Program;
  onGenerate: () => void;
  onManual: () => void;
}) {
  const observations = useResource(
    `/programs/${program.id}/version-observations`,
    versionsSchema,
  );
  const recipes = useResource(
    `/programs/${program.id}/version-recipes`,
    recipesSchema,
  );
  const hasRecipe = !!program.config.active_recipe_id;
  const active = recipes.data?.items.find(
    (recipe) => recipe.id === program.config.active_recipe_id,
  );
  const unfingerprinted =
    !!active && !fingerprintCoverage(active.metadata).releases.length;
  return (
    <>
      {unfingerprinted && (
        <Callout
          tone="warm"
          title="The active recipe has no release fingerprints"
          action={
            <button className="secondary" onClick={onGenerate}>
              <Sparkles size={15} aria-hidden="true" />
              Generate recipe
            </button>
          }
        >
          No release files could be captured when it was generated, so checks
          can recognise the product but cannot narrow its version. A new recipe
          captures the releases&apos; published files and lets each check
          compare them with the site.
        </Callout>
      )}
      <Panel
        title="Version observations"
        description="Recipes are reused without another agent call. Ambiguous and failed observations keep their evidence."
        actions={
          <>
            <button className="secondary" onClick={onManual}>
              Record manual version
            </button>
            <button className="secondary" onClick={onGenerate}>
              <Sparkles size={15} aria-hidden="true" />
              Generate recipe
            </button>
            <ActionButton
              className="primary"
              disabled={!hasRecipe}
              title={hasRecipe ? undefined : "Generate a recipe first"}
              onAction={() => runVersionCheck(program)}
            >
              <RefreshCw size={15} aria-hidden="true" />
              Run check
            </ActionButton>
          </>
        }
      >
        {!hasRecipe && (
          <div className="panel-body">
            <Callout tone="warm" title="Version check not configured">
              Run check is unavailable until a validated recipe exists. Generate
              a recipe, or record a manual observation.
            </Callout>
          </div>
        )}
        <DataState
          loading={observations.loading}
          error={observations.error}
          retry={observations.refresh}
          hasData={!!observations.data}
        >
          {observations.data?.items.length ? (
            <div className="row-list">
              {observations.data.items.map((observation) => (
                <article className="observation" key={observation.id}>
                  <div className="observation-head">
                    <h3>{versionLabel(observation)}</h3>
                    <Badge>{observation.status}</Badge>
                    <Badge tone="neutral">
                      {observation.origin === "manual" ? "Manual" : "Script"}
                    </Badge>
                    <span className="observation-time">
                      <Time value={observation.checked_at} absolute />
                    </span>
                  </div>
                  {observation.status === "error" && (
                    <p className="danger-text">
                      {describeError(observation.error) ||
                        "The check failed without a reported reason."}
                    </p>
                  )}
                  <p className="observation-meta">
                    {observation.origin === "manual"
                      ? "Manual observation"
                      : observation.method || "Script observation"}
                    {confidenceOf(observation.confidence).level &&
                      ` · ${confidenceOf(observation.confidence).level}`}
                    {confidenceOf(observation.confidence).basis &&
                      ` — ${confidenceOf(observation.confidence).basis}`}
                  </p>
                  {!!observation.limitations?.length && (
                    <ul className="limitations">
                      {observation.limitations.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  )}
                  <FingerprintList evidence={observation.evidence} />
                  <Evidence
                    value={observation}
                    label="Evidence, confidence & limitations"
                  />
                </article>
              ))}
            </div>
          ) : (
            <Empty
              title="No version observations"
              description="Checks record an exact version, a candidate set, or an explicit unknown result."
            />
          )}
        </DataState>
      </Panel>
      <Panel
        title="Recipe revisions"
        description="Python source, metadata, fingerprints, and validation fixtures."
      >
        <DataState
          loading={recipes.loading}
          error={recipes.error}
          retry={recipes.refresh}
          hasData={!!recipes.data}
        >
          {recipes.data?.items.length ? (
            recipes.data.items.map((recipe) => (
              <details key={recipe.id} className="disclosure-row">
                <summary>
                  <span className="mono">{recipe.id.slice(0, 16)}</span>
                  <Badge>{recipe.status}</Badge>
                  {program.config.active_recipe_id === recipe.id && (
                    <Badge tone="accent">Active</Badge>
                  )}
                  <RecipeCoverage metadata={recipe.metadata} />
                  <span className="summary-end">
                    <Time value={recipe.created_at} absolute />
                  </span>
                </summary>
                <div className="disclosure-body">
                  <RecipeResolution metadata={recipe.metadata} />
                  <Evidence value={recipe.metadata} label="Recipe metadata" />
                </div>
                <ArtifactBrowser artifacts={recipe.artifacts} />
              </details>
            ))
          ) : (
            <Empty
              title="No recipes generated"
              description="An agent creates a reusable version script with evidence sources and fixture checks."
              action={
                <button className="secondary" onClick={onGenerate}>
                  <Sparkles size={15} aria-hidden="true" />
                  Generate recipe
                </button>
              }
            />
          )}
        </DataState>
      </Panel>
    </>
  );
}
function ManualVersion({
  program,
  onClose,
  refresh,
}: {
  program: Program;
  onClose: () => void;
  refresh: () => void;
}) {
  const [version, setVersion] = useState("");
  const [evidence, setEvidence] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <Modal
      title="Record manual observation"
      description="Use this when you have independent evidence of the deployed version. It is labeled Manual and kept separate from script observations."
      onClose={onClose}
    >
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            await mutate(
              `/programs/${program.id}/version-observations`,
              versionSchema,
              { version, evidence },
            );
            notify("Manual version observation recorded.");
            refresh();
            onClose();
          } catch (err) {
            setError(
              err instanceof Error
                ? err.message
                : "Unable to save observation.",
            );
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Observed version
          <input
            required
            data-autofocus
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            placeholder="6.5.3"
          />
        </label>
        <label>
          Evidence and source
          <textarea
            required
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
            placeholder="Where and how you observed this version"
          />
        </label>
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy}>
            {busy ? "Saving…" : "Record observation"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
type ProgramData = {
  commits: Collection<Commit>;
  cves: Collection<CVE>;
  findings: Collection<FindingSummary>;
  jobs: Collection<Job>;
  audits: { data?: { items: unknown[] } };
};
function useProgramData(program: Program): ProgramData {
  const id = program.id;
  return {
    commits: useCollection(`/programs/${id}/commits`, commitsSchema),
    cves: useCollection(`/cves?program_id=${id}`, cvesSchema),
    findings: useCollection(
      `/findings?program_id=${id}&view=summary`,
      findingSummariesSchema,
    ),
    jobs: useCollection(`/jobs?program_id=${id}`, jobsSchema, 15000, 200),
    audits: useResource(`/programs/${id}/audit-contexts`, auditsSchema),
  };
}
function StatCard({
  label,
  value,
  foot,
  to,
  tone,
}: {
  label: string;
  value: ReactNode;
  foot?: ReactNode;
  to: string;
  tone?: string;
}) {
  return (
    <Link className={`stat-card ${tone || ""}`} to={to}>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {foot && <span className="stat-foot">{foot}</span>}
    </Link>
  );
}
function ProgramGlance({
  program,
  data,
}: {
  program: Program;
  data: ProgramData;
}) {
  const cves = cveRows(data.cves.data?.items || []);
  const eligible = cves.filter((c) => c.eligible);
  const top = Math.max(...eligible.map((c) => c.best ?? 0), 0);
  const commits = sortCommits(data.commits.data?.items || []);
  const findings = data.findings.data?.items || [];
  const open = findings.filter((f) => f.status === "open").length;
  const failed = (data.jobs.data?.items || []).filter(
    (j) => j.status === "failed",
  );
  const base = `/programs/${program.id}`;
  const loading = (c: { data?: unknown }) => (c.data ? undefined : "…");
  return (
    <div className="stat-grid">
      <StatCard
        label="Deployed version"
        value={
          program.version?.version ||
          (program.version?.candidates?.length
            ? `${program.version.candidates.length} candidates`
            : "Unknown")
        }
        foot={
          program.version ? (
            <>
              Observed <Time value={program.version.checked_at} />
            </>
          ) : (
            "Not observed yet"
          )
        }
        to={`${base}?tab=version`}
        tone={program.version ? undefined : "warm"}
      />
      <StatCard
        label="CVEs"
        value={loading(data.cves) ?? cves.length}
        foot={
          data.cves.data &&
          (eligible.length
            ? `${eligible.length} eligible · top score ${top.toFixed(1)}`
            : "None meet the score criteria")
        }
        to={
          eligible.length
            ? `${base}?tab=cves&elig=eligible`
            : `${base}?tab=cves`
        }
      />
      <StatCard
        label="Revisions"
        value={loading(data.commits) ?? commits.length}
        foot={
          commits[0]?.committed_at ? (
            <>
              Latest <Time value={commits[0].committed_at} />
            </>
          ) : (
            data.commits.data && "None imported yet"
          )
        }
        to={`${base}?tab=commits`}
      />
      <StatCard
        label="Open findings"
        value={loading(data.findings) ?? open}
        foot={data.findings.data && `${findings.length} recorded`}
        to={`${base}?tab=findings`}
      />
      <StatCard
        label="Failed jobs"
        value={loading(data.jobs) ?? failed.length}
        foot={data.jobs.data && "For this program"}
        to={`/jobs?program=${program.id}&status=failed`}
        tone={failed.length ? "danger" : undefined}
      />
    </div>
  );
}
function SetupChecklist({
  program,
  data,
  onGenerateRecipe,
  onManual,
  onGenerateContext,
}: {
  program: Program;
  data: ProgramData;
  onGenerateRecipe: () => void;
  onManual: () => void;
  onGenerateContext: () => void;
}) {
  const commits = data.commits.data?.items.length || 0;
  const cves = data.cves.data?.items || [];
  const eligible = cves.filter((c) => c.eligible).length;
  const config = program.config;
  const criteria =
    config.cve_selectors.length > 0 &&
    config.cve_min_score != null &&
    config.cve_versions.length > 0;
  const edit = (
    <Link className="secondary button" to={`/programs/${program.id}/edit`}>
      Edit program
    </Link>
  );
  const steps: {
    title: string;
    done: boolean;
    detail: ReactNode;
    action?: ReactNode;
  }[] = [
    {
      title: "Import source history",
      done: commits > 0,
      detail:
        commits > 0
          ? `${commits} revisions imported`
          : "Run a source check to import upstream revisions.",
      action: (
        <ActionButton className="secondary" onAction={() => runCheck(program)}>
          Check now
        </ActionButton>
      ),
    },
    {
      title: "Observe the deployed version",
      done: !!program.version,
      detail: program.version
        ? `Observed ${program.version.version || "candidate versions"}`
        : cves.length
          ? `Needed to decide whether the ${cves.length} CVEs apply to this asset.`
          : "Needed to decide whether CVEs apply to this asset.",
      action: (
        <>
          <button className="secondary" onClick={onGenerateRecipe}>
            Generate recipe
          </button>
          <button className="secondary" onClick={onManual}>
            Record manually
          </button>
        </>
      ),
    },
    {
      title: "Configure CVE criteria",
      done: criteria,
      detail: criteria
        ? `${cves.length} CVEs synced · ${eligible} meet the minimum score`
        : "Add CPE selectors, a minimum Base score, and CVSS versions.",
      action: edit,
    },
    {
      title: "Build audit context",
      done: (data.audits.data?.items.length || 0) > 0,
      detail:
        "Gives CVE analysis and finding artifacts a source-referenced map of the code to start from.",
      action: (
        <button className="secondary" onClick={onGenerateContext}>
          Generate context
        </button>
      ),
    },
    {
      title: "Enable commit triage",
      done: config.triage_mode !== "disabled",
      detail:
        config.triage_mode !== "disabled"
          ? `New revisions are classified by ${humanTriage(config.triage_mode)}.`
          : "New revisions wait for manual review.",
      action: edit,
    },
  ];
  const done = steps.filter((s) => s.done).length;
  if (done === steps.length) return null;
  return (
    <Panel
      title="Setup"
      description={`${done} of ${steps.length} steps complete`}
      actions={
        <span className="progress" aria-hidden="true">
          <span style={{ width: `${(done / steps.length) * 100}%` }} />
        </span>
      }
    >
      <ol className="checklist">
        {steps.map((step) => (
          <li key={step.title} className={step.done ? "done" : ""}>
            <span className="check-mark" aria-hidden="true">
              {step.done ? <Check size={13} /> : null}
            </span>
            <div className="checklist-main">
              <strong>
                {step.title}
                <span className="sr-only">
                  {step.done ? " (complete)" : " (to do)"}
                </span>
              </strong>
              <span>{step.detail}</span>
            </div>
            {!step.done && step.action && (
              <div className="inline-actions">{step.action}</div>
            )}
          </li>
        ))}
      </ol>
    </Panel>
  );
}
function RecentJobs({
  program,
  data,
}: {
  program: Program;
  data: ProgramData;
}) {
  const items = data.jobs.data?.items || [];
  const failures = failureGroups(items);
  return (
    <Panel
      title="Recent jobs"
      description="Background work for this program"
      actions={
        <Link className="inline-link" to={`/jobs?program=${program.id}`}>
          All jobs
          <ArrowRight size={14} aria-hidden="true" />
        </Link>
      }
    >
      <DataState
        loading={data.jobs.loading}
        error={data.jobs.error}
        retry={data.jobs.refresh}
        hasData={!!data.jobs.data}
      >
        {failures[0] && failures[0].count > 1 && (
          <Link
            className="failure-banner"
            to={`/jobs?program=${program.id}&status=failed&q=${encodeURIComponent(failures[0].reason)}`}
          >
            <strong>{failures[0].count}× failed</strong>
            <span className="clamp">{failures[0].reason}</span>
          </Link>
        )}
        {items.length ? (
          <div className="row-list">
            {items.slice(0, 6).map((job) => (
              <Link key={job.id} to={`/jobs/${job.id}`} className="job-row">
                <Badge>{job.status}</Badge>
                <span className="job-row-main">
                  <strong>
                    {jobName(job.kind)}
                    {job.subject && (
                      <span className="muted">: {job.subject.label}</span>
                    )}
                  </strong>
                  <span className={`clamp job-outcome ${jobOutcome(job).tone}`}>
                    {jobOutcome(job).summary}
                  </span>
                </span>
                <small>
                  <Time value={job.finished_at || job.created_at} />
                </small>
              </Link>
            ))}
          </div>
        ) : (
          <Empty
            title="No jobs yet"
            description="Checks and agent operations for this program appear here."
          />
        )}
      </DataState>
    </Panel>
  );
}
