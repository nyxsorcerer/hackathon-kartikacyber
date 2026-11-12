import { useCallback, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import {
  Check,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";
import { mutate } from "../api";
import type { Collection } from "../hooks";
import {
  useCollection,
  useQueryState,
  useResource,
  useShortcut,
} from "../hooks";
import {
  cveSchema,
  cvesSchema,
  applicationSchema,
  applicationsSchema,
  safeHref,
} from "../types";
import type { CVE, Application } from "../types";
import { JobLaunch, queueJob } from "../components/JobLaunch";
import {
  ActionButton,
  Badge,
  Callout,
  countBy,
  DataState,
  DetailGrid,
  Empty,
  Evidence,
  ExternalLink,
  FilterSelect,
  Kbd,
  matches,
  Modal,
  PageHeading,
  Panel,
  ResultSummary,
  SearchField,
  Segmented,
  Tabs,
  severityLabels,
  severityOf,
  Time,
  useShowMore,
} from "../components/ui";
import type { Severity } from "../components/ui";
import { CVEAnalysisResults } from "../components/CVEAnalysisResults";
type Score = CVE["scores"][number];
type Row = CVE & { best?: number; severity: Severity; published: number };
/** Only CVSS v3/v4 Base scores count; v2-only records are unscored. */
function counted(score: Score) {
  return /^[34]/.test(score.version);
}
const shortReasons: Record<string, string> = {
  "No selected scoring version meets the minimum Base score":
    "Below minimum score",
  "Product identity requires confirmation": "Product match unconfirmed",
  "Save scoring versions and a minimum Base score": "Criteria not configured",
  "CVE record is rejected": "Rejected record",
};
function shortReason(reason: string) {
  return shortReasons[reason] || reason;
}
function qualifies(cve: CVE, score: Score) {
  const q = cve.qualifying_score;
  return (
    !!q &&
    q.version === score.version &&
    q.source === score.source &&
    q.vector === score.vector
  );
}
function referenceUrl(reference: unknown) {
  const href =
    typeof reference === "string"
      ? reference
      : typeof reference === "object" &&
          reference &&
          "url" in reference &&
          typeof reference.url === "string"
        ? reference.url
        : null;
  return href && safeHref(href) ? href : undefined;
}
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge tone={severity === "none" ? "neutral" : `sev-${severity}`}>
      {severityLabels[severity]}
    </Badge>
  );
}
export function cveRows(items: CVE[]): Row[] {
  return items.map((cve) => {
    const scores = cve.scores.filter(counted).map((s) => s.base_score);
    const best = scores.length ? Math.max(...scores) : undefined;
    return {
      ...cve,
      best,
      severity: severityOf(best),
      published: cve.published_at ? Date.parse(cve.published_at) || 0 : 0,
    };
  });
}
const defaults = {
  q: "",
  elig: "all",
  sev: "all",
  app: "all",
  application: "all",
  sort: "score",
  cve: "",
  cve_application: "",
  act: "",
  view: "overview",
  run: "",
  // Accept links already emitted by job details and CVE notifications.
  cve_id: "",
  application_id: "",
};
type Filters = typeof defaults;
const pagerKeys = ["j", "k"];
const sorters: Record<string, (a: Row, b: Row) => number> = {
  score: (a, b) => (b.best ?? -1) - (a.best ?? -1) || b.published - a.published,
  newest: (a, b) => b.published - a.published,
  oldest: (a, b) => a.published - b.published,
  id: (a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }),
};
function applyFilters(rows: Row[], f: Filters, skip?: keyof Filters) {
  return rows.filter(
    (cve) =>
      matches(f.q, cve.id, cve.title, cve.description) &&
      (skip === "elig" ||
        f.elig === "all" ||
        (f.elig === "eligible") === cve.eligible) &&
      (skip === "sev" || f.sev === "all" || cve.severity === f.sev) &&
      (skip === "app" || f.app === "all" || cve.applicability === f.app) &&
      (skip === "application" ||
        f.application === "all" ||
        cve.application_id === f.application),
  );
}
export function CVEs() {
  return (
    <>
      <PageHeading
        eyebrow="Vulnerability intelligence"
        title="CVEs"
        description="Product matching, score eligibility, and deployed-version applicability are separate judgments."
      />
      <CVEList />
    </>
  );
}
export function CVEList({
  application,
  collection,
}: {
  application?: Application;
  collection?: Collection<CVE>;
}) {
  const own = useCollection(
    collection
      ? null
      : application
        ? `/cves?application_id=${application.id}`
        : "/cves",
    cvesSchema,
  );
  const cves = collection || own;
  const applications = useResource(
    application ? null : "/applications",
    applicationsSchema,
  );
  const [filters, update] = useQueryState(defaults);
  const applicationName = (id: string) =>
    applications.data?.items.find((p) => p.id === id)?.asset_name;
  const rows = useMemo(() => cveRows(cves.data?.items || []), [cves.data]);
  const visible = useMemo(
    () =>
      applyFilters(rows, filters).sort(sorters[filters.sort] || sorters.score),
    [rows, filters],
  );
  const { shown, footer } = useShowMore(
    visible,
    [
      filters.q,
      filters.elig,
      filters.sev,
      filters.app,
      filters.application,
      filters.sort,
    ].join("|"),
  );
  const facet = (key: keyof Filters, of: (row: Row) => string) =>
    countBy(applyFilters(rows, filters, key), of);
  const eligibility = facet("elig", (r) => (r.eligible ? "eligible" : "not"));
  const severity = facet("sev", (r) => r.severity);
  const applicability = facet("app", (r) => r.applicability);
  const byApplication = facet("application", (r) => r.application_id);
  const selectedId = filters.cve || filters.cve_id;
  const selectedApplication = filters.cve_application || filters.application_id;
  const selected = selectedId
    ? rows.find(
        (row) =>
          row.id === selectedId &&
          (application ||
            !selectedApplication ||
            row.application_id === selectedApplication),
      )
    : undefined;
  const open = (cve?: CVE, act?: "analyze", view = filters.view) =>
    update({
      cve: cve?.id || null,
      cve_application: application ? null : cve?.application_id,
      act: act || null,
      view: cve ? view : null,
      run:
        cve?.id === selected?.id &&
        cve?.application_id === selected?.application_id
          ? filters.run
          : null,
      cve_id: null,
      application_id: null,
    });
  const analyze =
    filters.act === "analyze" && selected?.eligible ? selected : undefined;
  const clear = () =>
    update({ q: "", elig: "all", sev: "all", app: "all", application: "all" });
  return (
    <>
      <Panel
        title="CVE records"
        description={
          application
            ? `Minimum Base score ${application.config.cve_min_score ?? "not configured"} · CVSS ${application.config.cve_versions.join(", ") || "not configured"}`
            : "A qualifying score alone does not confirm the deployed asset is affected."
        }
        actions={
          <>
            <button
              type="button"
              className="secondary"
              disabled={cves.refreshing}
              onClick={cves.refresh}
            >
              <RefreshCw
                size={15}
                className={cves.refreshing ? "spin" : undefined}
                aria-hidden="true"
              />
              Refresh records
            </button>
            {application && (
              <ActionButton
                className="secondary"
                onAction={() =>
                  queueJob(
                    `/applications/${application.id}/cve-sync`,
                    {},
                    undefined,
                    "CVE sync queued.",
                  )
                }
              >
                <RefreshCw size={15} aria-hidden="true" />
                Sync CVEs
              </ActionButton>
            )}
          </>
        }
      >
        <div className="explorer-toolbar">
          <SearchField
            label="Search CVEs"
            placeholder="Search ID, title, or description"
            value={filters.q}
            onChange={(q) => update({ q })}
          />
          <Segmented
            label="Score eligibility"
            value={filters.elig}
            onChange={(elig) => update({ elig })}
            options={[
              {
                value: "all",
                label: "All",
                count: (eligibility.eligible || 0) + (eligibility.not || 0),
              },
              {
                value: "eligible",
                label: "Eligible",
                count: eligibility.eligible || 0,
              },
              {
                value: "not",
                label: "Not eligible",
                count: eligibility.not || 0,
              },
            ]}
          />
          <FilterSelect
            label="Severity"
            value={filters.sev}
            onChange={(sev) => update({ sev })}
            options={[
              { value: "all", label: "Any" },
              ...(["critical", "high", "medium", "low", "none"] as const).map(
                (value) => ({
                  value,
                  label: severityLabels[value],
                  count: severity[value] || 0,
                }),
              ),
            ]}
          />
          <FilterSelect
            label="Target"
            value={filters.app}
            onChange={(app) => update({ app })}
            options={[
              { value: "all", label: "Any" },
              ...["affected", "unknown", "not affected"].map((value) => ({
                value,
                label: value.charAt(0).toUpperCase() + value.slice(1),
                count: applicability[value] || 0,
              })),
            ]}
          />
          {!application && (applications.data?.items.length || 0) > 1 && (
            <FilterSelect
              label="Application"
              value={filters.application}
              onChange={(application) => update({ application })}
              options={[
                { value: "all", label: "All applications" },
                ...(applications.data?.items || []).map((p) => ({
                  value: p.id,
                  label: p.asset_name,
                  count: byApplication[p.id] || 0,
                })),
              ]}
            />
          )}
          <FilterSelect
            label="Sort"
            value={filters.sort}
            onChange={(sort) => update({ sort })}
            options={[
              { value: "score", label: "Highest score" },
              { value: "newest", label: "Newest published" },
              { value: "oldest", label: "Oldest published" },
              { value: "id", label: "CVE ID" },
            ]}
          />
        </div>
        <DataState
          loading={cves.loading}
          error={cves.error}
          retry={cves.refresh}
          hasData={!!cves.data}
        >
          {rows.length > 0 && (
            <div className="explorer-summary">
              <ResultSummary
                shown={visible.length}
                total={rows.length}
                noun={["CVE", "CVEs"]}
                truncated={cves.data?.truncated}
                onClear={clear}
              />
            </div>
          )}
          {visible.length ? (
            <div className="table-scroll cve-table-scroll">
              <table className="cve-table">
                <thead>
                  <tr>
                    <th scope="col">CVE</th>
                    <th scope="col">Base scores</th>
                    <th scope="col">Product match</th>
                    <th scope="col">Score eligibility</th>
                    <th scope="col">Target</th>
                    <th scope="col">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((cve) => (
                    <tr
                      key={`${cve.application_id}-${cve.id}`}
                      className="clickable-row"
                      aria-selected={selected === cve || undefined}
                      onClick={(e) => {
                        if (!(e.target as HTMLElement).closest("a, button"))
                          open(cve);
                      }}
                    >
                      <td className="cve-cell">
                        <div className="cve-heading">
                          <button
                            className="table-title text-button mono"
                            aria-haspopup="dialog"
                            onClick={() => open(cve)}
                          >
                            {cve.id}
                          </button>
                          <SeverityBadge severity={cve.severity} />
                        </div>
                        <div className="table-subtitle clamp">{cve.title}</div>
                        <div className="table-subtitle">
                          {cve.published_at && (
                            <>
                              Published <Time value={cve.published_at} />
                            </>
                          )}
                          {!application && (
                            <>
                              {cve.published_at && " · "}
                              <Link
                                to={`/applications/${cve.application_id}?tab=cves`}
                              >
                                {applicationName(cve.application_id) ||
                                  "Application"}
                              </Link>
                            </>
                          )}
                        </div>
                      </td>
                      <td data-label="Base scores">
                        <ScoreList cve={cve} />
                      </td>
                      <td data-label="Product match">
                        <Badge>{cve.match_status}</Badge>
                      </td>
                      <td data-label="Score eligibility">
                        <Badge tone={cve.eligible ? "good" : "neutral"}>
                          {cve.eligible ? "Eligible" : "Not eligible"}
                        </Badge>
                        {cve.eligibility_reason && (
                          <div
                            className="table-subtitle"
                            title={cve.eligibility_reason}
                          >
                            {shortReason(cve.eligibility_reason)}
                          </div>
                        )}
                      </td>
                      <td data-label="Target">
                        <Badge>{cve.applicability}</Badge>
                      </td>
                      <td className="cell-actions">
                        {cve.analyses.length > 0 && (
                          <button
                            className="text-button"
                            onClick={() => open(cve, undefined, "analysis")}
                            aria-label={`View analysis for ${cve.id}`}
                          >
                            View analysis{" "}
                            <span className="muted">
                              ({cve.analyses.length})
                            </span>
                          </button>
                        )}
                        <button
                          className="secondary"
                          disabled={!cve.eligible}
                          onClick={() => open(cve, "analyze")}
                          aria-label={`Analyze ${cve.id}`}
                          title={
                            !cve.eligible
                              ? cve.eligibility_reason ||
                                "Confirm the product match and score criteria to enable analysis."
                              : undefined
                          }
                        >
                          <Sparkles size={14} aria-hidden="true" />
                          Analyze
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {footer}
            </div>
          ) : rows.length ? (
            <Empty
              icon={ShieldAlert}
              title="No CVEs match these filters"
              description="Try a broader severity or eligibility filter, or a different search."
              action={
                <button className="secondary" onClick={clear}>
                  Clear filters
                </button>
              }
            />
          ) : (
            <Empty
              icon={ShieldAlert}
              title="No CVE records yet"
              description={
                application
                  ? "Configure product selectors and score criteria, then sync CVEs."
                  : "CVE records appear after a configured application synchronizes its product selectors."
              }
            />
          )}
        </DataState>
      </Panel>
      {selected && !analyze && (
        <CVEDrawer
          key={`${selected.application_id}-${selected.id}`}
          cve={selected}
          list={visible.includes(selected) ? visible : rows}
          applicationName={
            application?.asset_name || applicationName(selected.application_id)
          }
          view={filters.view}
          run={filters.run}
          onViewChange={(view) => update({ view })}
          onRunChange={(run) => update({ run })}
          onNavigate={open}
          onClose={() => open(undefined)}
          onUpdated={cves.refresh}
          onAnalyze={() => open(selected, "analyze")}
        />
      )}
      {analyze && (
        <CVEAnalysisLaunch
          cve={analyze}
          onClose={() => update({ act: null })}
          onSubmitted={cves.refresh}
        />
      )}
    </>
  );
}
/** Short label for a score source: NVD, MITRE, or the assigning CNA. */
function sourceLabel(source: string) {
  if (source === "nvd@nist.gov") return "NVD";
  if (source === "cve@mitre.org") return "MITRE";
  return /^[0-9a-f-]{36}$/i.test(source) ? "CNA" : source;
}
function ScoreList({ cve }: { cve: CVE }) {
  if (!cve.scores.length) return <span className="muted">Unscored</span>;
  const usable = cve.scores.filter(counted);
  return (
    <>
      {cve.scores.map((score, i) => (
        <div
          className={`score-line ${qualifies(cve, score) ? "qualifying" : ""} ${counted(score) ? "" : "legacy"}`}
          key={i}
        >
          <strong>{score.base_score.toFixed(1)}</strong>
          <span title={score.source}>
            v{score.version} · {sourceLabel(score.source)}
          </span>
          {qualifies(cve, score) && (
            <span className="score-flag">
              <Check size={12} aria-hidden="true" />
              meets minimum
            </span>
          )}
        </div>
      ))}
      {!usable.length && (
        <div className="table-subtitle">v2 only — treated as unscored</div>
      )}
    </>
  );
}
function CVEDrawer({
  cve,
  list,
  applicationName,
  view,
  run,
  onViewChange,
  onRunChange,
  onNavigate,
  onClose,
  onUpdated,
  onAnalyze,
}: {
  cve: Row;
  list: Row[];
  applicationName?: string;
  view: string;
  run: string;
  onViewChange: (view: string) => void;
  onRunChange: (run: string) => void;
  onNavigate: (cve: CVE) => void;
  onClose: () => void;
  onUpdated: () => void;
  onAnalyze: () => void;
}) {
  const index = list.indexOf(cve);
  const previous = index > 0 ? list[index - 1] : undefined;
  const next =
    index >= 0 && index < list.length - 1 ? list[index + 1] : undefined;
  const step = useCallback(
    (key: string) => {
      const target = key === "j" ? next : previous;
      if (target) onNavigate(target);
    },
    [next, previous, onNavigate],
  );
  useShortcut(pagerKeys, step);
  useEffect(() => {
    document.querySelector(".modal-drawer")?.scrollTo({ top: 0 });
  }, [cve.id, view]);
  const activeView = ["analysis", "scores", "references"].includes(view)
    ? view
    : "overview";
  const references = [
    ...new Set(
      cve.references.flatMap((reference) => {
        const url = referenceUrl(reference);
        return url ? [url] : [];
      }),
    ),
  ];
  async function setMatch(confirmed: boolean) {
    await mutate(
      `/applications/${cve.application_id}/cves/${cve.id}/match`,
      cveSchema,
      { confirmed },
    );
    onUpdated();
  }
  return (
    <Modal
      title={cve.id}
      description={applicationName || "CVE details and saved analysis"}
      onClose={onClose}
      size="drawer"
      headerActions={
        index >= 0 && (
          <span className="pager">
            <button
              type="button"
              className="icon-button"
              aria-label="Previous CVE"
              title="Previous (K)"
              disabled={!previous}
              onClick={() => previous && onNavigate(previous)}
            >
              <ChevronLeft size={18} aria-hidden="true" />
            </button>
            <span className="pager-position">
              {index + 1} / {list.length}
            </span>
            <button
              type="button"
              className="icon-button"
              aria-label="Next CVE"
              title="Next (J)"
              disabled={!next}
              onClick={() => next && onNavigate(next)}
            >
              <ChevronRight size={18} aria-hidden="true" />
            </button>
          </span>
        )
      }
    >
      <div className="cve-workspace">
        <div className="cve-workspace-heading">
          <div className="chip-row">
            <SeverityBadge severity={cve.severity} />
            {cve.best !== undefined && (
              <span className="muted">
                Highest v3/v4 score {cve.best.toFixed(1)}
              </span>
            )}
            <Badge tone={cve.eligible ? "good" : "neutral"}>
              {cve.eligible ? "Score eligible" : "Not eligible"}
            </Badge>
            <span className="hint">
              Target <Badge>{cve.applicability}</Badge>
            </span>
          </div>
          {!cve.description.startsWith(cve.title) && (
            <h3 className="cve-record-title">{cve.title}</h3>
          )}
          <div className="drawer-actions">
            <button
              className="primary"
              disabled={!cve.eligible}
              onClick={onAnalyze}
              aria-describedby={!cve.eligible ? "cve-analysis-gate" : undefined}
            >
              <Sparkles size={15} aria-hidden="true" />
              Analyze CVE
            </button>
            <Link
              className="secondary button"
              to={`/findings/new?application_id=${cve.application_id}&cve_id=${cve.id}`}
            >
              Create CVE finding
            </Link>
          </div>
          {!cve.eligible && cve.eligibility_reason && (
            <p className="hint warning" id="cve-analysis-gate">
              Analysis is unavailable: {cve.eligibility_reason}.
            </p>
          )}
          {cve.eligible && cve.analysis_blocked && (
            <p className="hint warning">
              Automatic analysis is waiting: {cve.analysis_blocked.message}.
            </p>
          )}
        </div>
        <Tabs
          label="CVE details"
          items={[
            { id: "overview", label: "Overview" },
            {
              id: "analysis",
              label: "Analysis & artifacts",
              count: cve.analyses.length,
            },
            { id: "scores", label: "Scores", count: cve.scores.length },
            { id: "references", label: "References", count: references.length },
          ]}
          active={activeView}
          onChange={onViewChange}
        />
        {activeView === "analysis" && (
          <section role="tabpanel" aria-label="Analysis & artifacts">
            <CVEAnalysisResults cve={cve} run={run} onRunChange={onRunChange} />
          </section>
        )}
        {activeView === "overview" && (
          <section role="tabpanel" aria-label="Overview">
            <p className="readable-copy drawer-lead">{cve.description}</p>
            <section className="drawer-section">
              <h3>Assessment</h3>
              <DetailGrid
                items={[
                  ["Product match", <Badge>{cve.match_status}</Badge>],
                  [
                    "Score eligibility",
                    <Badge tone={cve.eligible ? "good" : "neutral"}>
                      {cve.eligible ? "Eligible" : "Not eligible"}
                    </Badge>,
                  ],
                  ["Target applicability", <Badge>{cve.applicability}</Badge>],
                  [
                    "Application",
                    <Link to={`/applications/${cve.application_id}`}>
                      {applicationName || "Application details"}
                    </Link>,
                  ],
                  [
                    "Published",
                    <Time
                      value={cve.published_at}
                      absolute
                      fallback="Unknown"
                    />,
                  ],
                  [
                    "Modified",
                    <Time
                      value={cve.modified_at}
                      absolute
                      fallback="Unknown"
                    />,
                  ],
                ]}
              />
              {cve.applicability === "unknown" && (
                <p className="hint">
                  Applicability stays unknown until the deployed version is
                  observed.
                  <Link to={`/applications/${cve.application_id}?tab=version`}>
                    Check the target version
                  </Link>{" "}
                  or record a manual observation in the application.
                </p>
              )}
              <div className="inline-actions">
                <ActionButton
                  className="secondary"
                  onAction={() => setMatch(true)}
                >
                  <Check size={14} aria-hidden="true" />
                  Confirm product match
                </ActionButton>
                <ActionButton
                  className="secondary"
                  onAction={() => setMatch(false)}
                >
                  <X size={14} aria-hidden="true" />
                  Reject product match
                </ActionButton>
              </div>
            </section>
            <section className="drawer-section">
              <h3>Version evidence</h3>
              <DetailGrid
                items={[
                  ["Affected", cve.affected_versions.join(", ") || "Unknown"],
                  ["Fixed in", cve.fixed_versions.join(", ") || "Unknown"],
                  ["Observed target", <Badge>{cve.applicability}</Badge>],
                ]}
              />
            </section>
          </section>
        )}
        {activeView === "scores" && (
          <section role="tabpanel" aria-label="Scores">
            <section className="drawer-section">
              <h3>Score evidence</h3>
              {cve.scores.length ? (
                cve.scores.map((score, i) => (
                  <div
                    className={`score-evidence ${qualifies(cve, score) ? "qualifying" : ""}`}
                    key={i}
                  >
                    <div className="score-evidence-head">
                      <strong>{score.base_score.toFixed(1)}</strong>
                      <span>CVSS {score.version}</span>
                      {qualifies(cve, score) && (
                        <Badge tone="good">Meets minimum</Badge>
                      )}
                      {!counted(score) && (
                        <Badge tone="neutral">Not used</Badge>
                      )}
                    </div>
                    <code>{score.vector}</code>
                    <small>{score.source}</small>
                  </div>
                ))
              ) : (
                <p className="muted">
                  No CVSS v3 or v4 Base score. Unscored records stay visible but
                  cannot start analysis.
                </p>
              )}
            </section>
          </section>
        )}
        {activeView === "references" && (
          <section role="tabpanel" aria-label="References">
            <section className="drawer-section">
              <h3>References ({references.length})</h3>
              <ul className="reference-list">
                {references.map((href) => (
                  <li key={href}>
                    <ExternalLink href={href}>{href}</ExternalLink>
                  </li>
                ))}
              </ul>
              {!references.length && (
                <p className="hint">
                  No accessible source links were supplied for this record.
                </p>
              )}
              <Evidence value={cve.references} label="Raw source references" />
            </section>
          </section>
        )}
        <p className="hint drawer-shortcuts">
          <Kbd>J</Kbd> next · <Kbd>K</Kbd> previous · <Kbd>Esc</Kbd> close
        </p>
      </div>
    </Modal>
  );
}
function CVEAnalysisLaunch({
  cve,
  onClose,
  onSubmitted,
}: {
  cve: Row;
  onClose: () => void;
  onSubmitted: () => void;
}) {
  const resource = useResource(
    `/applications/${cve.application_id}`,
    applicationSchema,
  );
  if (!resource.data)
    return (
      <Modal
        title="CVE analysis"
        description="Resolving this application’s execution profile."
        onClose={onClose}
      >
        <DataState
          loading={resource.loading}
          error={resource.error}
          retry={resource.refresh}
        >
          <p>Loading application configuration…</p>
        </DataState>
        <div className="form-actions">
          <button className="secondary" onClick={onClose}>
            Cancel
          </button>
        </div>
      </Modal>
    );
  return (
    <JobLaunch
      operation="cve_analysis"
      path={`/applications/${cve.application_id}/cves/${cve.id}/analyses`}
      initialProfile={resource.data.config.profiles.cve_analysis}
      context={
        <div className="cve-launch-context">
          <div className="chip-row">
            <strong className="mono">{cve.id}</strong>
            <SeverityBadge severity={cve.severity} />
          </div>
          <p>{cve.title}</p>
          <DetailGrid
            items={[
              ["Application", resource.data.asset_name],
              ["Product match", <Badge>{cve.match_status}</Badge>],
              [
                "Qualifying score",
                cve.qualifying_score
                  ? `${cve.qualifying_score.base_score.toFixed(1)} · CVSS ${cve.qualifying_score.version}`
                  : "Eligible",
              ],
              ["Target applicability", <Badge>{cve.applicability}</Badge>],
            ]}
          />
          {(!resource.data.config.version_scheme ||
            resource.data.config.version_scheme === "unknown") && (
            <Callout tone="warm" title="Choose a vulnerable revision">
              This application has no version scheme for resolving an affected
              release. Enter a vulnerable tag or commit below to avoid analyzing
              the monitored checkout.
            </Callout>
          )}
          {cve.applicability === "unknown" && (
            <p className="hint">
              The deployed version is unknown. This analysis investigates
              upstream source; it does not establish that the target is
              affected.
            </p>
          )}
        </div>
      }
      onClose={onClose}
      onSubmitted={onSubmitted}
    />
  );
}
