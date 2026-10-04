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
  programSchema,
  programsSchema,
  safeHref,
} from "../types";
import type { CVE, Program } from "../types";
import { JobLaunch, queueJob } from "../components/JobLaunch";
import {
  ActionButton,
  Badge,
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
  severityLabels,
  severityOf,
  Time,
  useShowMore,
} from "../components/ui";
import type { Severity } from "../components/ui";
import { AnalysisHistory } from "./Commits";
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
  prog: "all",
  sort: "score",
  cve: "",
  cvep: "",
  act: "",
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
      (skip === "prog" || f.prog === "all" || cve.program_id === f.prog),
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
  program,
  collection,
}: {
  program?: Program;
  collection?: Collection<CVE>;
}) {
  const own = useCollection(
    collection ? null : program ? `/cves?program_id=${program.id}` : "/cves",
    cvesSchema,
  );
  const cves = collection || own;
  const programs = useResource(program ? null : "/programs", programsSchema);
  const [filters, update] = useQueryState(defaults);
  const programName = (id: string) =>
    programs.data?.items.find((p) => p.id === id)?.asset_name;
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
      filters.prog,
      filters.sort,
    ].join("|"),
  );
  const facet = (key: keyof Filters, of: (row: Row) => string) =>
    countBy(applyFilters(rows, filters, key), of);
  const eligibility = facet("elig", (r) => (r.eligible ? "eligible" : "not"));
  const severity = facet("sev", (r) => r.severity);
  const applicability = facet("app", (r) => r.applicability);
  const byProgram = facet("prog", (r) => r.program_id);
  const selected = filters.cve
    ? rows.find(
        (row) =>
          row.id === filters.cve &&
          (program || !filters.cvep || row.program_id === filters.cvep),
      )
    : undefined;
  const open = (cve?: CVE, act?: "analyze") =>
    update({
      cve: cve?.id || null,
      cvep: program ? null : cve?.program_id,
      act: act || null,
    });
  const analyze = filters.act === "analyze" ? selected : undefined;
  const clear = () =>
    update({ q: "", elig: "all", sev: "all", app: "all", prog: "all" });
  return (
    <>
      <Panel
        title="CVE records"
        description={
          program
            ? `Minimum Base score ${program.config.cve_min_score ?? "not configured"} · CVSS ${program.config.cve_versions.join(", ") || "not configured"}`
            : "A qualifying score alone does not confirm the deployed asset is affected."
        }
        actions={
          program && (
            <ActionButton
              className="secondary"
              onAction={() =>
                queueJob(
                  `/programs/${program.id}/cve-sync`,
                  {},
                  undefined,
                  "CVE sync queued.",
                )
              }
            >
              <RefreshCw size={15} aria-hidden="true" />
              Sync CVEs
            </ActionButton>
          )
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
          {!program && (programs.data?.items.length || 0) > 1 && (
            <FilterSelect
              label="Program"
              value={filters.prog}
              onChange={(prog) => update({ prog })}
              options={[
                { value: "all", label: "All programs" },
                ...(programs.data?.items || []).map((p) => ({
                  value: p.id,
                  label: p.asset_name,
                  count: byProgram[p.id] || 0,
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
            <div className="table-scroll">
              <table>
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
                      key={`${cve.program_id}-${cve.id}`}
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
                          {!program && (
                            <>
                              {cve.published_at && " · "}
                              <Link to={`/programs/${cve.program_id}?tab=cves`}>
                                {programName(cve.program_id) || "Program"}
                              </Link>
                            </>
                          )}
                        </div>
                      </td>
                      <td>
                        <ScoreList cve={cve} />
                      </td>
                      <td>
                        <Badge>{cve.match_status}</Badge>
                      </td>
                      <td>
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
                      <td>
                        <Badge>{cve.applicability}</Badge>
                      </td>
                      <td className="cell-actions">
                        <button
                          className="secondary"
                          disabled={!cve.eligible}
                          onClick={() => open(cve, "analyze")}
                          aria-label={`Analyze ${cve.id}`}
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
                program
                  ? "Configure product selectors and score criteria, then sync CVEs."
                  : "CVE records appear after a configured program synchronizes its product selectors."
              }
            />
          )}
        </DataState>
      </Panel>
      {selected && !analyze && (
        <CVEDrawer
          cve={selected}
          list={visible.includes(selected) ? visible : rows}
          programName={programName(selected.program_id)}
          onNavigate={open}
          onClose={() => open(undefined)}
          onUpdated={cves.refresh}
          onAnalyze={() => open(selected, "analyze")}
        />
      )}
      {analyze && (
        <CVEAnalysisLaunch
          cve={analyze}
          onClose={() => open(undefined)}
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
  programName,
  onNavigate,
  onClose,
  onUpdated,
  onAnalyze,
}: {
  cve: Row;
  list: Row[];
  programName?: string;
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
  }, [cve.id]);
  const references = cve.references.flatMap((reference) => {
    const url = referenceUrl(reference);
    return url ? [url] : [];
  });
  async function setMatch(confirmed: boolean) {
    await mutate(
      `/programs/${cve.program_id}/cves/${cve.id}/match`,
      cveSchema,
      { confirmed },
    );
    onUpdated();
  }
  return (
    <Modal
      title={cve.id}
      description={cve.title}
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
              <ChevronLeft size={18} />
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
              <ChevronRight size={18} />
            </button>
          </span>
        )
      }
    >
      <div className="chip-row">
        <SeverityBadge severity={cve.severity} />
        {cve.best !== undefined && (
          <span className="muted">
            Highest v3/v4 score {cve.best.toFixed(1)}
          </span>
        )}
      </div>
      <p className="readable-copy drawer-lead">{cve.description}</p>
      <div className="drawer-actions">
        <button
          className="primary"
          disabled={!cve.eligible}
          onClick={onAnalyze}
        >
          <Sparkles size={15} aria-hidden="true" />
          Analyze
        </button>
        <Link
          className="secondary button"
          to={`/findings/new?program_id=${cve.program_id}&cve_id=${cve.id}`}
        >
          Create CVE finding
        </Link>
      </div>
      {!cve.eligible && cve.eligibility_reason && (
        <p className="hint warning">
          Analysis is unavailable: {cve.eligibility_reason}.
        </p>
      )}
      {cve.eligible && cve.analysis_blocked && (
        <p className="hint warning">
          Automatic analysis is waiting: {cve.analysis_blocked.message}.
        </p>
      )}
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
              "Program",
              <Link to={`/programs/${cve.program_id}`}>
                {programName || "Program details"}
              </Link>,
            ],
            [
              "Published",
              <Time value={cve.published_at} absolute fallback="Unknown" />,
            ],
            [
              "Modified",
              <Time value={cve.modified_at} absolute fallback="Unknown" />,
            ],
          ]}
        />
        {cve.applicability === "unknown" && (
          <p className="hint">
            Applicability stays unknown until the deployed version is observed.
            Use the program’s Version tab to generate a recipe or record a
            manual version.
          </p>
        )}
        <div className="inline-actions">
          <ActionButton className="secondary" onAction={() => setMatch(true)}>
            <Check size={14} aria-hidden="true" />
            Confirm product match
          </ActionButton>
          <ActionButton className="secondary" onAction={() => setMatch(false)}>
            <X size={14} aria-hidden="true" />
            Reject product match
          </ActionButton>
        </div>
      </section>
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
                {!counted(score) && <Badge tone="neutral">Not used</Badge>}
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
      {cve.references.length > 0 && (
        <section className="drawer-section">
          <h3>References ({references.length})</h3>
          <ul className="reference-list">
            {references.map((href) => (
              <li key={href}>
                <ExternalLink href={href}>{href}</ExternalLink>
              </li>
            ))}
          </ul>
          <Evidence value={cve.references} label="Raw source references" />
        </section>
      )}
      <section className="drawer-section">
        <h3>Analysis history</h3>
        <AnalysisHistory analyses={cve.analyses} programId={cve.program_id} />
      </section>
      <p className="hint drawer-shortcuts">
        <Kbd>J</Kbd> next · <Kbd>K</Kbd> previous · <Kbd>Esc</Kbd> close
      </p>
    </Modal>
  );
}
function CVEAnalysisLaunch({
  cve,
  onClose,
  onSubmitted,
}: {
  cve: CVE;
  onClose: () => void;
  onSubmitted: () => void;
}) {
  const resource = useResource(`/programs/${cve.program_id}`, programSchema);
  if (!resource.data)
    return (
      <Modal
        title="CVE analysis"
        description="Resolving this program’s execution profile."
        onClose={onClose}
      >
        <DataState
          loading={resource.loading}
          error={resource.error}
          retry={resource.refresh}
        >
          <p>Loading program configuration…</p>
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
      path={`/programs/${cve.program_id}/cves/${cve.id}/analyses`}
      initialProfile={resource.data.config.profiles.cve_analysis}
      context={`${cve.id} · Product: ${cve.match_status} · Score ${cve.qualifying_score?.base_score ?? "eligible"} · Target: ${cve.applicability}`}
      onClose={onClose}
      onSubmitted={onSubmitted}
    />
  );
}
