import { useCallback, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ChevronLeft,
  ChevronRight,
  CircleCheck,
  FileSearch,
  GitCommitHorizontal,
  Sparkles,
  Undo2,
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
  analysisBatchMax,
  analysisBatchSchema,
  commitSchema,
  commitsSchema,
  applicationSchema,
  applicationsSchema,
  findingVerdicts,
  repositoryLabel,
  reviewBatchSchema,
  verdicts,
} from "../types";
import type { Analysis, Commit, CommitFile, Application } from "../types";
import { AnalysisResult } from "../components/AnalysisResult";
import { JobLaunch } from "../components/JobLaunch";
import { confidenceText } from "../jobSummary";
import {
  ActionButton,
  announceChange,
  Badge,
  Callout,
  CopyButton,
  countBy,
  DataState,
  date,
  describeError,
  DetailGrid,
  DiffView,
  Empty,
  Evidence,
  ExternalLink,
  FilterSelect,
  humanize,
  matches,
  notify,
  PageHeading,
  Panel,
  ResultSummary,
  SearchField,
  Segmented,
  Tabs,
  Time,
  toneFor,
  useShowMore,
} from "../components/ui";
function verdictOf(analysis: Analysis) {
  return analysis.result?.verdict;
}
function triageField(commit: Commit, key: "decision" | "reason" | "title") {
  const result = commit.triage_result;
  if (typeof result !== "object" || !result || !(key in result)) return;
  const value: unknown = Reflect.get(result, key);
  return typeof value === "string" ? value : undefined;
}
/** A Triage that failed or was blocked decided nothing, so it is never read as unrelated. */
function triageKey(commit: Commit) {
  return ["failed", "blocked"].includes(commit.triage_status)
    ? commit.triage_status
    : triageField(commit, "decision") || commit.triage_status;
}
function TriageBadge({ commit }: { commit: Commit }) {
  const key = triageKey(commit);
  return key === "failed" || key === "blocked" ? (
    <Badge tone="danger">{`Triage ${key}`}</Badge>
  ) : (
    <Badge>{key}</Badge>
  );
}
const prefilterLabels: Record<string, string> = {
  dependency_manifest: "Dependency manifest",
  package_scripts: "Package scripts",
  ci_workflow: "CI workflow",
  minified_or_obfuscated: "Minified or obfuscated",
  auth_or_crypto: "Auth or crypto",
};
function prefilterLabel(rule: string) {
  return prefilterLabels[rule] || humanize(rule);
}
/** The Pre-filter's flags, shown beside the Triage result they never override. */
function PrefilterFlags({ commit }: { commit: Commit }) {
  if (!commit.prefilter.length) return null;
  return (
    <ul className="chip-row prefilter-flags" aria-label="Pre-filter flags">
      {commit.prefilter.map((flag) => (
        <li className="chip" key={flag.rule} title={flag.paths.join("\n")}>
          {prefilterLabel(flag.rule)}
        </li>
      ))}
    </ul>
  );
}
const analysisStates: Record<string, { label: string; tone: string }> = {
  queued: { label: "Queued", tone: "info" },
  waiting_for_cap: { label: "Waiting for cap", tone: "warm" },
  timed_out: { label: "Timed out after 30 minutes", tone: "danger" },
  blocked: { label: "Blocked", tone: "danger" },
  failed: { label: "Failed", tone: "danger" },
};
const capLabels: Record<string, string> = {
  application: "Application",
  account: "Provider account",
};
/** The newest Verdict with its confidence, and where a later Analysis stands. */
function AnalysisState({ commit }: { commit: Commit }) {
  const state = commit.analysis_state;
  const shown = state ? analysisStates[state.status] : undefined;
  const confidence = confidenceText(commit.analyses[0]?.result?.confidence);
  const detail =
    state?.status === "waiting_for_cap"
      ? `Daily ${capLabels[state.cap || ""] || "Analysis"} cap reached`
      : describeError(state?.error);
  return (
    <>
      {commit.verdict ? (
        <>
          <Badge>{commit.verdict}</Badge>
          {confidence && (
            <div className="table-subtitle">{humanize(confidence)}</div>
          )}
        </>
      ) : (
        !shown &&
        (commit.analyses.length ? (
          <Badge>Report available</Badge>
        ) : (
          <span className="muted">Not analysed</span>
        ))
      )}
      {shown && (
        <div className={commit.verdict ? "table-subtitle" : undefined}>
          <Badge tone={shown.tone}>{shown.label}</Badge>
          {detail && state?.status !== "timed_out" && (
            <div className="table-subtitle clamp">{detail}</div>
          )}
        </div>
      )}
    </>
  );
}
function commitTitle(commit: Commit) {
  return (
    commit.analyses[0]?.result?.title ||
    triageField(commit, "title") ||
    commit.message.split("\n")[0]
  );
}
function triageConfidence(commit: Commit) {
  const value =
    typeof commit.triage_result === "object" && commit.triage_result !== null
      ? Reflect.get(commit.triage_result, "confidence")
      : undefined;
  if (typeof value === "number" && Number.isFinite(value))
    return new Intl.NumberFormat(undefined, {
      style: "percent",
      maximumFractionDigits: 0,
    }).format(value);
  if (typeof value === "string") return value;
  if (
    typeof value === "object" &&
    value !== null &&
    "level" in value &&
    typeof value.level === "string"
  )
    return value.level;
}
export function AnalysisHistory({
  analyses,
  applicationId,
  commitId,
  onRerun,
}: {
  analyses: Analysis[];
  applicationId: string;
  commitId?: string;
  onRerun?: () => void;
}) {
  const [selection, update] = useQueryState({ run: "" });
  const analysis = analyses.find((a) => a.id === selection.run) || analyses[0];
  if (!analysis)
    return (
      <Empty
        icon={FileSearch}
        title="No Analysis yet"
        description="Analysis starts automatically when Triage flags this change, or choose Analyze. It reads a read-only checkout of the commit, builds nothing, and gives one Verdict."
      />
    );
  const verdict = verdictOf(analysis);
  return (
    <div className="commit-analysis-history">
      <div className="analysis-run-toolbar">
        <label>
          Analysis run
          <select
            name="analysis_run"
            value={analysis.id || "0"}
            onChange={(e) => update({ run: e.target.value })}
          >
            {analyses.map((a, i) => (
              <option key={a.id || i} value={a.id || String(i)}>
                {i === 0 ? "Latest · " : ""}
                {date(a.created_at)}
                {a.id ? ` · ${a.id.slice(0, 8)}` : ""}
              </option>
            ))}
          </select>
        </label>
        <span className="hint">
          {analyses.length} saved {analyses.length === 1 ? "run" : "runs"} ·
          Earlier output is preserved
        </span>
      </div>
      {selection.run && !analyses.some((a) => a.id === selection.run) && (
        <Callout tone="warm" title="Requested analysis is unavailable">
          Showing the latest saved report. Refresh the commit to check for newer
          output.
        </Callout>
      )}
      <AnalysisResult
        key={analysis.id || analysis.created_at}
        analysis={analysis}
        kind="commit"
      />
      {verdict === "Insufficient context" && (
        <Callout
          tone="warm"
          title="Sent to the Review queue"
          action={
            onRerun && (
              <button className="secondary" onClick={onRerun}>
                Analyze again
              </button>
            )
          }
        >
          Analysis could not decide from what it could see, so the change waits
          in the Review queue for your review decision. Review the open
          questions and source, or analyze it again.
        </Callout>
      )}
      {!analysis.result?.finding_id &&
        findingVerdicts.includes(verdict || "") && (
          <Link
            className="secondary button"
            to={`/findings/new?application_id=${encodeURIComponent(applicationId)}${commitId ? `&source_commit_id=${encodeURIComponent(commitId)}` : ""}${analysis.id ? `&source_analysis_id=${encodeURIComponent(analysis.id)}` : ""}`}
          >
            Create finding
          </Link>
        )}
    </div>
  );
}
// Candidates await review; confirmed revisions are real vulnerabilities, dismissed ones are not.
const decisionOrder = ["candidate", "confirmed", "pending", "dismissed"];
const decisionLabels: Record<string, string> = {
  candidate: "Marked for review",
  confirmed: "Confirmed",
  pending: "Pending",
  dismissed: "Dismissed",
};
/** Labels for the controls that set each decision. */
const decisionActions: Record<string, string> = {
  candidate: "Mark for review",
  confirmed: "Confirm finding",
  pending: "Leave pending",
  dismissed: "Dismiss",
};
const decisionResults: Record<string, string> = {
  candidate: "marked for review",
  confirmed: "confirmed",
  pending: "left pending",
  dismissed: "dismissed",
};
function DecisionBadge({ decision }: { decision: string }) {
  return (
    <Badge tone={toneFor(decision)}>
      {decisionLabels[decision] || decision}
    </Badge>
  );
}
/** A prefilled Create finding form for this revision and its latest analysis. */
function createFindingHref(commit: Commit) {
  const query = new URLSearchParams({
    application_id: commit.application_id ?? "",
    source_commit_id: commit.id,
    title: commitTitle(commit),
  });
  if (commit.analyses[0]?.id)
    query.set("source_analysis_id", commit.analyses[0].id);
  return `/findings/new?${query}`;
}
/** The revision's findings, or what its decision still needs. */
function FindingState({ commit }: { commit: Commit }) {
  return (
    <>
      {commit.review_decision === "candidate" && commit.findings.length > 0 && (
        <div className="table-subtitle">
          <Badge tone="accent">Finding ready</Badge>
        </div>
      )}
      {commit.findings.map((finding) => (
        <div className="table-subtitle" key={finding.id}>
          <Link to={`/findings/${finding.id}`}>
            Finding · {humanize(finding.status)}
          </Link>
        </div>
      ))}
      {commit.review_decision === "confirmed" && !commit.findings.length && (
        <div className="table-subtitle">
          <Link to={createFindingHref(commit)}>Create finding</Link>
        </div>
      )}
    </>
  );
}
function revisionCount(n: number) {
  return `${n} ${n === 1 ? "revision" : "revisions"}`;
}
/** Sets one review decision on many revisions in a single request. */
async function reviewBatch(ids: string[], decision: string) {
  const result = await mutate("/commits/review", reviewBatchSchema, {
    ids,
    decision,
  });
  return result.items;
}
type DecisionChange = { id: string; previous: string };
/** Restores each revision's decision from before a batch change. */
async function undoBatch(changes: DecisionChange[]) {
  const groups = new Map<string, string[]>();
  for (const { id, previous } of changes)
    groups.set(previous, [...(groups.get(previous) || []), id]);
  for (const [decision, ids] of groups) await reviewBatch(ids, decision);
}
const skipReasons: Record<string, string> = {
  analysis_active: "already being analyzed",
  historical_source: "from an earlier source generation",
};
/** Queues one detailed analysis per revision and describes the outcome. */
async function analyzeBatch(
  ids: string[],
  body: Record<string, unknown>,
  key: string,
): Promise<Receipt> {
  const { items } = await mutate(
    "/commits/analyses",
    analysisBatchSchema,
    { ...body, ids },
    "POST",
    key,
  );
  const queued = items.filter((i) => i.job_id);
  const skipped = countBy(
    items.filter((i) => !i.job_id),
    (i) => i.skipped || "skipped",
  );
  const message = [
    queued.length
      ? `Queued ${queued.length} ${queued.length === 1 ? "analysis" : "analyses"}`
      : "No analyses queued",
    ...Object.entries(skipped).map(
      ([reason, n]) => `${n} ${skipReasons[reason] || "skipped"}`,
    ),
  ].join(" · ");
  return {
    message: `${message}.`,
    undo: [],
    link: !queued.length
      ? undefined
      : queued.length === 1
        ? { to: `/jobs/${queued[0].job_id}`, label: "View job" }
        : { to: "/jobs?kind=commit_analysis", label: "View jobs" },
  };
}
function committedAt(commit: Commit) {
  return commit.committed_at ? Date.parse(commit.committed_at) || 0 : 0;
}
/** Newest first; undated revisions sort last. */
export function sortCommits(items: Commit[], oldest = false) {
  return [...items].sort((a, b) =>
    oldest ? committedAt(a) - committedAt(b) : committedAt(b) - committedAt(a),
  );
}
function dayLabel(commit: Commit) {
  if (!commit.committed_at) return "Undated";
  return new Date(commit.committed_at).toLocaleDateString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}
type CommitFilters = {
  q: string;
  decision: string;
  triage: string;
  show: string;
  sort: string;
  verdict: string;
};
function applyCommitFilters(
  items: Commit[],
  f: CommitFilters,
  skip?: keyof CommitFilters,
) {
  return items.filter(
    (c) =>
      matches(
        f.q,
        c.message,
        c.author,
        c.revision,
        commitTitle(c),
        triageField(c, "reason"),
        ...c.files.flatMap((file) => [file.path, file.previous_path]),
      ) &&
      (skip === "decision" ||
        f.decision === "all" ||
        c.review_decision === f.decision) &&
      (skip === "triage" || f.triage === "all" || triageKey(c) === f.triage) &&
      (skip === "verdict" ||
        f.verdict === "all" ||
        (c.verdict || "none") === f.verdict) &&
      (skip === "show" ||
        f.show === "all" ||
        (f.show === "review" &&
          c.verdict === "Insufficient context" &&
          c.review_decision === "pending") ||
        (f.show === "analyzed" && c.analyses.length > 0) ||
        (f.show === "unanalyzed" && c.analyses.length === 0) ||
        (f.show === "incomplete" && !c.diff_complete) ||
        (f.show === "finding" && c.findings.length > 0)),
  );
}
type Receipt = {
  message: string;
  undo: DecisionChange[];
  link?: { to: string; label: string };
};
/**
 * The bar above the queue: result counts, or the batch decision controls while
 * revisions are selected, or the outcome of the last batch change with Undo.
 */
function QueueBar({
  selected,
  matching,
  onSelectMatching,
  onClearSelection,
  onApply,
  onAnalyze,
  receipt,
  onUndo,
  onCloseReceipt,
  summary,
}: {
  selected: Commit[];
  matching?: number;
  onSelectMatching: () => void;
  onClearSelection: () => void;
  onApply: (decision: string) => Promise<void>;
  onAnalyze: () => void;
  receipt?: Receipt;
  onUndo: (changes: DecisionChange[]) => Promise<void>;
  onCloseReceipt: () => void;
  summary: ReactNode;
}) {
  if (selected.length)
    return (
      <div className="queue-bar batch">
        <span className="queue-bar-count" role="status">
          <strong>{selected.length}</strong> selected
        </span>
        {matching !== undefined && (
          <button
            type="button"
            className="text-button"
            onClick={onSelectMatching}
          >
            Select all {revisionCount(matching)} matching
          </button>
        )}
        <div
          className="queue-bar-actions"
          role="group"
          aria-label="Set review decision for selected revisions"
        >
          {decisionOrder.map((decision) => (
            <ActionButton
              key={decision}
              className="secondary"
              disabled={selected.every((c) => c.review_decision === decision)}
              title={
                selected.every((c) => c.review_decision === decision)
                  ? `Every selected revision is already ${decisionResults[decision]}`
                  : undefined
              }
              onAction={() => onApply(decision)}
            >
              {decisionActions[decision]}
            </ActionButton>
          ))}
        </div>
        <button
          type="button"
          className="primary"
          disabled={selected.length > analysisBatchMax}
          title={
            selected.length > analysisBatchMax
              ? `Analyze at most ${analysisBatchMax} revisions at a time`
              : "Queue a detailed analysis for each selected revision"
          }
          onClick={onAnalyze}
        >
          <Sparkles size={15} aria-hidden="true" />
          Analyze
        </button>
        <button
          type="button"
          className="text-button queue-bar-clear"
          onClick={onClearSelection}
        >
          Clear selection
        </button>
      </div>
    );
  if (receipt)
    return (
      <div className="queue-bar receipt">
        <CircleCheck size={16} aria-hidden="true" />
        <span role="status">{receipt.message}</span>
        {receipt.undo.length > 0 && (
          <ActionButton
            className="secondary"
            onAction={() => onUndo(receipt.undo)}
          >
            <Undo2 size={15} aria-hidden="true" />
            Undo
          </ActionButton>
        )}
        {receipt.link && (
          <Link className="secondary button" to={receipt.link.to}>
            {receipt.link.label}
          </Link>
        )}
        <button
          type="button"
          className="icon-button queue-bar-clear"
          aria-label="Dismiss message"
          onClick={onCloseReceipt}
        >
          <X size={16} />
        </button>
      </div>
    );
  return (
    <div className="queue-bar">
      {summary}
      <span className="hint queue-bar-hint">
        Select revisions to set their decision or analyze them together.
        Shift-click selects a range.
      </span>
    </div>
  );
}
const noSelection = new Set<string>();
export function CommitList({
  application,
  collection,
  scopeId,
  scopeApplication,
}: {
  application?: Application;
  collection?: Collection<Commit>;
  scopeId?: string;
  /** The application a scoped queue belongs to, for its execution profile. */
  scopeApplication?: Application;
}) {
  const own = useCollection(
    collection
      ? null
      : application
        ? `/applications/${application.id}/commits`
        : scopeId
          ? `/commits?application_id=${encodeURIComponent(scopeId)}`
          : "/commits",
    commitsSchema,
  );
  const commits = collection || own;
  const [filters, update] = useQueryState({
    q: "",
    decision: application ? "all" : "candidate",
    triage: "all",
    show: "all",
    sort: "newest",
    verdict: "all",
  });
  const items = useMemo(() => commits.data?.items || [], [commits.data]);
  const visible = useMemo(
    () =>
      sortCommits(
        applyCommitFilters(items, filters),
        filters.sort === "oldest",
      ),
    [items, filters],
  );
  const filterKey = [
    filters.q,
    filters.decision,
    filters.triage,
    filters.show,
    filters.sort,
    filters.verdict,
  ].join("|");
  const { shown, footer } = useShowMore(visible, filterKey);
  // A selection belongs to one filtered view, so a batch change never reaches
  // a revision the operator cannot see.
  const [selection, setSelection] = useState({
    key: filterKey,
    ids: noSelection,
  });
  const selectedIds = selection.key === filterKey ? selection.ids : noSelection;
  const selected = visible.filter((c) => selectedIds.has(c.id));
  const shownSelected = shown.filter((c) => selectedIds.has(c.id)).length;
  const allShownSelected = shown.length > 0 && shownSelected === shown.length;
  const anchor = useRef<string>(undefined);
  const [receipt, setReceipt] = useState<Receipt>();
  // The revisions a batch analysis was opened for, fixed while its dialog is open.
  const [analyzing, setAnalyzing] = useState<Commit[]>();
  const owner = application || scopeApplication;
  const select = (ids: Set<string>) => {
    setSelection({ key: filterKey, ids });
    setReceipt(undefined);
  };
  const toggle = (id: string, checked: boolean, range: boolean) => {
    const from = range ? visible.findIndex((c) => c.id === anchor.current) : -1;
    const to = visible.findIndex((c) => c.id === id);
    const targets =
      from >= 0
        ? visible
            .slice(Math.min(from, to), Math.max(from, to) + 1)
            .map((c) => c.id)
        : [id];
    const next = new Set(selectedIds);
    for (const target of targets)
      if (checked) next.add(target);
      else next.delete(target);
    anchor.current = id;
    select(next);
  };
  const apply = async (decision: string) => {
    const result = await reviewBatch(
      selected.map((c) => c.id),
      decision,
    );
    const changed = result.filter((r) => r.previous !== r.review_decision);
    const unchanged = result.length - changed.length;
    setSelection({ key: filterKey, ids: noSelection });
    setReceipt({
      message: `${revisionCount(changed.length)} ${decisionResults[decision]}${unchanged ? ` · ${unchanged} already were` : ""}.`,
      undo: changed,
    });
    announceChange();
    commits.refresh();
  };
  const analyze = async (body: Record<string, unknown>, key: string) => {
    const outcome = await analyzeBatch(
      (analyzing || []).map((c) => c.id),
      body,
      key,
    );
    setSelection({ key: filterKey, ids: noSelection });
    setReceipt(outcome);
    announceChange();
    commits.refresh();
  };
  const undo = async (changes: DecisionChange[]) => {
    await undoBatch(changes);
    setReceipt({
      message: `Restored ${revisionCount(changes.length)} to the previous decision.`,
      undo: [],
    });
    announceChange();
    commits.refresh();
  };
  const decisionCounts = countBy(
    applyCommitFilters(items, filters, "decision"),
    (c) => c.review_decision,
  );
  const triageCounts = countBy(
    applyCommitFilters(items, filters, "triage"),
    triageKey,
  );
  const verdictCounts = countBy(
    applyCommitFilters(items, filters, "verdict"),
    (c) => c.verdict || "none",
  );
  const clear = () =>
    update({
      q: "",
      decision: "all",
      triage: "all",
      show: "all",
      verdict: "all",
    });
  let lastDay = "";
  return (
    <Panel
      title={application ? "Source history" : "Commit review"}
      description="A Triage flag starts Analysis automatically. Analysis reads a read-only checkout, builds nothing, and gives one Verdict."
      className="commit-queue-panel"
    >
      <div className="queue-filters">
        <div className="queue-filters-row">
          <Segmented
            label="Review decision"
            value={filters.decision}
            onChange={(decision) => update({ decision })}
            options={[
              ...decisionOrder.map((value) => ({
                value,
                label: decisionLabels[value],
                count: decisionCounts[value] || 0,
              })),
              {
                value: "all",
                label: "All",
                count: Object.values(decisionCounts).reduce((a, b) => a + b, 0),
              },
            ]}
          />
          <SearchField
            label="Search revisions"
            placeholder="Search message, author, revision, or path"
            value={filters.q}
            onChange={(q) => update({ q })}
          />
        </div>
        <div className="queue-filters-row secondary-filters">
          <FilterSelect
            label="Verdict"
            value={filters.verdict}
            onChange={(verdict) => update({ verdict })}
            options={[
              { value: "all", label: "Any" },
              ...verdicts.map((value) => ({
                value,
                label: value,
                count: verdictCounts[value] || 0,
              })),
              {
                value: "none",
                label: "Not analysed",
                count: verdictCounts.none || 0,
              },
            ]}
          />
          <FilterSelect
            label="Triage"
            value={filters.triage}
            onChange={(triage) => update({ triage })}
            options={[
              { value: "all", label: "Any" },
              ...Object.keys(triageCounts)
                .sort()
                .map((value) => ({
                  value,
                  label: humanize(value),
                  count: triageCounts[value],
                })),
            ]}
          />
          <FilterSelect
            label="Show"
            value={filters.show}
            // The Review queue holds only changes still pending a decision.
            onChange={(show) =>
              update(
                show === "review" ? { show, decision: "pending" } : { show },
              )
            }
            options={[
              { value: "all", label: "All revisions" },
              { value: "review", label: "Review queue" },
              { value: "analyzed", label: "With analysis" },
              { value: "unanalyzed", label: "Not analysed" },
              { value: "incomplete", label: "Incomplete diff" },
              { value: "finding", label: "With finding" },
            ]}
          />
          <FilterSelect
            label="Sort"
            value={filters.sort}
            onChange={(sort) => update({ sort })}
            options={[
              { value: "newest", label: "Newest first" },
              { value: "oldest", label: "Oldest first" },
            ]}
          />
        </div>
      </div>
      <DataState
        loading={commits.loading}
        error={commits.error}
        retry={commits.refresh}
        hasData={!!commits.data}
      >
        {items.length > 0 && (
          <QueueBar
            selected={selected}
            matching={
              allShownSelected && visible.length > selected.length
                ? visible.length
                : undefined
            }
            onSelectMatching={() => select(new Set(visible.map((c) => c.id)))}
            onClearSelection={() => select(noSelection)}
            onApply={apply}
            onAnalyze={() => setAnalyzing(selected)}
            receipt={receipt}
            onUndo={undo}
            onCloseReceipt={() => setReceipt(undefined)}
            summary={
              <ResultSummary
                shown={visible.length}
                total={items.length}
                noun={["revision", "revisions"]}
                truncated={commits.data?.truncated}
                onClear={clear}
              />
            }
          />
        )}
        {visible.length ? (
          <div className="table-scroll">
            <table className="commit-queue">
              <thead>
                <tr>
                  <th scope="col" className="select-cell">
                    <label className="select-hit">
                      <input
                        type="checkbox"
                        aria-label="Select all shown revisions"
                        checked={allShownSelected}
                        ref={(el) => {
                          if (el)
                            el.indeterminate =
                              shownSelected > 0 && !allShownSelected;
                        }}
                        onChange={() => {
                          const next = new Set(selectedIds);
                          for (const c of shown)
                            if (allShownSelected) next.delete(c.id);
                            else next.add(c.id);
                          select(next);
                        }}
                      />
                    </label>
                  </th>
                  <th scope="col">Security issue / revision</th>
                  <th scope="col">Author</th>
                  <th scope="col">Triage</th>
                  <th scope="col">Analysis</th>
                  <th scope="col">Decision</th>
                </tr>
              </thead>
              <tbody>
                {shown.flatMap((commit) => {
                  const day = dayLabel(commit);
                  const title = commitTitle(commit);
                  const subject = commit.message.split("\n")[0];
                  const isSelected = selectedIds.has(commit.id);
                  const rows = [];
                  if (day !== lastDay) {
                    lastDay = day;
                    rows.push(
                      <tr className="group-row" key={`day-${day}`}>
                        <th scope="colgroup" colSpan={6}>
                          {day}
                        </th>
                      </tr>,
                    );
                  }
                  rows.push(
                    <tr
                      key={commit.id}
                      className={isSelected ? "is-selected" : undefined}
                    >
                      <td className="select-cell">
                        <label className="select-hit">
                          <input
                            type="checkbox"
                            aria-label={`Select ${title}`}
                            checked={isSelected}
                            onChange={(e) =>
                              toggle(
                                commit.id,
                                e.target.checked,
                                e.nativeEvent instanceof MouseEvent &&
                                  e.nativeEvent.shiftKey,
                              )
                            }
                          />
                        </label>
                      </td>
                      <td>
                        <Link
                          className="table-title clamp"
                          to={`/commits/${commit.id}`}
                        >
                          {title}
                        </Link>
                        {title !== subject && (
                          <div className="table-subtitle clamp">{subject}</div>
                        )}
                        <div className="table-subtitle mono">
                          {commit.revision.slice(0, 10)} · {commit.files.length}{" "}
                          {commit.files.length === 1 ? "path" : "paths"}
                        </div>
                      </td>
                      <td>
                        {commit.author || "Unknown"}
                        <div className="table-subtitle">
                          <Time
                            value={commit.committed_at}
                            fallback="Unknown"
                          />
                        </div>
                      </td>
                      <td>
                        <TriageBadge commit={commit} />
                        {["failed", "blocked"].includes(triageKey(commit)) && (
                          <div className="table-subtitle clamp">
                            {triageField(commit, "reason")}
                          </div>
                        )}
                        <PrefilterFlags commit={commit} />
                        {!commit.diff_complete && (
                          <div className="table-subtitle warning">
                            Incomplete diff
                          </div>
                        )}
                      </td>
                      <td>
                        <AnalysisState commit={commit} />
                      </td>
                      <td>
                        <DecisionBadge decision={commit.review_decision} />
                        <FindingState commit={commit} />
                      </td>
                    </tr>,
                  );
                  return rows;
                })}
              </tbody>
            </table>
            {footer}
          </div>
        ) : items.length ? (
          <Empty
            icon={GitCommitHorizontal}
            title={
              filters.q
                ? "No revisions match these filters"
                : filters.decision === "candidate"
                  ? "Nothing marked for review"
                  : filters.decision === "confirmed"
                    ? "No confirmed findings"
                    : "No revisions match these filters"
            }
            description={
              filters.decision === "candidate"
                ? "Security candidates from triage, and changes you mark, appear here."
                : filters.decision === "confirmed"
                  ? "Revisions you confirm as real vulnerabilities appear here with their findings."
                  : "Try a different search or a broader filter."
            }
            action={
              <div className="inline-actions">
                {filters.decision !== "pending" &&
                  (decisionCounts.pending || 0) > 0 && (
                    <button
                      className="secondary"
                      onClick={() => update({ decision: "pending" })}
                    >
                      Show {decisionCounts.pending} pending
                    </button>
                  )}
                <button className="secondary" onClick={clear}>
                  Show all revisions
                </button>
              </div>
            }
          />
        ) : (
          <Empty
            icon={GitCommitHorizontal}
            title="No revisions yet"
            description={
              application
                ? "Run a source check to import the available history."
                : "Revisions appear here after source checks import them."
            }
          />
        )}
      </DataState>
      {analyzing && (
        <JobLaunch
          path="/commits/analyses"
          operation="commit_analysis"
          initialProfile={owner?.config.profiles.commit_analysis}
          context={
            <BatchAnalysisContext commits={analyzing} application={owner} />
          }
          submit={analyze}
          submitLabel={`Start ${analyzing.length} ${analyzing.length === 1 ? "analysis" : "analyses"}`}
          onClose={() => setAnalyzing(undefined)}
        />
      )}
    </Panel>
  );
}
/** What a batch analysis covers: the first few revisions and how the batch runs. */
function BatchAnalysisContext({
  commits,
  application,
}: {
  commits: Commit[];
  application?: Application;
}) {
  const listed = commits.slice(0, 5);
  return (
    <div className="commit-launch-context">
      <p>
        <strong>{revisionCount(commits.length)}</strong>
        {application && ` · ${application.product_name}`}
      </p>
      <ul className="batch-launch-list">
        {listed.map((c) => (
          <li key={c.id}>
            <span className="mono">{c.revision.slice(0, 10)}</span>{" "}
            {commitTitle(c)}
          </li>
        ))}
      </ul>
      {commits.length > listed.length && (
        <p className="hint">and {commits.length - listed.length} more</p>
      )}
      <p className="hint">
        Each revision runs as its own analysis job with the profile below.
        Revisions already being analyzed, or from an earlier source generation,
        are skipped.
      </p>
    </div>
  );
}
export function Reviews() {
  const applications = useCollection("/applications", applicationsSchema);
  const [scope, update] = useQueryState({ application: "", q: "" });
  const list = applications.data?.items || [];
  const selected = list.find((p) => p.id === scope.application);
  return (
    <>
      <PageHeading
        eyebrow="Upstream intelligence"
        title="Commit review"
        description={
          selected ? (
            <Link to={`/applications/${selected.id}?tab=commits`}>
              {selected.asset_name} · {selected.product_name}
            </Link>
          ) : (
            "Review one application at a time, distinguish security changes, and investigate supported findings."
          )
        }
        actions={
          scope.application &&
          applications.data && (
            <FilterSelect
              label="Application"
              value={scope.application}
              onChange={(application) => update({ application, q: null })}
              options={[
                ...(selected
                  ? []
                  : [
                      {
                        value: scope.application,
                        label: "Unavailable application",
                      },
                    ]),
                ...list.map((p) => ({ value: p.id, label: p.asset_name })),
              ]}
            />
          )
        }
      />
      {!scope.application ? (
        <Panel
          title="Choose an application"
          description="Each application's commits are reviewed on their own, so different sources never mix."
        >
          <div className="explorer-toolbar">
            <SearchField
              label="Search review applications"
              placeholder="Search asset or product…"
              value={scope.q}
              onChange={(q) => update({ q })}
            />
          </div>
          <DataState
            loading={applications.loading}
            error={applications.error}
            retry={applications.refresh}
            hasData={!!applications.data}
          >
            <div className="review-application-grid">
              {list
                .filter((p) => matches(scope.q, p.asset_name, p.product_name))
                .map((p) => (
                  <Link
                    key={p.id}
                    className="review-application-card"
                    aria-label={`Review commits for ${p.asset_name}`}
                    to={`/reviews?application=${encodeURIComponent(p.id)}`}
                  >
                    <GitCommitHorizontal size={20} aria-hidden="true" />
                    <div>
                      <strong>{p.asset_name}</strong>
                      <span>{p.product_name}</span>
                      <small>Review security candidates</small>
                    </div>
                    <ChevronRight size={18} aria-hidden="true" />
                  </Link>
                ))}
              {!list.length && (
                <Empty
                  title="No applications yet"
                  description="Register an application to monitor and review its source revisions."
                />
              )}
            </div>
          </DataState>
        </Panel>
      ) : (
        <>
          {applications.data && !selected && (
            <Callout
              tone="warm"
              title="This application is unavailable"
              action={
                <Link className="secondary button" to="/reviews">
                  Choose an application
                </Link>
              }
            >
              It may have been removed. Revisions below are limited to this
              application identifier.
            </Callout>
          )}
          <CommitList
            key={scope.application}
            scopeId={scope.application}
            scopeApplication={selected}
          />
        </>
      )}
    </>
  );
}
export function CommitDetail() {
  const { id } = useParams();
  const resource = useResource(
    `/commits/${encodeURIComponent(id || "")}`,
    commitSchema,
  );
  return (
    <DataState
      loading={resource.loading}
      error={resource.error}
      retry={resource.refresh}
      hasData={!!resource.data}
    >
      {resource.data && (
        <CommitDetailBody
          key={resource.data.id}
          commit={resource.data}
          refresh={resource.refresh}
        />
      )}
    </DataState>
  );
}
type DiffFile = {
  path: string;
  text: string;
  adds: number;
  dels: number;
  large: boolean;
};
const LARGE_FILE_CHARS = 20000;
function cleanPath(path: string) {
  return path.replace(/^[ab]\//, "").replace(/\t.*$/, "");
}
/**
 * Split a unified diff into per-file sections. Sections start at a
 * `diff --git` header, or at a `---` line followed by `+++` (GitHub patches).
 */
export function splitDiff(diff: string): DiffFile[] {
  const lines = diff.replace(/\n$/, "").split("\n");
  const groups: { path: string; lines: string[] }[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const git = line.match(/^diff --git a\/(.+?) b\/(.+)$/);
    const pair =
      line.startsWith("--- ") && lines[i + 1]?.startsWith("+++ ")
        ? [line.slice(4), lines[i + 1].slice(4)]
        : undefined;
    const previous = groups[groups.length - 1];
    // A `---/+++` pair directly after a `diff --git` header belongs to it.
    const continues =
      pair &&
      previous &&
      previous.lines.length <= 4 &&
      previous.lines[0]?.startsWith("diff --git");
    if (git || (pair && !continues) || !groups.length) {
      const path = git
        ? git[2]
        : pair
          ? cleanPath(pair[1] === "/dev/null" ? pair[0] : pair[1])
          : "Changes";
      groups.push({ path, lines: [] });
    }
    groups[groups.length - 1].lines.push(line);
  }
  return groups.map(({ path, lines }) => {
    const text = lines.join("\n");
    return {
      path,
      text,
      adds: lines.filter((l) => l.startsWith("+") && !l.startsWith("+++"))
        .length,
      dels: lines.filter((l) => l.startsWith("-") && !l.startsWith("---"))
        .length,
      large: text.length > LARGE_FILE_CHARS,
    };
  });
}
function DiffStat({ file }: { file: DiffFile }) {
  return (
    <span className="diff-stat">
      <span className="diff-stat-add">+{file.adds}</span>
      <span className="diff-stat-del">−{file.dels}</span>
    </span>
  );
}
type NavEntry = { path: string; status?: string | null; section: number };
/** Every changed path, linked to its patch section when one exists. */
function navEntries(files: DiffFile[], changed: CommitFile[]): NavEntry[] {
  const used = new Set<number>();
  const entries = changed.map((file) => {
    const section = files.findIndex(
      (s, i) =>
        !used.has(i) && (s.path === file.path || s.path === file.previous_path),
    );
    if (section >= 0) used.add(section);
    return { path: file.path, status: file.status, section };
  });
  files.forEach((file, i) => {
    if (!used.has(i))
      entries.push({ path: file.path, section: i, status: null });
  });
  return entries;
}
function DiffFiles({
  diff,
  files: changed,
}: {
  diff: string;
  files: CommitFile[];
}) {
  const files = useMemo(() => splitDiff(diff), [diff]);
  const entries = useMemo(() => navEntries(files, changed), [files, changed]);
  const missing = entries.filter((e) => e.section < 0).length;
  const sectioned = entries.length > 1;
  const [wrap, setWrap] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<number, boolean>>(() =>
    Object.fromEntries(
      files.map((file, i) => [i, file.large && files.length > 1]),
    ),
  );
  const sections = useRef<(HTMLDetailsElement | null)[]>([]);
  const statusOf = (i: number) => entries.find((e) => e.section === i)?.status;
  return (
    <>
      <div className="diff-toolbar">
        {sectioned && (
          <nav className="diff-file-nav" aria-label="Changed files">
            {entries.map((entry) => {
              const file = files[entry.section];
              return (
                <button
                  key={entry.path}
                  type="button"
                  disabled={!file}
                  title={
                    file ? undefined : "No patch was provided for this path"
                  }
                  onClick={() => {
                    setCollapsed((c) => ({ ...c, [entry.section]: false }));
                    requestAnimationFrame(() =>
                      sections.current[entry.section]?.scrollIntoView({
                        block: "start",
                      }),
                    );
                  }}
                >
                  <span className="mono">{entry.path}</span>
                  {file ? (
                    <DiffStat file={file} />
                  ) : (
                    <span className="muted">no patch</span>
                  )}
                </button>
              );
            })}
          </nav>
        )}
        <div className="inline-actions diff-options">
          <label className="check-label">
            <input
              type="checkbox"
              checked={wrap}
              onChange={(e) => setWrap(e.target.checked)}
            />
            Wrap long lines
          </label>
          {files.length > 1 && (
            <>
              <button
                type="button"
                className="secondary"
                onClick={() =>
                  setCollapsed(
                    Object.fromEntries(files.map((_, i) => [i, false])),
                  )
                }
              >
                Expand all
              </button>
              <button
                type="button"
                className="secondary"
                onClick={() =>
                  setCollapsed(
                    Object.fromEntries(files.map((_, i) => [i, true])),
                  )
                }
              >
                Collapse all
              </button>
            </>
          )}
        </div>
      </div>
      {missing > 0 && (
        <p className="hint diff-missing">
          {missing} of {entries.length} changed paths have no patch from the
          upstream source, so this input is incomplete.
        </p>
      )}
      {!sectioned ? (
        <DiffView diff={diff} wrap={wrap} />
      ) : (
        files.map((file, i) => (
          <details
            key={i}
            className="diff-file"
            ref={(el) => {
              sections.current[i] = el;
            }}
            open={!collapsed[i]}
            onToggle={(e) => {
              const open = e.currentTarget.open;
              setCollapsed((c) => (c[i] === !open ? c : { ...c, [i]: !open }));
            }}
          >
            <summary>
              <span className="mono">{file.path}</span>
              {statusOf(i) && statusOf(i) !== "modified" && (
                <Badge tone="neutral">{statusOf(i) || ""}</Badge>
              )}
              {file.large && (
                <span className="muted">
                  {Math.round(file.text.length / 1024)} KB — likely generated or
                  minified
                </span>
              )}
              <DiffStat file={file} />
            </summary>
            {!collapsed[i] && <DiffView diff={file.text} wrap={wrap} />}
          </details>
        ))
      )}
    </>
  );
}
const historyKeys = ["j", "k"];
/** Newer/older navigation through an application's revisions. */
function HistoryPager({ commit }: { commit: Commit }) {
  const navigate = useNavigate();
  const history = useCollection(
    `/applications/${commit.application_id}/commits`,
    commitsSchema,
  );
  const list = useMemo(
    () => sortCommits(history.data?.items || []),
    [history.data],
  );
  const index = list.findIndex((c) => c.id === commit.id);
  const newer = index > 0 ? list[index - 1] : undefined;
  const older = index >= 0 ? list[index + 1] : undefined;
  const step = useCallback(
    (key: string) => {
      const target = key === "j" ? older : newer;
      if (target) navigate(`/commits/${target.id}`);
    },
    [older, newer, navigate],
  );
  useShortcut(historyKeys, step, index >= 0);
  if (index < 0) return null;
  return (
    <nav className="history-pager" aria-label="Revision history">
      <button
        type="button"
        className="secondary"
        disabled={!newer}
        title="Newer revision (K)"
        onClick={() => newer && navigate(`/commits/${newer.id}`)}
      >
        <ChevronLeft size={15} aria-hidden="true" />
        Newer
      </button>
      <span className="pager-position">
        {index + 1} of {list.length}
      </span>
      <button
        type="button"
        className="secondary"
        disabled={!older}
        title="Older revision (J)"
        onClick={() => older && navigate(`/commits/${older.id}`)}
      >
        Older
        <ChevronRight size={15} aria-hidden="true" />
      </button>
    </nav>
  );
}
function CommitDetailBody({
  commit,
  refresh,
}: {
  commit: Commit;
  refresh: () => void;
}) {
  const [analyze, setAnalyze] = useState(false);
  const [view, updateView] = useQueryState({ view: "" });
  const activeView = ["source", "triage", "analysis"].includes(view.view)
    ? view.view
    : commit.analyses.length
      ? "analysis"
      : "source";
  const application = useResource(
    `/applications/${commit.application_id}`,
    applicationSchema,
  );
  const source = application.data;
  const repository = source?.repositories.find(
    (r) => r.repository_id === commit.repository_id,
  );
  const reason = triageField(commit, "reason");
  const confidence = triageConfidence(commit);
  return (
    <>
      <HistoryPager commit={commit} />
      <PageHeading
        back={{
          to: `/reviews?application=${encodeURIComponent(commit.application_id ?? "")}`,
          label: "Commit review",
        }}
        eyebrow={`Revision ${commit.revision.slice(0, 12)}`}
        title={commitTitle(commit)}
        description={
          source && (
            <Link to={`/applications/${source.id}?tab=commits`}>
              {source.asset_name} · {source.product_name}
            </Link>
          )
        }
        actions={
          <>
            {commit.url && (
              <ExternalLink className="secondary button" href={commit.url}>
                View upstream
              </ExternalLink>
            )}
            <button className="primary" onClick={() => setAnalyze(true)}>
              <Sparkles size={16} aria-hidden="true" />
              Analyze
            </button>
          </>
        }
      />
      {commitTitle(commit) !== commit.message.split("\n")[0] && (
        <p className="hint commit-upstream-subject">
          Upstream commit: {commit.message.split("\n")[0]}
        </p>
      )}
      <Panel padded>
        <DetailGrid
          items={[
            [
              "Repository",
              repository ? (
                <ExternalLink href={repository.source_url}>
                  {repositoryLabel(repository)}
                </ExternalLink>
              ) : (
                "Loading…"
              ),
            ],
            [
              "Revision",
              <span className="with-copy">
                <span className="mono">{commit.revision.slice(0, 16)}</span>
                <CopyButton value={commit.revision} label="Copy revision" />
              </span>,
            ],
            ["Author", commit.author || "Unknown"],
            [
              "Committed",
              <Time value={commit.committed_at} absolute fallback="Unknown" />,
            ],
            [
              "Triage",
              <>
                <TriageBadge commit={commit} />
                <PrefilterFlags commit={commit} />
              </>,
            ],
            ["Verdict", <AnalysisState commit={commit} />],
            [
              "Finding",
              commit.findings.length ? (
                <span className="finding-links">
                  {commit.findings.map((finding) => (
                    <Link
                      key={finding.id}
                      to={`/findings/${finding.id}`}
                      title={finding.title}
                    >
                      {humanize(finding.status)} finding
                    </Link>
                  ))}
                </span>
              ) : (
                <span className="muted">None recorded</span>
              ),
            ],
          ]}
        />
        {commit.review_decision === "candidate" &&
          commit.findings.length > 0 && (
            <Callout
              tone="good"
              title="Analysis produced a finding"
              action={
                <ActionButton
                  className="primary"
                  onAction={async () => {
                    await mutate(`/commits/${commit.id}/review`, commitSchema, {
                      decision: "confirmed",
                    });
                    notify("Revision confirmed.");
                    refresh();
                  }}
                >
                  Confirm finding
                </ActionButton>
              }
            >
              Review the report and artifacts, then confirm the finding or
              dismiss the revision.
            </Callout>
          )}
        {commit.review_decision === "confirmed" && !commit.findings.length && (
          <Callout
            tone="warm"
            title="Confirmed without a finding"
            action={
              <Link className="secondary button" to={createFindingHref(commit)}>
                Create finding
              </Link>
            }
          >
            Record the finding to track its status, versions, and reproducible
            artifacts.
          </Callout>
        )}
        <div className="decision-bar">
          <span className="field-label" id="decision-label">
            Review decision
          </span>
          <div
            className="segmented"
            role="group"
            aria-labelledby="decision-label"
          >
            {decisionOrder.map((decision) => {
              const current = commit.review_decision === decision;
              return (
                <ActionButton
                  key={decision}
                  className={current ? "selected" : ""}
                  disabled={current}
                  confirm={
                    decision === "dismissed" &&
                    commit.findings.some((f) => f.status === "open")
                      ? "Dismiss? The finding stays open"
                      : undefined
                  }
                  onAction={async () => {
                    await mutate(`/commits/${commit.id}/review`, commitSchema, {
                      decision,
                    });
                    notify(`Revision ${decisionResults[decision]}.`);
                    refresh();
                  }}
                >
                  {decisionActions[decision]}
                  {current && <span className="sr-only"> (current)</span>}
                </ActionButton>
              );
            })}
          </div>
          <span className="hint">
            Analyze starts a job only after you submit its dialog.
          </span>
        </div>
      </Panel>
      <Tabs
        label="Commit evidence"
        items={[
          { id: "source", label: "Source diff", count: commit.files.length },
          { id: "triage", label: "Triage" },
          {
            id: "analysis",
            label: "Analysis & artifacts",
            count: commit.analyses.length,
          },
        ]}
        active={activeView}
        onChange={(value) => updateView({ view: value })}
      />
      {activeView === "source" && (
        <Panel
          title="Source diff"
          description={`${commit.files.length} changed ${commit.files.length === 1 ? "path" : "paths"} · ${commit.diff_complete ? "complete input" : "input is incomplete"}`}
        >
          {commit.files.length > 0 && !commit.diff && (
            <div className="changed-paths">
              {commit.files.map((file) => (
                <code key={file.path}>
                  {file.path}
                  {file.status &&
                    file.status !== "modified" &&
                    ` (${file.status})`}
                </code>
              ))}
            </div>
          )}
          {commit.diff ? (
            <DiffFiles diff={commit.diff} files={commit.files} />
          ) : (
            <div className="panel-body">
              <Callout tone="warm" title="No diff available">
                Analysis may need additional source context and can report
                Insufficient context.
              </Callout>
            </div>
          )}
        </Panel>
      )}
      {activeView === "triage" && (
        <Panel
          title="Triage evidence"
          description="Triage result, Pre-filter flags, and input completeness"
          padded
        >
          <div className="triage-summary">
            <TriageBadge commit={commit} />
            {confidence && (
              <span className="muted">Confidence: {confidence}</span>
            )}
          </div>
          {reason ? (
            <p className="readable-copy">{reason}</p>
          ) : (
            <p className="muted">
              {commit.triage_status === "disabled"
                ? "Triage is disabled for this application. Review the change manually."
                : "No Triage reason recorded."}
            </p>
          )}
          <h3>Pre-filter</h3>
          {commit.prefilter.length ? (
            <ul className="prefilter-list" aria-label="Pre-filter rules">
              {commit.prefilter.map((flag) => (
                <li key={flag.rule}>
                  <strong>{prefilterLabel(flag.rule)}</strong>
                  {flag.paths.map((path) => (
                    <code key={path}>{path}</code>
                  ))}
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">No sensitive files were flagged.</p>
          )}
          <p className="hint">
            The Pre-filter only flags files; it never decides on its own.
          </p>
          {commit.diff_complete ? (
            <Callout tone="good">
              Diff input is complete for this revision.
            </Callout>
          ) : (
            <Callout tone="warm" title="Diff input is incomplete">
              Triage cannot call it unrelated, and an Analysis that finds no
              security bearing gives Insufficient context.
            </Callout>
          )}
          <div className="triage-footer">
            {source && (
              <Link
                className="secondary button"
                to={`/applications/${source.id}?tab=audit`}
              >
                Inspect audit context
              </Link>
            )}
            <span className="hint">
              A security candidate or insufficient context result starts
              Analysis automatically.
            </span>
          </div>
          {commit.triage_result !== null && (
            <Evidence value={commit.triage_result} label="Triage result" />
          )}
        </Panel>
      )}
      {activeView === "analysis" && (
        <Panel
          title="Analysis"
          description="Each run keeps its source input and resolved execution profile."
        >
          <AnalysisHistory
            analyses={commit.analyses}
            applicationId={commit.application_id ?? ""}
            commitId={commit.id}
            onRerun={() => setAnalyze(true)}
          />
        </Panel>
      )}
      {analyze && (
        <JobLaunch
          path={`/commits/${commit.id}/analyses`}
          operation="commit_analysis"
          initialProfile={application.data?.config.profiles.commit_analysis}
          context={
            <div className="commit-launch-context">
              <p>
                <strong>{commitTitle(commit)}</strong>
              </p>
              <p className="mono">{commit.revision}</p>
              <p>
                {application.data?.product_name || "Source context"} ·{" "}
                {commit.diff_complete ? "Complete diff" : "Incomplete diff"}
              </p>
              <p className="hint">
                Analysis reads a read-only checkout of this commit and builds
                nothing. It gives one Verdict and may draft a Proof bundle,
                which a Lab verifies only after your Approval.
              </p>
            </div>
          }
          onClose={() => setAnalyze(false)}
          onSubmitted={refresh}
        />
      )}
    </>
  );
}
