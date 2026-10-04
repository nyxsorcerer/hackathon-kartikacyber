import { useCallback, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ChevronLeft,
  ChevronRight,
  FileSearch,
  GitCommitHorizontal,
  Sparkles,
} from "lucide-react";
import { mutate } from "../api";
import type { Collection } from "../hooks";
import {
  useCollection,
  useQueryState,
  useResource,
  useShortcut,
} from "../hooks";
import { commitSchema, commitsSchema, programSchema } from "../types";
import type { Analysis, Commit, CommitFile, Program } from "../types";
import { ArtifactBrowser } from "../components/ArtifactPreview";
import { JobLaunch } from "../components/JobLaunch";
import {
  ActionButton,
  Badge,
  Callout,
  CopyButton,
  countBy,
  DataState,
  DetailGrid,
  DiffView,
  Empty,
  Evidence,
  ExternalLink,
  FilterSelect,
  humanize,
  Markdown,
  matches,
  notify,
  PageHeading,
  Panel,
  ResultSummary,
  SearchField,
  Segmented,
  Time,
  toneFor,
  useShowMore,
} from "../components/ui";
const findingCategories = [
  "Likely vulnerability fix",
  "Potentially introduced vulnerability",
];
function categoryOf(analysis: Analysis) {
  return analysis.result?.category || analysis.category;
}
function triageField(
  commit: Commit,
  key: "decision" | "reason" | "confidence",
) {
  const result = commit.triage_result;
  if (typeof result !== "object" || !result || !(key in result)) return;
  const value: unknown = Reflect.get(result, key);
  return typeof value === "string" ? value : undefined;
}
function TriageBadge({ commit }: { commit: Commit }) {
  return (
    <Badge>{triageField(commit, "decision") || commit.triage_status}</Badge>
  );
}
export function AnalysisHistory({
  analyses,
  programId,
  commitId,
  onRerun,
}: {
  analyses: Analysis[];
  programId: string;
  commitId?: string;
  onRerun?: () => void;
}) {
  return analyses.length ? (
    <div className="row-list">
      {analyses.map((analysis, i) => {
        const category = categoryOf(analysis);
        const summary = analysis.result?.summary || analysis.summary;
        const report = analysis.result?.report || analysis.report;
        return (
          <article className="analysis-entry" key={analysis.id || i}>
            <div className="analysis-header">
              <h3
                className={`analysis-category ${category ? toneFor(category) : "neutral"}`}
              >
                {category || "Analysis report"}
              </h3>
              {i === 0 && analyses.length > 1 && (
                <Badge tone="accent">Latest</Badge>
              )}
              <span className="analysis-time">
                <Time value={analysis.created_at} absolute />
              </span>
            </div>
            {summary && <p className="analysis-summary">{summary}</p>}
            {analysis.profile && (
              <p className="hint">
                {analysis.profile.agent} · {analysis.profile.model_id} ·{" "}
                {analysis.profile.reasoning_effort || "Provider managed"}
              </p>
            )}
            {category === "Insufficient context" && (
              <Callout
                tone="warm"
                title="More source or context is needed"
                action={
                  onRerun && (
                    <button className="secondary" onClick={onRerun}>
                      Run again
                    </button>
                  )
                }
              >
                Check the report for the missing source or stale audit context.
                After those inputs change, run another analysis; this result
                stays in the history.
              </Callout>
            )}
            {report && <Markdown>{report}</Markdown>}
            {analysis.artifacts?.length ? (
              <ArtifactBrowser artifacts={analysis.artifacts} />
            ) : null}
            <div className="analysis-footer">
              <Evidence
                value={analysis}
                label="Source evidence & full result"
              />
              {findingCategories.includes(category || "") && (
                <Link
                  className="secondary button"
                  to={`/findings/new?program_id=${encodeURIComponent(programId)}${commitId ? `&source_commit_id=${encodeURIComponent(commitId)}` : ""}${analysis.id ? `&source_analysis_id=${encodeURIComponent(analysis.id)}` : ""}`}
                >
                  Create finding
                </Link>
              )}
            </div>
          </article>
        );
      })}
    </div>
  ) : (
    <Empty
      icon={FileSearch}
      title="No detailed analysis yet"
      description="Choose Analyze and submit an execution profile to investigate this change. Each run is kept."
    />
  );
}
const decisionLabels: Record<string, string> = {
  candidate: "Marked for review",
  pending: "Pending",
  dismissed: "Dismissed",
};
function committedAt(commit: Commit) {
  return commit.committed_at ? Date.parse(commit.committed_at) || 0 : 0;
}
/** Newest first; undated revisions sort last. */
export function sortCommits(items: Commit[], oldest = false) {
  return [...items].sort((a, b) =>
    oldest ? committedAt(a) - committedAt(b) : committedAt(b) - committedAt(a),
  );
}
function triageKey(commit: Commit) {
  return triageField(commit, "decision") || commit.triage_status;
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
        ...c.files.flatMap((file) => [file.path, file.previous_path]),
      ) &&
      (skip === "decision" ||
        f.decision === "all" ||
        c.review_decision === f.decision) &&
      (skip === "triage" || f.triage === "all" || triageKey(c) === f.triage) &&
      (skip === "show" ||
        f.show === "all" ||
        (f.show === "analyzed" && c.analyses.length > 0) ||
        (f.show === "unanalyzed" && c.analyses.length === 0) ||
        (f.show === "incomplete" && !c.diff_complete)),
  );
}
export function CommitList({
  program,
  collection,
}: {
  program?: Program;
  collection?: Collection<Commit>;
}) {
  const own = useCollection(
    collection
      ? null
      : program
        ? `/programs/${program.id}/commits`
        : "/commits",
    commitsSchema,
  );
  const commits = collection || own;
  const [filters, update] = useQueryState({
    q: "",
    decision: program ? "all" : "candidate",
    triage: "all",
    show: "all",
    sort: "newest",
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
  const { shown, footer } = useShowMore(
    visible,
    [
      filters.q,
      filters.decision,
      filters.triage,
      filters.show,
      filters.sort,
    ].join("|"),
  );
  const decisionCounts = countBy(
    applyCommitFilters(items, filters, "decision"),
    (c) => c.review_decision,
  );
  const triageCounts = countBy(
    applyCommitFilters(items, filters, "triage"),
    triageKey,
  );
  const clear = () =>
    update({ q: "", decision: "all", triage: "all", show: "all" });
  let lastDay = "";
  return (
    <Panel
      title={program ? "Source history" : "Review queue"}
      description="Triage classification and detailed analysis are separate judgments."
    >
      <div className="explorer-toolbar">
        <SearchField
          label="Search revisions"
          placeholder="Search message, author, revision, or path"
          value={filters.q}
          onChange={(q) => update({ q })}
        />
        <Segmented
          label="Review decision"
          value={filters.decision}
          onChange={(decision) => update({ decision })}
          options={[
            ...["candidate", "pending", "dismissed"].map((value) => ({
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
          onChange={(show) => update({ show })}
          options={[
            { value: "all", label: "All revisions" },
            { value: "analyzed", label: "With analysis" },
            { value: "unanalyzed", label: "Not analyzed" },
            { value: "incomplete", label: "Incomplete diff" },
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
      <DataState
        loading={commits.loading}
        error={commits.error}
        retry={commits.refresh}
        hasData={!!commits.data}
      >
        {items.length > 0 && (
          <div className="explorer-summary">
            <ResultSummary
              shown={visible.length}
              total={items.length}
              noun={["revision", "revisions"]}
              truncated={commits.data?.truncated}
              onClear={clear}
            />
          </div>
        )}
        {visible.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Revision / message</th>
                  <th scope="col">Author</th>
                  <th scope="col">Triage</th>
                  <th scope="col">Decision</th>
                  <th scope="col">Detailed analysis</th>
                </tr>
              </thead>
              <tbody>
                {shown.flatMap((commit) => {
                  const day = dayLabel(commit);
                  const latest = commit.analyses[0];
                  const rows = [];
                  if (day !== lastDay) {
                    lastDay = day;
                    rows.push(
                      <tr className="group-row" key={`day-${day}`}>
                        <th scope="colgroup" colSpan={5}>
                          {day}
                        </th>
                      </tr>,
                    );
                  }
                  rows.push(
                    <tr key={commit.id}>
                      <td>
                        <Link
                          className="table-title"
                          to={`/commits/${commit.id}`}
                        >
                          {commit.message.split("\n")[0]}
                        </Link>
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
                        {!commit.diff_complete && (
                          <div className="table-subtitle warning">
                            Incomplete diff
                          </div>
                        )}
                      </td>
                      <td>
                        <Badge>{commit.review_decision}</Badge>
                      </td>
                      <td>
                        {latest ? (
                          <Badge>
                            {categoryOf(latest) || "Report available"}
                          </Badge>
                        ) : (
                          <span className="muted">Not analyzed</span>
                        )}
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
              filters.decision === "candidate" && !filters.q
                ? "Nothing marked for review"
                : "No revisions match these filters"
            }
            description={
              filters.decision === "candidate"
                ? "Security candidates from triage, and changes you mark, appear here."
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
              program
                ? "Run a source check to import the available history."
                : "Revisions appear here after source checks import them."
            }
          />
        )}
      </DataState>
    </Panel>
  );
}
export function Reviews() {
  return (
    <>
      <PageHeading
        eyebrow="Upstream intelligence"
        title="Commit review"
        description="Inspect source changes, decide what needs investigation, and keep the evidence."
      />
      <CommitList />
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
/** Newer/older navigation through a program's revisions. */
function HistoryPager({ commit }: { commit: Commit }) {
  const navigate = useNavigate();
  const history = useCollection(
    `/programs/${commit.program_id}/commits`,
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
const decisions = [
  { value: "pending", label: "Leave pending" },
  { value: "candidate", label: "Mark for review" },
  { value: "dismissed", label: "Dismiss" },
];
function CommitDetailBody({
  commit,
  refresh,
}: {
  commit: Commit;
  refresh: () => void;
}) {
  const [analyze, setAnalyze] = useState(false);
  const program = useResource(`/programs/${commit.program_id}`, programSchema);
  const source = program.data;
  const reason = triageField(commit, "reason");
  const confidence = triageField(commit, "confidence");
  return (
    <>
      <HistoryPager commit={commit} />
      <PageHeading
        back={{ to: "/reviews", label: "Commit review" }}
        eyebrow={`Revision ${commit.revision.slice(0, 12)}`}
        title={commit.message.split("\n")[0]}
        description={
          source && (
            <Link to={`/programs/${source.id}?tab=commits`}>
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
      <Panel padded>
        <DetailGrid
          items={[
            [
              "Upstream source",
              source ? (
                <ExternalLink href={source.source_url}>
                  {source.source_kind === "wordpress"
                    ? `WordPress · ${source.plugin_slug}`
                    : source.source_url?.replace("https://github.com/", "")}
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
            ["Triage", <TriageBadge commit={commit} />],
            ["Operator decision", <Badge>{commit.review_decision}</Badge>],
          ]}
        />
        <div className="decision-bar">
          <span className="field-label" id="decision-label">
            Review decision
          </span>
          <div
            className="segmented"
            role="group"
            aria-labelledby="decision-label"
          >
            {decisions.map((decision) => {
              const current = commit.review_decision === decision.value;
              return (
                <ActionButton
                  key={decision.value}
                  className={current ? "selected" : ""}
                  disabled={current}
                  onAction={async () => {
                    await mutate(`/commits/${commit.id}/review`, commitSchema, {
                      decision: decision.value,
                    });
                    notify(
                      `Decision recorded: ${decision.label.toLowerCase()}.`,
                    );
                    refresh();
                  }}
                >
                  {decision.label}
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
      <Panel
        title="Triage evidence"
        description="Classification input, completeness, and supporting context"
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
              ? "Triage is disabled for this program. Review the change manually."
              : "No classification reason recorded."}
          </p>
        )}
        {commit.diff_complete ? (
          <Callout tone="good">
            Diff input is complete for this revision.
          </Callout>
        ) : (
          <Callout tone="warm" title="Diff input is incomplete">
            An unrelated classification cannot be confirmed. Detailed analysis
            may need more source context.
          </Callout>
        )}
        <div className="triage-footer">
          {source && (
            <Link
              className="secondary button"
              to={`/programs/${source.id}?tab=audit`}
            >
              Inspect audit context
            </Link>
          )}
          <span className="hint">
            A security candidate is a prompt to review. It does not start
            analysis.
          </span>
        </div>
        {commit.triage_result !== null && (
          <Evidence
            value={commit.triage_result}
            label="Classification result"
          />
        )}
      </Panel>
      <Panel
        title="Detailed analysis"
        description="Each run keeps its source input and resolved execution profile."
      >
        <AnalysisHistory
          analyses={commit.analyses}
          programId={commit.program_id}
          commitId={commit.id}
          onRerun={() => setAnalyze(true)}
        />
      </Panel>
      {analyze && (
        <JobLaunch
          path={`/commits/${commit.id}/analyses`}
          operation="commit_analysis"
          initialProfile={program.data?.config.profiles.commit_analysis}
          context={`${commit.revision} · ${commit.diff_complete ? "Complete diff" : "Incomplete diff"} · ${program.data?.product_name || "Source context"}`}
          onClose={() => setAnalyze(false)}
          onSubmitted={refresh}
        />
      )}
    </>
  );
}
