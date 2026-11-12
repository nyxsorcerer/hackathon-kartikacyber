import { useEffect, useMemo, useState } from "react";
import {
  Check,
  CircleDashed,
  FileSearch,
  FileText,
  LoaderCircle,
  RefreshCw,
  Search,
  Sparkles,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useArtifactText, useQueryState, useResource } from "../hooks";
import {
  auditCoverageSchema,
  auditOrientationSchema,
  auditsSchema,
} from "../types";
import type {
  Artifact,
  AuditContextRecord as Context,
  AuditCoverage,
  Application,
} from "../types";
import { ArtifactPreview } from "../components/ArtifactPreview";
import {
  Badge,
  Callout,
  DataState,
  describeError,
  Empty,
  JobLink,
  matches,
  Markdown,
  Panel,
  sentence,
  Time,
} from "../components/ui";
const ENTRY = "audit-context-building.md";
const stages = [
  { id: "orientation", label: "Orientation" },
  { id: "functions", label: "Function analysis" },
  { id: "synthesis", label: "Synthesis" },
  { id: "complete", label: "Complete" },
];
function coverageOf(context: Context): AuditCoverage {
  const parsed = auditCoverageSchema.safeParse(context.coverage);
  return parsed.success ? parsed.data : {};
}
function shortRef(ref: string) {
  return ref.length > 12 ? ref.slice(0, 12) : ref;
}
/** Bullet items under an "Open questions" heading in the entry report. */
export function openQuestions(markdown: string) {
  const questions: string[] = [];
  let inSection = false;
  for (const line of markdown.split("\n")) {
    if (/^#{1,6}\s/.test(line)) {
      inSection = /open questions/i.test(line);
      continue;
    }
    const item = inSection && line.match(/^\s*(?:[-*+]|\d+[.)])\s+(.+)$/);
    if (item) questions.push(item[1].trim());
  }
  return questions;
}
type Doc = {
  key: string;
  label: string;
  detail?: string;
  artifact?: Artifact;
  state: "ready" | "failed" | "pending";
  error?: string;
};
type DocGroups = { overview: Doc[]; functions: Doc[]; supporting: Doc[] };
/**
 * Organize a context's artifacts for reading: the entry report and dossier,
 * one entry per selected function (named from orientation.json or the entry
 * report's links), then supporting data files.
 */
export function organizeDocs(
  artifacts: Artifact[],
  coverage: AuditCoverage,
  orientation: { functions?: { name?: string; path?: string; id?: string }[] },
  entryText: string | undefined,
): DocGroups {
  const byPath = new Map(artifacts.map((a) => [a.path, a]));
  const used = new Set<string>();
  const take = (artifact: Artifact | undefined) => {
    if (artifact) used.add(artifact.path);
    return artifact;
  };
  const overview: Doc[] = [];
  const entry = take(byPath.get(ENTRY));
  if (entry)
    overview.push({
      key: entry.path,
      label: "Entry report",
      artifact: entry,
      state: "ready",
    });
  for (const artifact of artifacts)
    if (artifact.path.endsWith("DOSSIER.md")) {
      take(artifact);
      overview.push({
        key: artifact.path,
        label: "System dossier",
        detail: artifact.path,
        artifact,
        state: "ready",
      });
    }
  const linkNames = new Map<string, string>();
  for (const match of (entryText || "").matchAll(
    /\[([^\]]+)\]\((functions\/[^)\s]+\.md)\)/g,
  ))
    linkNames.set(match[2], match[1]);
  const failed = coverage.failed_units || [];
  const failedFor = (unit: { id?: string; path?: string; name?: string }) =>
    failed.find(
      (f) =>
        (unit.id && f.unit.id === unit.id) ||
        (f.unit.name === unit.name && f.unit.path === unit.path),
    );
  const functions: Doc[] = [];
  (orientation.functions || []).forEach((unit, i) => {
    const path = `functions/${String(i + 1).padStart(3, "0")}.md`;
    const artifact = take(byPath.get(path));
    const failure = failedFor(unit);
    functions.push({
      key: artifact?.path || `unit:${i}`,
      label: unit.name || linkNames.get(path) || `Function ${i + 1}`,
      detail: unit.path,
      artifact,
      state: artifact ? "ready" : failure ? "failed" : "pending",
      error: failure
        ? describeError(failure.error) || "Analysis failed"
        : undefined,
    });
  });
  // Without orientation.json, fall back to the documents and failures present.
  for (const artifact of artifacts)
    if (artifact.path.startsWith("functions/") && !used.has(artifact.path)) {
      take(artifact);
      functions.push({
        key: artifact.path,
        label:
          linkNames.get(artifact.path) ||
          artifact.path.replace(/^functions\//, ""),
        artifact,
        state: "ready",
      });
    }
  if (!orientation.functions?.length)
    failed.forEach((f, i) =>
      functions.push({
        key: `failed:${i}`,
        label: f.unit.name || `Function ${i + 1}`,
        detail: f.unit.path,
        state: "failed",
        error: describeError(f.error) || "Analysis failed",
      }),
    );
  const supporting: Doc[] = artifacts
    // Function records are bookkeeping for resuming and refreshing, not a document to read.
    .filter((a) => !used.has(a.path) && a.path !== "audit-functions.json")
    .sort((a, b) => a.path.localeCompare(b.path))
    .map((artifact) => ({
      key: artifact.path,
      label: artifact.path.split("/").pop() || artifact.path,
      detail: artifact.path.includes("/") ? artifact.path : undefined,
      artifact,
      state: "ready",
    }));
  return { overview, functions, supporting };
}
export function AuditTab({
  application,
  onGenerate,
  onRefresh,
}: {
  application: Application;
  onGenerate: () => void;
  onRefresh: (context: Context) => void;
}) {
  const [poll, setPoll] = useState(0);
  const resource = useResource(
    `/applications/${application.id}/audit-contexts`,
    auditsSchema,
    poll,
  );
  const contexts = resource.data?.items || [];
  const running = contexts.some((c) => c.status === "running");
  useEffect(() => setPoll(running ? 5000 : 0), [running]);
  const [query, update] = useQueryState({ ctx: "", doc: "" });
  const selected = contexts.find((c) => c.id === query.ctx) || contexts[0];
  return (
    <Panel
      title="Audit context"
      description="Trail of Bits structure and assumptions, pinned to a source revision."
      actions={
        <button className="primary" onClick={onGenerate}>
          <Sparkles size={15} aria-hidden="true" />
          Generate context
        </button>
      }
    >
      <DataState
        loading={resource.loading}
        error={resource.error}
        retry={resource.refresh}
        hasData={!!resource.data}
      >
        {selected ? (
          <>
            {contexts.length > 1 && (
              <div
                className="revision-strip"
                role="group"
                aria-label="Context revisions"
              >
                {contexts.map((context, i) => (
                  <button
                    key={context.id}
                    type="button"
                    aria-pressed={context === selected}
                    onClick={() =>
                      update({ ctx: i === 0 ? null : context.id, doc: null })
                    }
                  >
                    <span
                      className={`status-dot ${statusTone(context.status)}`}
                      aria-hidden="true"
                    />
                    <span className="mono">{shortRef(context.source_ref)}</span>
                    <span className="revision-meta">
                      {humanStatus(context.status)} ·{" "}
                      <Time value={context.created_at} />
                    </span>
                    {i === 0 && <span className="revision-latest">Latest</span>}
                  </button>
                ))}
              </div>
            )}
            <ContextView
              key={selected.id}
              context={selected}
              application={application}
              latest={selected === contexts[0]}
              doc={query.doc}
              onDoc={(doc) => update({ doc })}
              onGenerate={onGenerate}
              onRefresh={() => onRefresh(selected)}
            />
          </>
        ) : (
          <Empty
            icon={FileSearch}
            title="No audit context yet"
            description="Generate a source-referenced entry report, system dossier, and per-function documents for the current revision. CVE analysis and finding artifacts start from it to orient themselves; commit analysis judges each change on its own."
            action={
              <button className="primary" onClick={onGenerate}>
                <Sparkles size={15} aria-hidden="true" />
                Generate audit context
              </button>
            }
          />
        )}
      </DataState>
    </Panel>
  );
}
function statusTone(status: string) {
  return (
    {
      complete: "good",
      partial: "warm",
      stale: "warm",
      running: "info",
      failed: "danger",
    }[status] || "neutral"
  );
}
function humanStatus(status: string) {
  return status.charAt(0).toUpperCase() + status.slice(1);
}
function ContextView({
  context,
  application,
  latest,
  doc,
  onDoc,
  onGenerate,
  onRefresh,
}: {
  context: Context;
  application: Application;
  latest: boolean;
  doc: string;
  onDoc: (doc: string | null) => void;
  onGenerate: () => void;
  onRefresh: () => void;
}) {
  const coverage = coverageOf(context);
  const byPath = (path: string) =>
    context.artifacts.find((a) => a.path === path);
  const entryText = useArtifactText(byPath(ENTRY)?.id)?.text;
  const orientationText = useArtifactText(byPath("orientation.json")?.id)?.text;
  const orientation = useMemo(() => {
    try {
      const parsed = auditOrientationSchema.safeParse(
        JSON.parse(orientationText || "{}"),
      );
      return parsed.success ? parsed.data : {};
    } catch {
      return {};
    }
  }, [orientationText]);
  const groups = useMemo(
    () =>
      organizeDocs(
        context.artifacts,
        coverageOf(context),
        orientation,
        entryText,
      ),
    [context, orientation, entryText],
  );
  const questions = useMemo(() => openQuestions(entryText || ""), [entryText]);
  const all = [...groups.overview, ...groups.functions, ...groups.supporting];
  const active = all.find((d) => d.key === doc) || groups.overview[0] || all[0];
  return (
    <>
      <ContextSummary
        context={context}
        coverage={coverage}
        application={application}
        latest={latest}
        onGenerate={onGenerate}
        onRefresh={onRefresh}
      />
      {(questions.length > 0 || orientation.overview) && (
        <div className="audit-insights">
          {questions.length > 0 && <OpenQuestions questions={questions} />}
          {orientation.overview && (
            <section className="audit-insight">
              <h3>Orientation</h3>
              <Markdown compact>{orientation.overview}</Markdown>
            </section>
          )}
        </div>
      )}
      {all.length > 0 ? (
        <div className="audit-reader">
          <DocNav
            groups={groups}
            active={active}
            onSelect={(d) => onDoc(d.key)}
          />
          <div className="audit-viewer">
            {active?.artifact ? (
              <ArtifactPreview
                key={active.artifact.id}
                artifact={active.artifact}
                relatedArtifacts={context.artifacts}
                onOpen={(id) => {
                  const target = context.artifacts.find((a) => a.id === id);
                  if (target) onDoc(target.path);
                }}
              />
            ) : active ? (
              <div className="audit-viewer-empty">
                <h3>{active.label}</h3>
                {active.detail && <p className="mono muted">{active.detail}</p>}
                {active.state === "failed" ? (
                  <Callout
                    tone="danger"
                    title="Analysis failed for this function"
                  >
                    {active.error}
                  </Callout>
                ) : (
                  <Callout tone="info" title="Not analysed">
                    The run{" "}
                    {context.status === "running"
                      ? "has not reached"
                      : "stopped before"}{" "}
                    this function, so no document exists for it.
                  </Callout>
                )}
              </div>
            ) : null}
          </div>
        </div>
      ) : (
        <p className="hint audit-no-docs">
          {context.status === "running"
            ? "Documents appear here as each checkpoint is published."
            : "This revision published no documents."}
        </p>
      )}
    </>
  );
}
function ContextSummary({
  context,
  coverage,
  application,
  latest,
  onGenerate,
  onRefresh,
}: {
  context: Context;
  coverage: AuditCoverage;
  application: Application;
  latest: boolean;
  onGenerate: () => void;
  onRefresh: () => void;
}) {
  const selected = coverage.selected || 0;
  const completed = coverage.completed || 0;
  const failed = coverage.failed || 0;
  const omitted =
    coverage.omitted ?? Math.max(0, selected - completed - failed);
  const finished =
    ["complete", "stale"].includes(context.status) ||
    coverage.stage === "complete";
  const stageIndex = finished
    ? stages.length - 1
    : Math.max(
        0,
        stages.findIndex((s) => s.id === coverage.stage),
      );
  const stopped = context.status === "partial" && coverage.interrupted;
  const generationGap =
    context.source_generation !== undefined &&
    context.source_generation !== application.source_generation;
  const current = context.status === "complete" && latest && !generationGap;
  const pct = (n: number) => `${selected ? (n / selected) * 100 : 0}%`;
  return (
    <div className="audit-summary">
      <div className="audit-summary-head">
        <div className="audit-summary-title">
          <h3>
            Revision{" "}
            <span className="mono">{shortRef(context.source_ref)}</span>
          </h3>
          <Badge>{context.status}</Badge>
          {current && <Badge tone="good">Current</Badge>}
          {latest && !current && <Badge tone="accent">Latest</Badge>}
        </div>
        <p className="audit-summary-meta">
          Generated <Time value={context.created_at} /> · Source generation{" "}
          {context.source_generation ?? "unknown"} · Skill{" "}
          <span className="mono">{context.skill_revision.slice(0, 12)}</span>
          {context.job_id && (
            <>
              {" · "}
              <JobLink id={context.job_id} />
            </>
          )}
        </p>
        <p className="audit-summary-meta">
          Scope:{" "}
          {coverage.scope || "Significant functions selected by orientation"}
        </p>
        {coverage.refresh && (
          <p className="audit-summary-meta">
            Refreshed from{" "}
            <span className="mono">
              {shortRef(coverage.refresh.from_revision)}
            </span>{" "}
            with its orientation · {coverage.refresh.changed_files_total}{" "}
            {coverage.refresh.changed_files_total === 1 ? "file" : "files"}{" "}
            changed · {coverage.reused_functions || 0} reused ·{" "}
            {Math.max(0, completed - (coverage.reused_functions || 0))} analysed
            again
            {coverage.removed ? ` · ${coverage.removed} removed` : ""}
          </p>
        )}
        {(coverage.deferred || 0) > 0 && (
          <p className="audit-summary-meta">
            Orientation selected {coverage.deferred} more{" "}
            {coverage.deferred === 1 ? "function" : "functions"} than the limit;
            the most significant {selected} were analysed.
          </p>
        )}
      </div>
      <ol className="stage-steps" aria-label="Generation stages">
        {stages.map((stage, i) => {
          const state =
            i < stageIndex || (finished && i === stageIndex)
              ? "done"
              : i === stageIndex
                ? context.status === "running"
                  ? "active"
                  : stopped
                    ? "stopped"
                    : "active"
                : "todo";
          const Icon: LucideIcon | null =
            state === "done"
              ? Check
              : state === "stopped"
                ? X
                : state === "active"
                  ? LoaderCircle
                  : null;
          return (
            <li key={stage.id} className={state}>
              <span className="stage-dot" aria-hidden="true">
                {Icon && (
                  <Icon
                    size={12}
                    className={
                      state === "active" && context.status === "running"
                        ? "spin"
                        : ""
                    }
                  />
                )}
              </span>
              {stage.label}
              <span className="sr-only">
                {" "}
                (
                {state === "done"
                  ? "done"
                  : state === "stopped"
                    ? "stopped"
                    : state === "active"
                      ? "in progress"
                      : "not reached"}
                )
              </span>
            </li>
          );
        })}
      </ol>
      <div className="coverage-block">
        {selected > 0 ? (
          <>
            <div
              className="coverage-bar"
              role="img"
              aria-label={`${completed} of ${selected} functions analysed, ${failed} failed, ${omitted} not reached`}
            >
              <span className="good" style={{ width: pct(completed) }} />
              <span className="danger" style={{ width: pct(failed) }} />
              <span className="neutral" style={{ width: pct(omitted) }} />
            </div>
            <div className="coverage-legend">
              <span>
                <i className="status-dot good" /> {completed} analysed
              </span>
              <span>
                <i className="status-dot danger" /> {failed} failed
              </span>
              <span>
                <i className="status-dot neutral" /> {omitted} not reached
              </span>
              <span className="muted">of {selected} selected functions</span>
            </div>
          </>
        ) : (
          <p className="muted">
            {context.status === "running"
              ? "Orientation is choosing the significant functions to analyse."
              : "No functions were selected for analysis."}
          </p>
        )}
      </div>
      <GapCallout
        context={context}
        coverage={coverage}
        application={application}
        generationGap={generationGap}
        onGenerate={onGenerate}
        onRefresh={onRefresh}
      />
    </div>
  );
}
function GapCallout({
  context,
  coverage,
  application,
  generationGap,
  onGenerate,
  onRefresh,
}: {
  context: Context;
  coverage: AuditCoverage;
  application: Application;
  generationGap: boolean;
  onGenerate: () => void;
  onRefresh: () => void;
}) {
  const stage =
    stages.find((s) => s.id === coverage.stage)?.label.toLowerCase() ||
    "generation";
  const failures = coverage.failed_units || [];
  const regenerate = (label: string) => (
    <button className="secondary" onClick={onGenerate}>
      <Sparkles size={14} aria-hidden="true" />
      {label}
    </button>
  );
  if (context.status === "running")
    return (
      <Callout tone="info" title={`Generating · ${stage}`}>
        Checkpoints publish as each function completes, so documents below
        update while the job runs.
      </Callout>
    );
  if (generationGap)
    return (
      <Callout
        tone="warm"
        title="Stale for the current source"
        action={regenerate("Generate current context")}
      >
        Generated for source generation {context.source_generation}; the
        application is now at generation {application.source_generation}, so
        analyses no longer use it.
      </Callout>
    );
  if (context.status === "stale")
    return (
      <Callout
        tone="warm"
        title="Behind the current source"
        action={
          <div className="inline-actions">
            {(coverage.completed || 0) > 0 && (
              <button className="primary" onClick={onRefresh}>
                <RefreshCw size={14} aria-hidden="true" />
                Refresh for current source
              </button>
            )}
            {regenerate("Generate fresh context")}
          </div>
        }
      >
        New upstream revisions were imported after{" "}
        {shortRef(context.source_ref)}. Analyses still start from it and check
        what changed. A refresh analyses only the functions in changed files
        again and reuses the rest.
      </Callout>
    );
  if (context.status === "partial" && coverage.interrupted)
    return (
      <Callout
        tone="warm"
        title={`Stopped during ${stage}`}
        action={regenerate("Generate missing context")}
      >
        {sentence(
          describeError(coverage.error) ||
            coverage.reason ||
            "The job ended before finishing",
        )}{" "}
        {coverage.completed || 0} of {coverage.selected || 0} functions were
        analysed before it stopped; that checkpoint is kept.
      </Callout>
    );
  if (failures.length)
    return (
      <Callout
        tone="warm"
        title={`${failures.length} of ${coverage.selected || failures.length} functions failed analysis`}
        action={regenerate("Generate again")}
      >
        <ul className="gap-list">
          {failures.slice(0, 4).map((f, i) => (
            <li key={i}>
              <strong>{f.unit.name || "Unnamed function"}</strong>
              {f.unit.path && (
                <span className="mono"> {f.unit.path}</span>
              )} — {describeError(f.error) || "Analysis failed"}
            </li>
          ))}
        </ul>
      </Callout>
    );
  return null;
}
function OpenQuestions({ questions }: { questions: string[] }) {
  const [all, setAll] = useState(false);
  const shown = all ? questions : questions.slice(0, 4);
  return (
    <section className="audit-insight">
      <h3>
        Open questions <span className="tab-count">{questions.length}</span>
      </h3>
      <ul className="question-list">
        {shown.map((question, i) => (
          <li key={i}>
            <Markdown compact>{question}</Markdown>
          </li>
        ))}
      </ul>
      {questions.length > 4 && (
        <button
          type="button"
          className="text-button"
          onClick={() => setAll(!all)}
        >
          {all ? "Show fewer" : `Show all ${questions.length}`}
        </button>
      )}
    </section>
  );
}
const docIcons: Record<Doc["state"], LucideIcon> = {
  ready: FileText,
  failed: X,
  pending: CircleDashed,
};
function DocNav({
  groups,
  active,
  onSelect,
}: {
  groups: DocGroups;
  active: Doc | undefined;
  onSelect: (doc: Doc) => void;
}) {
  const [filter, setFilter] = useState("");
  const functions = groups.functions.filter((d) =>
    matches(filter, d.label, d.detail),
  );
  const analysed = groups.functions.filter((d) => d.state === "ready").length;
  const item = (doc: Doc) => {
    const Icon =
      doc.state === "ready" && groups.functions.includes(doc)
        ? Check
        : docIcons[doc.state];
    return (
      <li key={doc.key}>
        <button
          type="button"
          className={`doc-item ${doc.state}`}
          aria-current={doc === active ? "true" : undefined}
          onClick={() => onSelect(doc)}
        >
          <Icon size={14} aria-hidden="true" />
          <span className="doc-text">
            <span>{doc.label}</span>
            {doc.detail && <small className="mono">{doc.detail}</small>}
          </span>
          <span className="sr-only">
            {doc.state === "failed"
              ? " (failed)"
              : doc.state === "pending"
                ? " (not analysed)"
                : ""}
          </span>
        </button>
      </li>
    );
  };
  return (
    <nav className="audit-nav" aria-label="Context documents">
      {groups.overview.length > 0 && (
        <div className="doc-group">
          <h4>Overview</h4>
          <ul>{groups.overview.map(item)}</ul>
        </div>
      )}
      {groups.functions.length > 0 && (
        <div className="doc-group">
          <h4>
            Functions{" "}
            <span className="muted">
              {analysed}/{groups.functions.length}
            </span>
          </h4>
          {groups.functions.length > 8 && (
            <label className="doc-filter">
              <Search size={13} aria-hidden="true" />
              <input
                type="search"
                aria-label="Filter functions"
                placeholder="Filter functions"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
            </label>
          )}
          <ul>{functions.map(item)}</ul>
          {!functions.length && <p className="hint">No functions match.</p>}
        </div>
      )}
      {groups.supporting.length > 0 && (
        <details className="doc-group doc-supporting">
          <summary>
            <h4>
              Supporting files{" "}
              <span className="muted">{groups.supporting.length}</span>
            </h4>
          </summary>
          <ul>{groups.supporting.map(item)}</ul>
        </details>
      )}
    </nav>
  );
}
