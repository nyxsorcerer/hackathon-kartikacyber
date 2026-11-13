import { useMemo } from "react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { Activity, ArrowUpRight, RotateCcw, Square } from "lucide-react";
import { useCollection, useQueryState, useResource } from "../hooks";
import {
  jobSchema,
  jobsSchema,
  operationNames,
  applicationsSchema,
  recordsSchema,
} from "../types";
import type { Job, JobSubject } from "../types";
import {
  duration,
  jobError,
  jobName,
  jobOutcome,
  jobTitle,
  subjectLinkText,
  subjectRefText,
} from "../jobSummary";
import type { JobOutcome } from "../jobSummary";
import { queueJob } from "../components/JobLaunch";
import { AgentSession } from "../components/AgentSession";
import {
  ActionButton,
  Badge,
  Callout,
  countBy,
  DataState,
  DetailGrid,
  Empty,
  Evidence,
  FilterSelect,
  humanize,
  matches,
  PageHeading,
  Panel,
  ResultSummary,
  SearchField,
  Segmented,
  Time,
  useShowMore,
} from "../components/ui";
import { ActivityEvent } from "./Dashboard";
const statuses = [
  "queued",
  "running",
  "cancelling",
  "succeeded",
  "failed",
  "cancelled",
];
type JobFilters = {
  status: string;
  kind: string;
  application: string;
  q: string;
};
function resultId(result: unknown, key: string) {
  if (typeof result !== "object" || !result || !(key in result)) return;
  const value: unknown = Reflect.get(result, key);
  return typeof value === "string" ? value : undefined;
}
function applyJobFilters(items: Job[], f: JobFilters, skip?: keyof JobFilters) {
  return items.filter(
    (job) =>
      matches(
        f.q,
        job.id,
        job.kind,
        jobName(job.kind),
        jobError(job),
        job.application_name,
        job.subject?.label,
        job.subject?.ref,
        job.subject?.detail,
      ) &&
      (skip === "status" || f.status === "all" || job.status === f.status) &&
      (skip === "kind" || f.kind === "all" || job.kind === f.kind) &&
      (skip === "application" ||
        f.application === "all" ||
        (job.application_id || "none") === f.application),
  );
}
/** Group failed jobs by reason so repeated failures read as one problem. */
export function failureGroups(jobs: Job[]) {
  const groups = new Map<
    string,
    {
      reason: string;
      hint?: string;
      count: number;
      kinds: Set<string>;
      latest: string;
    }
  >();
  for (const job of jobs) {
    if (job.status !== "failed") continue;
    const reason = jobError(job);
    const group = groups.get(reason) || {
      reason,
      hint: jobOutcome(job).hint,
      count: 0,
      kinds: new Set<string>(),
      latest: job.created_at,
    };
    group.count += 1;
    group.kinds.add(jobName(job.kind));
    const time = job.finished_at || job.created_at;
    if (time > group.latest) group.latest = time;
    groups.set(reason, group);
  }
  return [...groups.values()].sort((a, b) => b.count - a.count);
}
export function Jobs() {
  const jobs = useCollection("/jobs", jobsSchema, 10000, 600);
  const applications = useResource("/applications", applicationsSchema);
  const [filters, update] = useQueryState({
    status: "all",
    kind: "all",
    application: "all",
    q: "",
  });
  const items = useMemo(() => jobs.data?.items || [], [jobs.data]);
  const visible = useMemo(
    () => applyJobFilters(items, filters),
    [items, filters],
  );
  const { shown, footer } = useShowMore(
    visible,
    [filters.status, filters.kind, filters.application, filters.q].join("|"),
  );
  const statusCounts = countBy(
    applyJobFilters(items, filters, "status"),
    (j) => j.status,
  );
  const kindCounts = countBy(
    applyJobFilters(items, filters, "kind"),
    (j) => j.kind,
  );
  const applicationCounts = countBy(
    applyJobFilters(items, filters, "application"),
    (j) => j.application_id || "none",
  );
  const failures = failureGroups(applyJobFilters(items, filters, "status"));
  const clear = () =>
    update({ status: "all", kind: "all", application: "all", q: "" });
  return (
    <>
      <PageHeading
        eyebrow="Execution history"
        title="Jobs"
        description="Progress, preserved execution profiles, failures, and retained partial outputs."
      />
      {failures.length > 0 && ["all", "failed"].includes(filters.status) && (
        <Panel
          title="Top failure reasons"
          description="Failed jobs grouped by their reported reason"
        >
          <div className="row-list">
            {failures.slice(0, 5).map((group) => (
              <div className="failure-row" key={group.reason}>
                <span className="failure-count">{group.count}×</span>
                <div className="failure-main">
                  <strong>{group.reason}</strong>
                  {group.hint && (
                    <span className="failure-hint">{group.hint}</span>
                  )}
                  <span className="muted">
                    {[...group.kinds].join(", ")} · latest{" "}
                    <Time value={group.latest} />
                  </span>
                </div>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => update({ status: "failed", q: group.reason })}
                >
                  Show jobs
                </button>
              </div>
            ))}
          </div>
        </Panel>
      )}
      <Panel>
        <div className="explorer-toolbar">
          <SearchField
            label="Search jobs"
            placeholder="Search subject, operation, error, or job ID"
            value={filters.q}
            onChange={(q) => update({ q })}
          />
          <Segmented
            label="Job status"
            value={filters.status}
            onChange={(status) => update({ status })}
            options={[
              {
                value: "all",
                label: "All",
                count: Object.values(statusCounts).reduce((a, b) => a + b, 0),
              },
              ...statuses
                .filter((s) => statusCounts[s] || s === filters.status)
                .map((value) => ({
                  value,
                  label: humanize(value),
                  count: statusCounts[value] || 0,
                })),
            ]}
          />
          <FilterSelect
            label="Operation"
            value={filters.kind}
            onChange={(kind) => update({ kind })}
            options={[
              { value: "all", label: "Any" },
              ...Object.keys(kindCounts)
                .sort((a, b) => jobName(a).localeCompare(jobName(b)))
                .map((value) => ({
                  value,
                  label: jobName(value),
                  count: kindCounts[value],
                })),
            ]}
          />
          {(applications.data?.items.length || 0) > 0 && (
            <FilterSelect
              label="Application"
              value={filters.application}
              onChange={(application) => update({ application })}
              options={[
                { value: "all", label: "Any" },
                ...(applications.data?.items || []).map((p) => ({
                  value: p.id,
                  label: p.asset_name,
                  count: applicationCounts[p.id] || 0,
                })),
                {
                  value: "none",
                  label: "Installation",
                  count: applicationCounts.none || 0,
                },
              ]}
            />
          )}
          <span className="muted live-indicator">
            <span className="status-dot info" aria-hidden="true" />
            Live
          </span>
        </div>
        <DataState
          loading={jobs.loading}
          error={jobs.error}
          retry={jobs.refresh}
          hasData={!!jobs.data}
        >
          {items.length > 0 && (
            <div className="explorer-summary">
              <ResultSummary
                shown={visible.length}
                total={items.length}
                noun={["job", "jobs"]}
                truncated={jobs.data?.truncated}
                onClear={clear}
              />
            </div>
          )}
          {visible.length ? (
            <div className="table-scroll">
              <table className="jobs-table">
                <thead>
                  <tr>
                    <th scope="col">Job</th>
                    <th scope="col">Outcome</th>
                    <th scope="col">Profile</th>
                    <th scope="col">When</th>
                    <th scope="col">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((job) => {
                    const outcome = jobOutcome(job);
                    const took = duration(job.started_at, job.finished_at);
                    return (
                      <tr key={job.id}>
                        <td className="job-cell">
                          <div className="job-kicker">
                            {jobName(job.kind)}
                            {job.application_id && (
                              <>
                                {" · "}
                                <Link
                                  to={`/applications/${job.application_id}`}
                                >
                                  {job.application_name || "Application"}
                                </Link>
                              </>
                            )}
                          </div>
                          <Link
                            className="table-title clamp"
                            to={`/jobs/${job.id}`}
                            title={jobTitle(job)}
                          >
                            {job.subject?.label || jobName(job.kind)}
                          </Link>
                          {job.subject?.detail && (
                            <div className="table-subtitle clamp">
                              {job.subject.detail}
                            </div>
                          )}
                          <div className="table-subtitle job-refs">
                            {job.subject && (
                              <SubjectLink subject={job.subject} />
                            )}
                            <span className="mono">{job.id.slice(0, 8)}</span>
                          </div>
                        </td>
                        <td>
                          <Badge>{job.status}</Badge>
                          <div
                            className={`table-subtitle clamp job-outcome ${outcome.tone}`}
                          >
                            {outcome.summary}
                          </div>
                        </td>
                        <td>
                          {job.profile ? (
                            <>
                              {job.profile.agent} · {job.profile.model_id}
                              <div className="table-subtitle">
                                {job.profile.reasoning_effort ||
                                  "Provider managed"}
                              </div>
                            </>
                          ) : (
                            <span className="muted">No coding agent</span>
                          )}
                        </td>
                        <td>
                          {job.finished_at ? (
                            <>
                              Finished <Time value={job.finished_at} />
                              {took && (
                                <div className="table-subtitle">
                                  took {took}
                                </div>
                              )}
                            </>
                          ) : (
                            <>
                              Submitted <Time value={job.created_at} />
                            </>
                          )}
                        </td>
                        <td className="cell-actions">
                          <JobActions job={job} refresh={jobs.refresh} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {footer}
            </div>
          ) : (
            <Empty
              icon={Activity}
              title={
                items.length ? "No jobs match these filters" : "No jobs yet"
              }
              description={
                items.length
                  ? "Try a broader status or operation filter."
                  : "Background checks and agent operations appear here after submission."
              }
              action={
                items.length ? (
                  <button className="secondary" onClick={clear}>
                    Clear filters
                  </button>
                ) : undefined
              }
            />
          )}
        </DataState>
      </Panel>
    </>
  );
}
function JobActions({ job, refresh }: { job: Job; refresh: () => void }) {
  // A Lab or Remediation PR is never retried: it needs a new Approval, and a
  // draft is drafted again, from its Finding.
  const retryable =
    ["failed", "cancelled"].includes(job.status) &&
    ![
      "lab_run",
      "remediation_pr",
      "patch_drafting",
      "remediation_draft",
    ].includes(job.kind);
  return (
    <div className="inline-actions">
      {["queued", "running"].includes(job.status) && (
        <ActionButton
          className="secondary"
          confirm="Confirm cancel"
          onAction={async () => {
            await queueJob(
              `/jobs/${job.id}/cancel`,
              {},
              undefined,
              "Cancellation requested.",
            );
            refresh();
          }}
        >
          <Square size={13} aria-hidden="true" />
          Cancel
        </ActionButton>
      )}
      {retryable && (
        <ActionButton
          className="secondary"
          onAction={async () => {
            await queueJob(
              `/jobs/${job.id}/retry`,
              {},
              undefined,
              "Retry submitted with the recorded profile.",
            );
            refresh();
          }}
        >
          <RotateCcw size={13} aria-hidden="true" />
          Retry
        </ActionButton>
      )}
    </div>
  );
}
/** Link to what a job acted on, e.g. "Open commit 74481f468d". */
function SubjectLink({ subject }: { subject: JobSubject }) {
  const label = (
    <>
      {subjectLinkText(subject)}
      {subject.ref && " "}
      {subject.ref && (
        <span className={subject.type === "account" ? "" : "mono"}>
          {subjectRefText(subject)}
        </span>
      )}
    </>
  );
  return subject.link ? (
    <Link className="subject-link" to={subject.link}>
      {label}
      <ArrowUpRight size={13} aria-hidden="true" />
    </Link>
  ) : (
    <span>{label}</span>
  );
}
const outcomeTitles: Record<string, string> = {
  failed: "failed",
  succeeded: "succeeded",
  cancelled: "was cancelled",
  cancelling: "is being cancelled",
  running: "is running",
  queued: "is queued",
};
/** Where the job stands, what it produced or why it failed, and what to do next. */
function OutcomePanel({
  job,
  outcome,
  links,
}: {
  job: Job;
  outcome: JobOutcome;
  links: ReactNode;
}) {
  const tone = outcome.tone === "neutral" ? "info" : outcome.tone;
  return (
    <section
      className={`job-outcome-panel ${outcome.tone}`}
      aria-label="Job outcome"
    >
      <Callout
        tone={tone}
        title={`${jobName(job.kind)} ${outcomeTitles[job.status] || humanize(job.status).toLowerCase()}: ${outcome.summary}`}
      >
        {outcome.hint && <p className="outcome-hint">{outcome.hint}</p>}
        {outcome.facts.length > 0 && (
          <ul className="outcome-facts">
            {outcome.facts.map((fact) => (
              <li key={fact}>{fact}</li>
            ))}
          </ul>
        )}
        {(outcome.action || links) && (
          <div className="inline-actions outcome-actions">
            {outcome.action && (
              <Link className="secondary button" to={outcome.action.to}>
                {outcome.action.label}
              </Link>
            )}
            {links}
          </div>
        )}
        {!!job.error && <Evidence value={job.error} label="Failure details" />}
      </Callout>
    </section>
  );
}
export function JobDetail() {
  const { id } = useParams();
  const resource = useResource(
    `/jobs/${encodeURIComponent(id || "")}`,
    jobSchema,
    3000,
  );
  const events = useResource(
    `/jobs/${encodeURIComponent(id || "")}/events`,
    recordsSchema,
    3000,
  );
  const job = resource.data;
  const findingId = resultId(job?.result, "finding_id");
  const cveId = resultId(job?.result, "cve_id");
  const analysisId = resultId(job?.result, "analysis_id");
  const commitId = resultId(job?.result, "commit_id");
  const resultLinks = job && (
    <>
      {job.kind === "commit_analysis" && commitId && (
        <Link
          className="secondary button"
          to={`/commits/${encodeURIComponent(commitId)}${analysisId ? `?run=${encodeURIComponent(analysisId)}` : ""}`}
        >
          View commit analysis and report
        </Link>
      )}
      {job.kind === "cve_analysis" && cveId && job.application_id && (
        <Link
          className="secondary button"
          to={`/cves?cve=${encodeURIComponent(cveId)}&cve_application=${encodeURIComponent(job.application_id)}&view=analysis${analysisId ? `&run=${encodeURIComponent(analysisId)}` : ""}`}
        >
          View CVE analysis and report
        </Link>
      )}
      {findingId && (
        <Link
          className="secondary button"
          to={`/findings/${encodeURIComponent(findingId)}`}
        >
          View finding artifacts
        </Link>
      )}
    </>
  );
  const hasResultLinks =
    !!job &&
    ((job.kind === "commit_analysis" && !!commitId) ||
      (job.kind === "cve_analysis" && !!cveId && !!job.application_id) ||
      !!findingId);
  return (
    <DataState
      loading={resource.loading}
      error={resource.error}
      retry={resource.refresh}
      hasData={!!job}
    >
      {job && (
        <>
          <PageHeading
            back={{ to: "/jobs", label: "All jobs" }}
            eyebrow={`${jobName(job.kind)} · Job ${job.id.slice(0, 12)}`}
            title={jobTitle(job)}
            description={
              <>
                {job.subject?.detail && (
                  <p className="job-subject-detail">{job.subject.detail}</p>
                )}
                <p className="job-refs">
                  {job.subject && <SubjectLink subject={job.subject} />}
                  {job.application_id && (
                    <Link to={`/applications/${job.application_id}`}>
                      {job.application_name || "Application"}
                    </Link>
                  )}
                </p>
              </>
            }
            actions={<JobActions job={job} refresh={resource.refresh} />}
            meta={
              <>
                <Badge>{job.status}</Badge>
                <span>
                  Submitted <Time value={job.created_at} />
                </span>
                {job.finished_at && (
                  <span>
                    Finished <Time value={job.finished_at} />
                  </span>
                )}
              </>
            }
          />
          <OutcomePanel
            job={job}
            outcome={jobOutcome(job)}
            links={hasResultLinks ? resultLinks : undefined}
          />
          <Panel padded>
            <DetailGrid
              items={[
                [
                  "Application",
                  job.application_id ? (
                    <Link to={`/applications/${job.application_id}`}>
                      {job.application_name || "Application"}
                    </Link>
                  ) : (
                    "Installation operation"
                  ),
                ],
                [
                  "Subject",
                  job.subject ? (
                    <SubjectLink subject={job.subject} />
                  ) : (
                    "Not applicable"
                  ),
                ],
                ["Submitted", <Time value={job.created_at} absolute />],
                [
                  "Started",
                  <Time
                    value={job.started_at}
                    absolute
                    fallback="Not started"
                  />,
                ],
                [
                  "Finished",
                  <Time
                    value={job.finished_at}
                    absolute
                    fallback="Not finished"
                  />,
                ],
                [
                  "Duration",
                  duration(job.started_at, job.finished_at) ||
                    (job.started_at ? "In progress" : "Not started"),
                ],
                ["Agent", job.profile?.agent || "No coding agent"],
                ["Model", job.profile?.model_id || "Not applicable"],
                [
                  "Reasoning effort",
                  job.profile
                    ? job.profile.reasoning_effort || "Provider managed"
                    : "Not applicable",
                ],
              ]}
            />
            <p className="hint job-immutable">
              Profile and inputs are immutable. Retry reuses the recorded
              configuration.
            </p>
            {(["queued", "running", "cancelling"].includes(job.status) ||
              isProgressReported(job.progress)) && (
              <Progress value={job.progress} />
            )}
            {!!job.result && (
              <Evidence
                value={job.result}
                label="Result & retained partial outputs"
              />
            )}
          </Panel>
          {job.kind in operationNames && !!job.profile && (
            <AgentSession
              jobId={job.id}
              active={job.status === "running"}
              polling={["queued", "running", "cancelling"].includes(job.status)}
            />
          )}
          <Panel
            title="Execution events"
            description="Sanitized progress and errors recorded by the worker."
          >
            <DataState
              loading={events.loading}
              error={events.error}
              retry={events.refresh}
              hasData={!!events.data}
            >
              {events.data?.items.length ? (
                <ol className="timeline">
                  {events.data.items.map((event, i) => (
                    <ActivityEvent
                      key={typeof event.id === "string" ? event.id : i}
                      event={event}
                    />
                  ))}
                </ol>
              ) : (
                <Empty
                  title="No events yet"
                  description="Queued work reports events once a worker claims it."
                />
              )}
            </DataState>
          </Panel>
        </>
      )}
    </DataState>
  );
}
function isProgressReported(value: unknown) {
  return typeof value === "object" && value !== null && "stage" in value;
}
function Progress({ value }: { value: unknown }) {
  const text = (key: string) =>
    typeof value === "object" &&
    value &&
    key in value &&
    typeof Reflect.get(value, key) === "string"
      ? String(Reflect.get(value, key))
      : null;
  const stage = text("stage");
  const status = text("status");
  return (
    <div className="job-progress" role="status">
      <span className="field-label">Current progress</span>
      <p>
        {stage
          ? `${humanize(stage)}${status ? ` · ${status}` : ""}`
          : "No progress reported yet"}
      </p>
      <Evidence value={value} label="Progress details" />
    </div>
  );
}
