import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import { Activity, RotateCcw, Square } from "lucide-react";
import { useCollection, useQueryState, useResource } from "../hooks";
import {
  jobSchema,
  jobsSchema,
  operationNames,
  programsSchema,
  recordsSchema,
} from "../types";
import type { Job } from "../types";
import { queueJob } from "../components/JobLaunch";
import {
  ActionButton,
  Badge,
  Callout,
  countBy,
  DataState,
  describeError,
  DetailGrid,
  Empty,
  ErrorNote,
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
export function jobName(kind: string) {
  return kind in operationNames
    ? operationNames[kind as keyof typeof operationNames]
    : humanize(kind);
}
const statuses = [
  "queued",
  "running",
  "cancelling",
  "succeeded",
  "failed",
  "cancelled",
];
type JobFilters = { status: string; kind: string; program: string; q: string };
function jobError(job: Job) {
  return job.error ? describeError(job.error) || "Failed without a reason" : "";
}
function applyJobFilters(items: Job[], f: JobFilters, skip?: keyof JobFilters) {
  return items.filter(
    (job) =>
      matches(f.q, job.id, job.kind, jobName(job.kind), jobError(job)) &&
      (skip === "status" || f.status === "all" || job.status === f.status) &&
      (skip === "kind" || f.kind === "all" || job.kind === f.kind) &&
      (skip === "program" ||
        f.program === "all" ||
        (job.program_id || "none") === f.program),
  );
}
/** Group failed jobs by reason so repeated failures read as one problem. */
export function failureGroups(jobs: Job[]) {
  const groups = new Map<
    string,
    { reason: string; count: number; kinds: Set<string>; latest: string }
  >();
  for (const job of jobs) {
    if (job.status !== "failed") continue;
    const reason = jobError(job);
    const group = groups.get(reason) || {
      reason,
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
  const programs = useResource("/programs", programsSchema);
  const [filters, update] = useQueryState({
    status: "all",
    kind: "all",
    program: "all",
    q: "",
  });
  const items = useMemo(() => jobs.data?.items || [], [jobs.data]);
  const visible = useMemo(
    () => applyJobFilters(items, filters),
    [items, filters],
  );
  const { shown, footer } = useShowMore(
    visible,
    [filters.status, filters.kind, filters.program, filters.q].join("|"),
  );
  const statusCounts = countBy(
    applyJobFilters(items, filters, "status"),
    (j) => j.status,
  );
  const kindCounts = countBy(
    applyJobFilters(items, filters, "kind"),
    (j) => j.kind,
  );
  const programCounts = countBy(
    applyJobFilters(items, filters, "program"),
    (j) => j.program_id || "none",
  );
  const failures = failureGroups(applyJobFilters(items, filters, "status"));
  const programName = (id: string | null | undefined) =>
    id ? programs.data?.items.find((p) => p.id === id)?.asset_name : undefined;
  const clear = () =>
    update({ status: "all", kind: "all", program: "all", q: "" });
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
            placeholder="Search operation, error, or job ID"
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
          {(programs.data?.items.length || 0) > 0 && (
            <FilterSelect
              label="Program"
              value={filters.program}
              onChange={(program) => update({ program })}
              options={[
                { value: "all", label: "Any" },
                ...(programs.data?.items || []).map((p) => ({
                  value: p.id,
                  label: p.asset_name,
                  count: programCounts[p.id] || 0,
                })),
                {
                  value: "none",
                  label: "Installation",
                  count: programCounts.none || 0,
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
              <table>
                <thead>
                  <tr>
                    <th scope="col">Operation</th>
                    <th scope="col">Status</th>
                    <th scope="col">Profile</th>
                    <th scope="col">Submitted</th>
                    <th scope="col">Finished</th>
                    <th scope="col">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((job) => (
                    <tr key={job.id}>
                      <td>
                        <Link className="table-title" to={`/jobs/${job.id}`}>
                          {jobName(job.kind)}
                        </Link>
                        <div className="table-subtitle">
                          <span className="mono">{job.id.slice(0, 8)}</span>
                          {job.program_id && (
                            <>
                              {" · "}
                              <Link to={`/programs/${job.program_id}`}>
                                {programName(job.program_id) || "Program"}
                              </Link>
                            </>
                          )}
                        </div>
                      </td>
                      <td>
                        <Badge>{job.status}</Badge>
                        {!!job.error && (
                          <div className="table-subtitle danger-text clamp">
                            {jobError(job)}
                          </div>
                        )}
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
                        <Time value={job.created_at} />
                      </td>
                      <td>
                        {job.finished_at ? (
                          <Time value={job.finished_at} />
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td className="cell-actions">
                        <JobActions job={job} refresh={jobs.refresh} />
                      </td>
                    </tr>
                  ))}
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
      {["failed", "cancelled"].includes(job.status) && (
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
            eyebrow={`Job ${job.id.slice(0, 12)}`}
            title={jobName(job.kind)}
            description="Profile and inputs are immutable. Retry reuses the recorded configuration."
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
          {job.status === "cancelling" && (
            <Callout tone="warm" title="Cancelling">
              Cancellation was requested. The workload is still being stopped
              and reconciled; partial output will be retained.
            </Callout>
          )}
          {job.status === "cancelled" && !!job.result && (
            <Callout tone="info" title="Cancelled">
              Partial output produced before cancellation is retained below.
            </Callout>
          )}
          {!!job.error && (
            <ErrorNote>
              <strong>
                {describeError(job.error) || "The operation failed."}
              </strong>
              <Evidence value={job.error} label="Failure details" />
            </ErrorNote>
          )}
          <Panel padded>
            <DetailGrid
              items={[
                ["Status", <Badge>{job.status}</Badge>],
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
                ["Agent", job.profile?.agent || "No coding agent"],
                ["Model", job.profile?.model_id || "Not applicable"],
                [
                  "Reasoning effort",
                  job.profile
                    ? job.profile.reasoning_effort || "Provider managed"
                    : "Not applicable",
                ],
                [
                  "Program",
                  job.program_id ? (
                    <Link to={`/programs/${job.program_id}`}>
                      Program details
                    </Link>
                  ) : (
                    "Installation operation"
                  ),
                ],
              ]}
            />
            <Progress value={job.progress} />
            {!!job.result && (
              <Evidence
                value={job.result}
                label="Result & retained partial outputs"
              />
            )}
          </Panel>
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
