import { Link } from "react-router-dom";
import {
  ArrowRight,
  FileSearch,
  GitCommitHorizontal,
  Plus,
  Radar,
  ShieldAlert,
  Target,
} from "lucide-react";
import { useResource } from "../hooks";
import {
  dashboardSchema,
  applicationSchema,
  applicationState,
  applicationsSchema,
  failingRepositories,
} from "../types";
import {
  Badge,
  Callout,
  DataState,
  describeError,
  Empty,
  Evidence,
  JobLink,
  PageHeading,
  Panel,
  Time,
} from "../components/ui";
export function Dashboard() {
  const dashboard = useResource("/dashboard", dashboardSchema, 30000);
  const applications = useResource("/applications", applicationsSchema);
  const data = dashboard.data;
  const failing = applications.data?.items.filter(
    (p) => failingRepositories(p).length && !p.archived,
  );
  const due = (data?.due_applications || []).flatMap((value) => {
    const parsed = applicationSchema.safeParse(value);
    return parsed.success ? [parsed.data] : [];
  });
  return (
    <>
      <PageHeading
        eyebrow="Security workspace"
        title="Dashboard"
        description="Assets, upstream changes, and evidence that need your attention."
        actions={
          <Link className="primary button" to="/applications/new">
            <Plus size={16} aria-hidden="true" />
            Insert application
          </Link>
        }
      />
      <DataState
        loading={dashboard.loading}
        error={dashboard.error}
        retry={dashboard.refresh}
        hasData={!!data}
      >
        {data && (
          <>
            <div className="metrics-grid">
              {[
                {
                  label: "Monitored applications",
                  value: data.applications,
                  icon: Radar,
                  to: "/applications",
                  foot: failing?.length
                    ? `${failing.length} with a failed check`
                    : "Asset / software pairs",
                  attention: !!failing?.length,
                },
                {
                  label: "Security reviews",
                  value: data.security_reviews,
                  icon: GitCommitHorizontal,
                  to: "/reviews",
                  foot: "Changes awaiting your decision",
                  attention: data.security_reviews > 0,
                },
                {
                  label: "Eligible CVEs",
                  value: data.eligible_cves,
                  icon: ShieldAlert,
                  to: "/cves",
                  foot: "Meet your score criteria",
                  attention: false,
                },
                {
                  label: "Open findings",
                  value: data.open_findings,
                  icon: Target,
                  to: "/findings",
                  foot: "Operator-confirmed findings",
                  attention: false,
                },
              ].map((item) => (
                <Link
                  className={`metric-card ${item.attention ? "attention" : ""}`}
                  key={item.label}
                  to={item.to}
                >
                  <span className="metric-label">
                    <item.icon size={16} aria-hidden="true" />
                    {item.label}
                  </span>
                  <span className="metric-number">{item.value}</span>
                  <span className="metric-foot">{item.foot}</span>
                </Link>
              ))}
            </div>
            <div className="overview-grid">
              <Panel
                title="Monitoring"
                description="Latest observed versions and source-check health"
                actions={
                  <Link className="inline-link" to="/applications">
                    All applications
                    <ArrowRight size={14} aria-hidden="true" />
                  </Link>
                }
              >
                <DataState
                  loading={applications.loading}
                  error={applications.error}
                  retry={applications.refresh}
                  hasData={!!applications.data}
                >
                  {applications.data?.items.length ? (
                    <div className="row-list">
                      {applications.data.items
                        .slice(0, 6)
                        .map((application) => (
                          <Link
                            key={application.id}
                            to={`/applications/${application.id}`}
                            className="list-row"
                          >
                            <span className="asset-monogram" aria-hidden="true">
                              {application.asset_name.slice(0, 2).toUpperCase()}
                            </span>
                            <span className="list-row-main">
                              <strong>{application.asset_name}</strong>
                              <span>
                                {application.product_name} ·{" "}
                                {application.version?.version ||
                                  (application.version?.candidates?.length
                                    ? `${application.version.candidates.length} candidate versions`
                                    : "Version unknown")}
                              </span>
                            </span>
                            <span className="list-row-end">
                              <Badge>{applicationState(application)}</Badge>
                              <small>
                                {application.last_check_at ? (
                                  <>
                                    Checked{" "}
                                    <Time value={application.last_check_at} />
                                  </>
                                ) : (
                                  "Not checked yet"
                                )}
                              </small>
                            </span>
                          </Link>
                        ))}
                    </div>
                  ) : (
                    <Empty
                      icon={Radar}
                      title="Your monitoring starts here"
                      description="Register an asset and its upstream software to begin tracking changes."
                      action={
                        <Link className="primary button" to="/applications/new">
                          <Plus size={15} aria-hidden="true" />
                          Insert your first application
                        </Link>
                      }
                    />
                  )}
                </DataState>
              </Panel>
              <Panel
                title="Needs attention"
                description="Failed work, overdue checks, and active jobs"
              >
                <div className="attention-list">
                  <Link
                    className="attention-row"
                    to="/jobs?status=failed"
                    data-tone={data.failed_jobs ? "danger" : undefined}
                  >
                    <span className="status-dot danger" aria-hidden="true" />
                    <span>Failed jobs</span>
                    <strong>{data.failed_jobs}</strong>
                  </Link>
                  <Link
                    className="attention-row"
                    to="/jobs"
                    data-tone={data.running_jobs ? "info" : undefined}
                  >
                    <span className="status-dot info" aria-hidden="true" />
                    <span>Active jobs</span>
                    <strong>{data.running_jobs}</strong>
                  </Link>
                  <div className="attention-group">
                    <span className="attention-group-label">
                      <span className="status-dot warm" aria-hidden="true" />
                      Checks due
                      <strong>{data.due_applications.length}</strong>
                    </span>
                    {due.map((application) => (
                      <Link
                        key={application.id}
                        className="attention-item"
                        to={`/applications/${application.id}`}
                      >
                        <span>{application.asset_name}</span>
                        <small>
                          {application.next_check_at ? (
                            <>
                              Due <Time value={application.next_check_at} />
                            </>
                          ) : (
                            "Never checked"
                          )}
                        </small>
                      </Link>
                    ))}
                  </div>
                  {!!failing?.length && (
                    <div className="attention-group">
                      <span className="attention-group-label">
                        <span
                          className="status-dot danger"
                          aria-hidden="true"
                        />
                        Source check errors
                        <strong>{failing.length}</strong>
                      </span>
                      {failing.map((application) => (
                        <Link
                          key={application.id}
                          className="attention-item"
                          to={`/applications/${application.id}`}
                        >
                          <span>{application.asset_name}</span>
                          <small className="clamp">
                            {describeError(
                              failingRepositories(application)[0]?.last_error,
                            ) || "Check failed"}
                          </small>
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
                {!data.failed_jobs &&
                  !data.due_applications.length &&
                  !failing?.length && (
                    <div className="panel-body">
                      <Callout tone="good">
                        No failed jobs, overdue checks, or source errors.
                      </Callout>
                    </div>
                  )}
              </Panel>
            </div>
            <Panel
              title="Review queue"
              description="Changes Analysis could not decide, waiting for your review decision"
            >
              {data.review_queue.length ? (
                <>
                  <div className="row-list">
                    {data.review_queue.map((item) => (
                      <Link
                        key={item.id}
                        to={item.link ?? `/commits/${item.id}`}
                        className="list-row"
                      >
                        <span className="list-row-main">
                          <strong>{item.title}</strong>
                          <span className="mono">
                            {item.revision.slice(0, 10)}
                          </span>
                        </span>
                        <span className="list-row-end">
                          <small>
                            <Time
                              value={item.committed_at}
                              fallback="Undated"
                            />
                          </small>
                        </span>
                      </Link>
                    ))}
                  </div>
                  {data.review_queue_count > data.review_queue.length && (
                    <p className="hint panel-body">
                      Showing the newest {data.review_queue.length} of{" "}
                      {data.review_queue_count}.
                    </p>
                  )}
                </>
              ) : (
                <Empty
                  icon={FileSearch}
                  title="The Review queue is empty"
                  description="Changes with an Insufficient context Verdict wait here for your judgement."
                />
              )}
            </Panel>
            <Panel
              title="Recent activity"
              description="Events recorded by background operations"
            >
              {data.recent_events.length ? (
                <ol className="timeline">
                  {data.recent_events.slice(0, 12).map((event, index) => (
                    <ActivityEvent key={index} event={event} />
                  ))}
                </ol>
              ) : (
                <Empty
                  title="No activity recorded yet"
                  description="Checks, reviews, and background operations will appear here as they happen."
                />
              )}
            </Panel>
          </>
        )}
      </DataState>
    </>
  );
}
function field(event: unknown, key: string) {
  if (typeof event !== "object" || !event || !(key in event)) return undefined;
  const value: unknown = Reflect.get(event, key);
  return typeof value === "string" ? value : undefined;
}
export function ActivityEvent({ event }: { event: unknown }) {
  const message = field(event, "message") || field(event, "kind") || "Event";
  const time = field(event, "created_at");
  const job = field(event, "job_id");
  const kind = `${field(event, "kind") || ""} ${message}`.toLowerCase();
  const tone = /error|fail/.test(kind)
    ? "danger"
    : /succeed|complete|verified/.test(kind)
      ? "good"
      : "neutral";
  return (
    <li className="timeline-item">
      <span className={`timeline-marker ${tone}`} aria-hidden="true" />
      <div className="timeline-body">
        <div className="timeline-title">
          <strong>{message}</strong>
          {job && <JobLink id={job} />}
        </div>
        {time && (
          <small>
            <Time value={time} absolute />
          </small>
        )}
        <Evidence value={event} label="Details" />
      </div>
    </li>
  );
}
