import { useState } from "react";
import { Link } from "react-router-dom";
import { Globe, RefreshCw } from "lucide-react";
import { z } from "zod";
import { mutate } from "../api";
import { useResource } from "../hooks";
import { userAgentLabels, watchedPageSchema, watchedPagesSchema } from "../types";
import type {
  Application,
  ServedChange,
  ServedDiff,
  ServedFetch,
  WatchedPage,
} from "../types";
import { queueJob } from "../components/JobLaunch";
import {
  ActionButton,
  Badge,
  DataState,
  DetailGrid,
  Empty,
  ErrorNote,
  humanize,
  notify,
  Panel,
  Time,
} from "../components/ui";
import { errorText } from "./ApplicationRepositories";
import { TextList } from "./Findings";

const states: Record<string, [string, string]> = {
  awaiting_baseline: ["No Baseline yet", "warm"],
  matches: ["Matches the Baseline", "good"],
  changed: ["Changed", "danger"],
  failed: ["Fetch failed", "danger"],
};
const diffLabels: Record<string, string> = {
  script_hosts: "External script hosts",
  scripts: "Scripts",
  inline_scripts: "Inline scripts",
  links: "Links",
  link_hosts: "Link hosts",
  words: "Words",
};
const SHOWN = 20; // values listed per diff entry; a page's words can run to thousands
/** A user agent's latest fetch: its fingerprint and time, or why it failed. */
function Latest({ fetch }: { fetch: ServedFetch | null }) {
  if (!fetch) return <span className="muted">Not checked yet</span>;
  if (fetch.status === "failed")
    return (
      <>
        {fetch.error?.status
          ? `HTTP ${fetch.error.status}`
          : fetch.error?.error || "No answer"}
        <span className="table-subtitle">
          <Time value={fetch.created_at} />
        </span>
      </>
    );
  return (
    <>
      <span className="mono">{fetch.fingerprint?.slice(0, 12)}</span>
      <span className="table-subtitle">
        <Time value={fetch.created_at} />
      </span>
    </>
  );
}
/** The diff from the Baseline as lists of text, such as "Links added". */
function Diff({ diff }: { diff: ServedDiff | null }) {
  const entries = Object.entries(diff || {}).flatMap(([key, change]) =>
    (["added", "removed"] as const)
      .filter((side) => change[side].length)
      .map((side) => [`${diffLabels[key] || humanize(key)} ${side}`, change[side]] as const),
  );
  if (!entries.length) return <span className="muted">None</span>;
  return (
    <DetailGrid
      items={entries.map(([label, values]) => [
        label,
        <TextList
          items={
            values.length > SHOWN
              ? [...values.slice(0, SHOWN), `and ${values.length - SHOWN} more`]
              : values
          }
        />,
      ])}
    />
  );
}
/** Where a served-content change stands: its Triage, Analysis, Verdict, Review queue and Finding,
 * with a manual Analysis and, for a change in the Review queue, its dismissal. */
function Change({
  change,
  refresh,
}: {
  change: ServedChange | null;
  refresh: () => void;
}) {
  if (!change) return <span className="muted">None</span>;
  const queued =
    change.verdict === "Insufficient context" &&
    change.review_decision === "pending";
  const { decision, reason } = change.triage_result || {};
  const triage =
    change.triage_status === "completed" && typeof decision === "string"
      ? humanize(decision)
      : change.triage_status === "disabled"
        ? "Off"
        : humanize(change.triage_status) +
          (typeof reason === "string" ? `: ${reason}` : "");
  return (
    <>
      <DetailGrid
        items={[
          ["Triage", triage],
          ["Analysis", humanize(change.analysis_state?.status || "none")],
          ["Verdict", change.verdict || "None yet"],
          [
            "Review queue",
            change.verdict !== "Insufficient context"
              ? "Not queued"
              : queued
                ? "Waiting for your review"
                : `Reviewed: ${humanize(change.review_decision)}`,
          ],
        ]}
      />
      <span className="inline-actions">
        {queued && (
          <ActionButton
            className="secondary"
            onAction={async () => {
              await mutate(`/served-changes/${change.id}/review`, z.unknown(), {
                decision: "dismissed",
              });
              notify("Served-content change dismissed.");
              refresh();
            }}
          >
            Dismiss
          </ActionButton>
        )}
        {change.analysis_state?.status !== "queued" && (
          <ActionButton
            className="secondary"
            onAction={async () => {
              await queueJob(
                `/served-changes/${change.id}/analyses`,
                {},
                undefined,
                "Served-content Analysis queued.",
              );
              refresh();
            }}
          >
            Run Analysis
          </ActionButton>
        )}
        {change.finding_id && (
          <Link className="inline-link" to={`/findings/${change.finding_id}`}>
            Open Finding
          </Link>
        )}
      </span>
    </>
  );
}
function AddPage({
  application,
  refresh,
}: {
  application: Application;
  refresh: () => void;
}) {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(undefined);
        try {
          await mutate(
            `/applications/${application.id}/watched-pages`,
            watchedPageSchema,
            { url: url.trim() },
          );
          notify("Watched page added. The next Served-content check fetches it.");
          setUrl("");
          refresh();
        } catch (err) {
          setError(errorText(err));
        } finally {
          setBusy(false);
        }
      }}
    >
      <label>
        Page URL
        <input
          required
          value={url}
          aria-invalid={!!error}
          placeholder={application.asset_url}
          onChange={(e) => setUrl(e.target.value)}
        />
      </label>
      {error && <ErrorNote>{error}</ErrorNote>}
      <div className="form-actions">
        <button className="primary" disabled={busy}>
          Add Watched page
        </button>
      </div>
    </form>
  );
}
/** The Served content tab (A10): each Watched page's latest Content fingerprint per user agent, its
 * Baseline, the diff from it and the change it recorded. Everything fetched is shown as text: no
 * fetched page is ever rendered. */
export function ApplicationServedContent({
  application,
}: {
  application: Application;
}) {
  const base = `/applications/${application.id}`;
  const resource = useResource(
    `${base}/watched-pages`,
    watchedPagesSchema,
    30000,
  );
  const pages = resource.data?.items || [];
  const remove = async (page: WatchedPage) => {
    await mutate(`${base}/watched-pages/${page.id}`, watchedPageSchema, {}, "DELETE");
    notify("Watched page removed. Its fetches are kept.");
    resource.refresh();
  };
  return (
    <div className="column-stack">
      <Panel
        title="Served content"
        description="On the Application's interval and when you ask, a Served-content check fetches each Watched page and the scripts it links to, once as a browser and once as Googlebot, without running them. Each fetch's Content fingerprint is compared with the Baseline you accepted; a changed fingerprint goes through Triage and Analysis."
        actions={
          <ActionButton
            className="secondary"
            onAction={async () => {
              await queueJob(
                `${base}/served-content-checks`,
                {},
                undefined,
                "Served-content check queued.",
              );
              resource.refresh();
            }}
          >
            <RefreshCw size={15} aria-hidden="true" />
            Check now
          </ActionButton>
        }
        padded
      >
        <AddPage application={application} refresh={resource.refresh} />
      </Panel>
      <DataState
        loading={resource.loading}
        error={resource.error}
        retry={resource.refresh}
        hasData={!!resource.data}
      >
        <Panel
          title="Watched pages"
          description="The homepage is always watched. You can accept a fetch's fingerprint as the Baseline when there is none yet, or after a Security hardening or Unrelated Verdict on it, or after Triage declined it or you dismissed it from the Review queue. Accepting is not an Approval."
        >
          {pages.length ? (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Watched page</th>
                    <th scope="col">User agent</th>
                    <th scope="col">Latest fetch</th>
                    <th scope="col">Baseline</th>
                    <th scope="col">Diff from the Baseline</th>
                    <th scope="col">Served-content change</th>
                  </tr>
                </thead>
                <tbody>
                  {pages.flatMap((page) =>
                    page.user_agents.map((row) => {
                      const [label, tone] = states[row.state];
                      const latest = row.latest;
                      return (
                        <tr key={`${page.id}:${row.user_agent}`}>
                          <td>
                            <span className="mono">{page.url}</span>
                            <span className="table-subtitle">
                              {page.homepage ? (
                                <Badge tone="neutral">Homepage</Badge>
                              ) : (
                                <ActionButton
                                  className="secondary"
                                  confirm="Confirm remove"
                                  onAction={() => remove(page)}
                                >
                                  Remove
                                </ActionButton>
                              )}
                            </span>
                          </td>
                          <td>
                            {userAgentLabels[row.user_agent] ||
                              humanize(row.user_agent)}
                          </td>
                          <td>
                            <Latest fetch={latest} />
                          </td>
                          <td>
                            <Badge tone={tone}>{label}</Badge>
                            {row.baseline && (
                              <span className="table-subtitle mono">
                                Baseline {row.baseline.fingerprint.slice(0, 12)}
                              </span>
                            )}
                            {row.accept_allowed && latest && (
                              <ActionButton
                                className="secondary"
                                onAction={async () => {
                                  await mutate(
                                    `${base}/watched-pages/${page.id}/baselines`,
                                    watchedPageSchema,
                                    { fetch_id: latest.id },
                                  );
                                  notify("Baseline accepted.");
                                  resource.refresh();
                                }}
                              >
                                Accept Baseline
                              </ActionButton>
                            )}
                          </td>
                          <td>
                            <Diff diff={row.diff} />
                          </td>
                          <td>
                            <Change
                              change={row.change}
                              refresh={resource.refresh}
                            />
                          </td>
                        </tr>
                      );
                    }),
                  )}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={Globe}
              title="No Watched pages"
              description="The homepage appears here once the Application has an Asset URL."
            />
          )}
        </Panel>
      </DataState>
    </div>
  );
}
