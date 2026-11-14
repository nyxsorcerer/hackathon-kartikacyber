import { useState } from "react";
import type { ReactNode } from "react";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import {
  Download,
  FlaskConical,
  GitPullRequest,
  PencilLine,
  Trash2,
  Plus,
  Save,
  Sparkles,
  Target,
  Upload,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { z } from "zod";
import { mutate, request } from "../api";
import { useResource } from "../hooks";
import {
  detectionChecks,
  exposureLabels,
  exposureTones,
  findingDeletionSchema,
  findingSchema,
  findingSummariesSchema,
  applicationSchema,
  applicationsSchema,
} from "../types";
import type {
  AdvisoryRanges,
  Finding,
  Application,
  CleanupReport,
  RemediationPR,
  StaticProof,
} from "../types";
import { versionLabels } from "../versions";
import { JobLaunch, queueJob } from "../components/JobLaunch";
import { ArtifactBrowser } from "../components/ArtifactPreview";
import {
  ActionButton,
  announceChange,
  Badge,
  Callout,
  CopyButton,
  DataState,
  describeError,
  DetailGrid,
  DiffView,
  Empty,
  ErrorNote,
  Evidence,
  ExternalLink,
  humanize,
  JobLink,
  Modal,
  notify,
  PageHeading,
  Panel,
  Pagination,
  Time,
} from "../components/ui";
function labState(status: unknown) {
  if (typeof status !== "string")
    return { label: "Lab unverified", tone: "neutral" };
  return status === "verified"
    ? { label: "Lab verified", tone: "good" }
    : {
        label: `Lab ${status.replaceAll("_", " ")}`,
        tone: status === "failed" ? "danger" : "warm",
      };
}
const sourceLabels: Record<Finding["source"], string> = {
  commit: "Commit",
  served_content: "Served content",
  advisory: "Advisory",
  cve: "CVE",
};
/** What opened the Finding: 'Commit abc1234', 'CVE-…', 'Advisory GHSA-…' or 'Watched page /path'. */
function sourceLabel(finding: Pick<Finding, "source" | "source_ref">) {
  const ref = finding.source_ref;
  if (!ref) return sourceLabels[finding.source];
  if (finding.source === "cve") return ref;
  return `${finding.source === "served_content" ? "Watched page" : sourceLabels[finding.source]} ${ref}`;
}
const causeLabels: Record<string, string> = {
  proof: "Reproduced Proof",
  detection_rule: "Validated Detection rule",
  advisory: "Advisory check",
  cve_analysis: "CVE analysis",
  remediation_pr: "Merged Remediation PR",
  version_bump: "Version bump",
  baseline_match: "Served content matches the Baseline",
  deployed_version: "Deployed version serves the fix",
  numen: "Carried over from Numen",
};
/** What the Deployed version check reports (A06): never a guess. */
const deployedLabels: Record<string, string> = {
  before_fix: "Still serving code from before the fix",
  serving_fix: "Serving the fix",
  unknown: "Unknown",
};
const deployedTones: Record<string, string> = {
  before_fix: "danger",
  serving_fix: "good",
};
/** A string field of a stored record, such as a cause or a history event. */
function text(record: unknown, key: string) {
  const value: unknown =
    record && typeof record === "object" ? Reflect.get(record, key) : undefined;
  return typeof value === "string" ? value : undefined;
}
/** Who or what set a Finding's state (A11). */
function causeLabel(cause: unknown) {
  const field = (key: string) => text(cause, key);
  const by = field("by") || "";
  if (by === "verdict")
    return `${field("verdict")} Verdict, ${field("confidence") || "unknown"} confidence`;
  if (by === "operator")
    return field("reason") ? `Operator: ${field("reason")}` : "Operator";
  return causeLabels[by] || (by ? humanize(by) : "Unknown");
}
/** The Operator's lifecycle actions and the states each can leave (A11). */
const transitions = [
  { state: "confirmed", label: "Confirm", from: ["open"] },
  { state: "dismissed", label: "Dismiss", from: ["open"] },
  {
    state: "remediated",
    label: "Mark remediated",
    from: ["open", "confirmed"],
  },
];
export function Findings() {
  return (
    <>
      <PageHeading
        eyebrow="Finding register"
        title="Findings"
        description="Open, Confirmed, Dismissed and Remediated Findings, their causes, and the Deployed version."
        actions={
          <Link className="primary button" to="/findings/new">
            <Plus size={16} aria-hidden="true" />
            Create finding
          </Link>
        }
      />
      <FindingsList />
    </>
  );
}
function findingCount(n: number) {
  return `${n} ${n === 1 ? "finding" : "findings"}`;
}
const noSelection = new Set<string>();
export function FindingsList({ application }: { application?: Application }) {
  const [cursor, setCursor] = useState("");
  const params = new URLSearchParams({ view: "summary" });
  if (application) params.set("application_id", application.id);
  if (cursor) params.set("cursor", cursor);
  const resource = useResource(
    `/findings${params.size ? `?${params}` : ""}`,
    findingSummariesSchema,
    0,
    true,
  );
  const items = resource.data?.items || [];
  // A selection belongs to one page, so a deletion never reaches a finding the
  // operator cannot see.
  const [selection, setSelection] = useState({ key: cursor, ids: noSelection });
  const selectedIds = selection.key === cursor ? selection.ids : noSelection;
  const selected = items.filter((f) => selectedIds.has(f.id));
  const allSelected = items.length > 0 && selected.length === items.length;
  const select = (ids: Set<string>) => setSelection({ key: cursor, ids });
  const remove = async () => {
    const { deleted } = await mutate(
      "/findings/delete",
      findingDeletionSchema,
      { ids: selected.map((f) => f.id) },
    );
    notify(`Deleted ${findingCount(deleted.length)}.`);
    select(noSelection);
    announceChange();
    // An emptied later page has nothing left to show; start from the first.
    if (cursor && deleted.length === items.length) setCursor("");
    else resource.refresh();
  };
  return (
    <Panel
      title="Finding register"
      description="Upstream remediation and target exposure are tracked independently."
      actions={
        application && (
          <Link
            className="secondary button"
            to={`/findings/new?application_id=${application.id}`}
          >
            <Plus size={14} aria-hidden="true" />
            Create finding
          </Link>
        )
      }
    >
      <DataState
        loading={resource.loading}
        error={resource.error}
        retry={resource.refresh}
        hasData={!!resource.data}
      >
        {items.length > 0 &&
          (selected.length ? (
            <div className="queue-bar batch">
              <span className="queue-bar-count" role="status">
                <strong>{selected.length}</strong> selected
              </span>
              <div className="queue-bar-actions">
                <ActionButton
                  className="danger-button"
                  confirm={`Delete ${findingCount(selected.length)} permanently?`}
                  title="Remove the selected findings, their bundles and lab runs. The analyses that created them are kept."
                  onAction={remove}
                >
                  <Trash2 size={15} aria-hidden="true" />
                  Delete {findingCount(selected.length)}
                </ActionButton>
              </div>
              <button
                type="button"
                className="text-button queue-bar-clear"
                onClick={() => select(noSelection)}
              >
                Clear selection
              </button>
            </div>
          ) : (
            <div className="queue-bar">
              <span>
                {findingCount(items.length)}
                {cursor || resource.data?.next_cursor ? " on this page" : ""}
              </span>
              <span className="hint queue-bar-hint">
                Select findings to delete them together.
              </span>
            </div>
          ))}
        {items.length ? (
          <div className="table-scroll">
            <table className="finding-table">
              <thead>
                <tr>
                  <th scope="col" className="select-cell">
                    <label className="select-hit">
                      <input
                        type="checkbox"
                        aria-label="Select all findings on this page"
                        checked={allSelected}
                        ref={(el) => {
                          if (el)
                            el.indeterminate =
                              selected.length > 0 && !allSelected;
                        }}
                        onChange={() =>
                          select(
                            allSelected
                              ? noSelection
                              : new Set(items.map((f) => f.id)),
                          )
                        }
                      />
                    </label>
                  </th>
                  <th scope="col">Finding</th>
                  <th scope="col">State</th>
                  <th scope="col">Upstream fixed in</th>
                  <th scope="col">Target exposure</th>
                  <th scope="col">Artifacts</th>
                  <th scope="col">Updated</th>
                </tr>
              </thead>
              <tbody>
                {items.map((finding) => {
                  const lab = labState(finding.lab_status);
                  const isSelected = selectedIds.has(finding.id);
                  return (
                    <tr
                      key={finding.id}
                      className={isSelected ? "is-selected" : undefined}
                    >
                      <td className="select-cell">
                        <label className="select-hit">
                          <input
                            type="checkbox"
                            aria-label={`Select ${finding.title}`}
                            checked={isSelected}
                            onChange={(e) => {
                              const next = new Set(selectedIds);
                              if (e.target.checked) next.add(finding.id);
                              else next.delete(finding.id);
                              select(next);
                            }}
                          />
                        </label>
                      </td>
                      <td>
                        <Link
                          className="table-title"
                          to={`/findings/${finding.id}`}
                        >
                          {finding.title}
                        </Link>
                        <div className="table-subtitle mono">
                          {sourceLabel(finding)}
                        </div>
                      </td>
                      <td>
                        <Badge>{finding.status}</Badge>
                        <div className="table-subtitle">
                          {causeLabel(finding.cause)}
                        </div>
                      </td>
                      <td>
                        {versionLabels(finding.fixed_versions).join(", ") || (
                          <span className="muted">Unknown</span>
                        )}
                      </td>
                      <td>
                        <Badge>{finding.target_applicability}</Badge>
                      </td>
                      <td>
                        <Badge>{finding.artifact_state.status}</Badge>
                        <div className="table-subtitle">
                          {/* A Malicious change never runs: no Lab (ADR-0004). Nor does an Advisory check match (A06). */}
                          {finding.malicious_change ? (
                            <Badge>Static Proof</Badge>
                          ) : (
                            finding.source !== "advisory" && (
                              <Badge tone={lab.tone}>{lab.label}</Badge>
                            )
                          )}
                        </div>
                      </td>
                      <td>
                        <Time value={finding.updated_at} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            icon={Target}
            title="No findings recorded"
            description="Create a finding from an analysis result, or enter an independently confirmed result."
            action={
              <Link
                className="secondary button"
                to={`/findings/new${application ? `?application_id=${application.id}` : ""}`}
              >
                <Plus size={15} aria-hidden="true" />
                Create finding
              </Link>
            }
          />
        )}
        <Pagination
          next={resource.data?.next_cursor}
          showFirst={!!cursor}
          onNext={setCursor}
          onFirst={() => setCursor("")}
        />
      </DataState>
    </Panel>
  );
}
export function FindingForm() {
  const { id } = useParams();
  if (id) return <EditFinding id={id} />;
  return <FindingEditor />;
}
function EditFinding({ id }: { id: string }) {
  const resource = useResource(`/findings/${id}`, findingSchema);
  return (
    <DataState
      loading={resource.loading}
      error={resource.error}
      retry={resource.refresh}
    >
      {resource.data && (
        <FindingEditor key={resource.data.id} finding={resource.data} />
      )}
    </DataState>
  );
}
function FindingEditor({ finding }: { finding?: Finding }) {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const applications = useResource("/applications", applicationsSchema);
  const [applicationId, setApplicationId] = useState(
    finding?.application_id || params.get("application_id") || "",
  );
  const [source, setSource] = useState<Finding["source"]>(
    finding?.source || (params.has("cve_id") ? "cve" : "commit"),
  );
  const [cveId, setCveId] = useState(
    finding?.cve_id || params.get("cve_id") || "",
  );
  const [title, setTitle] = useState(
    finding?.title || params.get("title") || "",
  );
  const initialAffected = versionLabels(finding?.affected_versions).join("\n");
  const initialFixed = versionLabels(finding?.fixed_versions).join("\n");
  const [affected, setAffected] = useState(initialAffected);
  const [fixed, setFixed] = useState(initialFixed);
  const [target, setTarget] = useState(
    finding?.target_applicability || "unknown",
  );
  const [evidence, setEvidence] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  return (
    <>
      <PageHeading
        back={{
          to: finding ? `/findings/${finding.id}` : "/findings",
          label: finding ? "Back to finding" : "All findings",
        }}
        eyebrow="Finding register"
        title={finding ? "Edit finding" : "Create finding"}
        description="A finding records an operator judgment. Artifacts and lab verification follow separately."
      />
      <form
        className="narrow-form"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            const saved = await mutate(
              finding ? `/findings/${finding.id}` : "/findings",
              findingSchema,
              {
                application_id: applicationId,
                source,
                cve_id: cveId || null,
                title,
                affected_versions:
                  finding && affected === initialAffected
                    ? finding.affected_versions
                    : affected.split("\n").filter(Boolean),
                fixed_versions:
                  finding && fixed === initialFixed
                    ? finding.fixed_versions
                    : fixed.split("\n").filter(Boolean),
                target_applicability: target,
                source_commit_id:
                  finding?.source_commit_id || params.get("source_commit_id"),
                source_analysis_id:
                  finding?.source_analysis_id ||
                  params.get("source_analysis_id"),
                ...(evidence
                  ? { evidence: [...(finding?.evidence || []), evidence] }
                  : {}),
              },
              finding ? "PATCH" : "POST",
            );
            notify(finding ? "Finding updated." : "Finding created.");
            navigate(`/findings/${saved.id}`);
          } catch (err) {
            setError(
              err instanceof Error ? err.message : "Could not save finding.",
            );
          } finally {
            setBusy(false);
          }
        }}
      >
        <Panel title="Finding identity">
          <div className="form-grid">
            <label className="full">
              Application
              <select
                required
                value={applicationId}
                onChange={(e) => setApplicationId(e.target.value)}
              >
                <option value="">Select an application</option>
                {applications.data?.items.map((p) => (
                  <option value={p.id} key={p.id}>
                    {p.asset_name} · {p.product_name}
                  </option>
                ))}
              </select>
              {applications.error && (
                <span className="field-error">{applications.error}</span>
              )}
            </label>
            <label>
              Source
              <select
                value={source}
                disabled={!!finding}
                onChange={(e) => {
                  if (e.target.value === "cve" || e.target.value === "commit")
                    setSource(e.target.value);
                }}
              >
                {(finding
                  ? [finding.source]
                  : (["commit", "cve"] as Finding["source"][])
                ).map((value) => (
                  <option value={value} key={value}>
                    {sourceLabels[value]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              {source === "cve"
                ? "CVE identifier"
                : "CVE identifier (optional)"}
              <input
                required={source === "cve"}
                value={cveId}
                pattern="CVE-[0-9]{4}-[0-9]{4,}"
                onChange={(e) => setCveId(e.target.value)}
                placeholder="CVE-2026-12345"
              />
              <span className="hint">
                A later CVE link preserves the original local identity.
              </span>
            </label>
            <label className="full">
              Title
              <input
                required
                maxLength={300}
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Describe the affected behavior"
              />
            </label>
            <label>
              Remote target exposure
              <select
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              >
                <option value="unknown">Unknown</option>
                <option value="affected">Affected</option>
                <option value="not affected">Not affected</option>
              </select>
            </label>
            <label>
              Affected versions (one per line)
              <textarea
                value={affected}
                onChange={(e) => setAffected(e.target.value)}
              />
            </label>
            <label>
              Upstream fixed versions (one per line)
              <textarea
                value={fixed}
                onChange={(e) => setFixed(e.target.value)}
              />
            </label>
            <label className="full">
              Additional evidence / operator notes
              <textarea
                value={evidence}
                onChange={(e) => setEvidence(e.target.value)}
                placeholder="Source references, reproduction evidence, or deployment confirmation"
              />
            </label>
          </div>
        </Panel>
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <Link
            className="secondary button"
            to={finding ? `/findings/${finding.id}` : "/findings"}
          >
            Cancel
          </Link>
          <button className="primary" disabled={busy || applications.loading}>
            <Save size={15} />
            {busy ? "Saving…" : "Save finding"}
          </button>
        </div>
      </form>
    </>
  );
}
export function FindingDetail() {
  const { id } = useParams();
  const resource = useResource(
    `/findings/${encodeURIComponent(id || "")}`,
    findingSchema,
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
        <FindingBody finding={resource.data} refresh={resource.refresh} />
      )}
    </DataState>
  );
}
function FindingBody({
  finding,
  refresh,
}: {
  finding: Finding;
  refresh: () => void;
}) {
  const [generate, setGenerate] = useState(false);
  const [upload, setUpload] = useState(false);
  const [approve, setApprove] = useState(false);
  const navigate = useNavigate();
  const application = useResource(
    `/applications/${finding.application_id}`,
    applicationSchema,
  );
  const complete = finding.artifact_state.status === "complete";
  // A Malicious change never runs (ADR-0004): its Proof is static, with no Lab. Nor does an
  // Own-repository Vulnerability fix: its Playbook cell has no Proof step (A06).
  const malicious = finding.malicious_change;
  const labbed =
    !malicious &&
    (!finding.playbook.length ||
      finding.playbook.some((step) => step.step === "proof"));
  const exposure = finding.exposure;
  const exposureRows: [string, ReactNode][] = exposure
    ? [
        [
          "Exposure",
          <>
            <Badge tone={exposureTones[exposure.state]}>
              {exposureLabels[exposure.state]}
            </Badge>{" "}
            {exposure.reason}
          </>,
        ],
        [
          "Locked version",
          exposure.locked_version ? (
            `${exposure.locked_version}${exposure.tag ? ` (tag ${exposure.tag})` : ""}`
          ) : (
            <span className="muted">None</span>
          ),
        ],
      ]
    : [];
  const observed = application.data?.version;
  const lab = labState(finding.lab_runs[0]?.status);
  return (
    <>
      <PageHeading
        back={{ to: "/findings", label: "All findings" }}
        eyebrow={sourceLabel(finding)}
        title={finding.title}
        description={
          application.data && (
            <Link to={`/applications/${finding.application_id}?tab=findings`}>
              {application.data.asset_name} · {application.data.product_name}
            </Link>
          )
        }
        actions={
          <>
            <Link
              className="secondary button"
              to={`/findings/${finding.id}/edit`}
            >
              <PencilLine size={15} aria-hidden="true" />
              Edit finding
            </Link>
            <ActionButton
              className="danger-button"
              confirm="Delete permanently?"
              title="Remove this finding, its bundle and lab runs. The analysis that created it is kept."
              onAction={async () => {
                await mutate(
                  `/findings/${finding.id}`,
                  z.unknown(),
                  {},
                  "DELETE",
                );
                // A false positive usually came from a commit; return there to dismiss it.
                if (finding.source_commit_id) {
                  notify(
                    "Finding deleted. You can dismiss the revision that produced it here.",
                  );
                  navigate(`/commits/${finding.source_commit_id}`);
                } else {
                  notify("Finding deleted.");
                  navigate("/findings");
                }
              }}
            >
              <Trash2 size={15} aria-hidden="true" />
              Delete finding
            </ActionButton>
            {/* An Upstream Proof is never exported (A15). */}
            {finding.exportable && finding.artifacts.length > 0 && (
              <a
                className={`${complete ? "primary" : "secondary"} button`}
                download
                href={`/api/findings/${finding.id}/download`}
              >
                <Download size={15} aria-hidden="true" />
                {complete ? "Download bundle" : "Download draft bundle"}
              </a>
            )}
          </>
        }
        meta={
          <>
            <Badge>{sourceLabels[finding.source]}</Badge>
            <Badge>{finding.status}</Badge>
            <span>
              Exposure <Badge>{finding.target_applicability}</Badge>
            </span>
            <span>
              Artifacts <Badge>{finding.artifact_state.status}</Badge>
            </span>
            {labbed && <Badge tone={lab.tone}>{lab.label}</Badge>}
          </>
        }
      />
      {/* Only a Lab or static Proof needs the bundle: an advisory Finding never offers a Lab. */}
      {finding.artifact_state.missing.length > 0 && (labbed || malicious) && (
        <Callout
          tone="warm"
          title="Draft bundle"
          action={
            <button className="secondary" onClick={() => setUpload(true)}>
              <Upload size={14} aria-hidden="true" />
              Upload missing files
            </button>
          }
        >
          Missing: {finding.artifact_state.missing.join(", ")}.{" "}
          {malicious
            ? "The static Proof is complete once its Detection rule validates."
            : labbed
              ? "Lab verification is available once the bundle is complete."
              : ""}
        </Callout>
      )}
      <Lifecycle finding={finding} refresh={refresh} />
      {finding.playbook.length > 0 && (
        <PlaybookPanel steps={finding.playbook} />
      )}
      {finding.advisories.map((advisory) => (
        <AdvisoryPanel
          key={advisory.id}
          advisory={advisory}
          finding={finding}
        />
      ))}
      <div className="detail-columns even">
        <Panel
          title="Upstream remediation"
          description="What the upstream project changed"
          padded
        >
          <DetailGrid
            items={[
              [
                "Fixed in",
                versionLabels(finding.fixed_versions).join(", ") || (
                  <span className="muted">Unknown</span>
                ),
              ],
              [
                "Affected versions",
                versionLabels(finding.affected_versions).join(", ") || (
                  <span className="muted">Unknown</span>
                ),
              ],
              ["Linked CVE", finding.cve_id || "Not linked"],
              [
                "Source commit",
                finding.source_commit_id ? (
                  <Link to={`/commits/${finding.source_commit_id}`}>
                    View commit
                  </Link>
                ) : (
                  "Not linked"
                ),
              ],
            ]}
          />
        </Panel>
        <Panel
          title="Remote target exposure"
          description="What is known about the deployed asset"
          padded
        >
          <DetailGrid
            items={[
              [
                "Target exposure",
                <Badge>{finding.target_applicability}</Badge>,
              ],
              ...exposureRows,
              [
                "Observed version",
                observed ? (
                  <>
                    {observed.version ||
                      observed.candidates?.join(" / ") ||
                      "Unknown"}{" "}
                    <span className="muted">
                      · <Time value={observed.checked_at} />
                    </span>
                  </>
                ) : (
                  <span className="muted">Not observed</span>
                ),
              ],
              [
                "Deployed version",
                <>
                  <Badge tone={deployedTones[finding.deployed_version]}>
                    {deployedLabels[finding.deployed_version] ||
                      humanize(finding.deployed_version)}
                  </Badge>{" "}
                  {finding.deployed_version_check?.reason}
                </>,
              ],
              [
                "Vulnerable lab version",
                finding.artifact_state.vulnerable_version || (
                  <span className="muted">Not declared</span>
                ),
              ],
            ]}
          />
          <p className="hint">
            A fix in the repository does not mean the Asset serves it.
          </p>
        </Panel>
      </div>
      <Panel title="Identity & evidence" padded>
        <DetailGrid
          items={[
            [
              "Local identity",
              <span className="with-copy">
                <span className="mono">{finding.id.slice(0, 18)}…</span>
                <CopyButton value={finding.id} label="Copy local identity" />
              </span>,
            ],
            ["Source", sourceLabels[finding.source]],
            ["Created", <Time value={finding.created_at} absolute />],
            ["Updated", <Time value={finding.updated_at} absolute />],
          ]}
        />
        <div className="field-block">
          <span className="field-label">Supporting evidence</span>
          {finding.evidence.length ? (
            finding.evidence.map((entry, index) =>
              typeof entry === "string" ? (
                <p key={index} className="readable-copy evidence-note">
                  {entry}
                </p>
              ) : (
                <Evidence
                  key={index}
                  value={entry}
                  label={`Evidence ${index + 1}`}
                />
              ),
            )
          ) : (
            <p className="muted">
              No notes yet. Edit the finding to record observations or source
              references.
            </p>
          )}
        </div>
        {finding.artifact_state.limitations.length > 0 && (
          <Evidence
            value={finding.artifact_state.limitations}
            label="Reproduction limitations"
          />
        )}
      </Panel>
      {finding.events?.length ? (
        <Panel
          title="History"
          description="When the Finding opened, the changes linked to it and each change of state."
        >
          <ol className="timeline">
            {finding.events.map((event, index) => (
              <HistoryEvent
                key={text(event, "id") || index}
                event={event}
                finding={finding}
              />
            ))}
          </ol>
        </Panel>
      ) : null}
      {finding.disclosure_report && (
        <DisclosureReportPanel report={finding.disclosure_report} />
      )}
      {finding.static_proof && (
        <StaticProofPanel proof={finding.static_proof} />
      )}
      {finding.cleanup_report && (
        <CleanupReportPanel
          report={finding.cleanup_report}
          proof={finding.static_proof}
        />
      )}
      <Panel
        title="Reproducible artifacts"
        description={
          malicious
            ? "Report, Detection rule and indicators."
            : "Report, Python PoC, and the pinned vulnerable application."
        }
        actions={
          <>
            <button className="secondary" onClick={() => setUpload(true)}>
              <Upload size={15} aria-hidden="true" />
              Upload
            </button>
            {!malicious && (
              <button className="secondary" onClick={() => setGenerate(true)}>
                <Sparkles size={15} aria-hidden="true" />
                Generate
              </button>
            )}
          </>
        }
      >
        {finding.artifacts.length ? (
          <ArtifactBrowser
            key={finding.artifact_revision}
            artifacts={finding.artifacts}
            exportable={finding.exportable}
            grouped
          />
        ) : (
          <Empty
            title="No artifacts yet"
            description={
              malicious
                ? "Analyse the commit again, or upload a report and a Detection rule."
                : "Upload files or request generation to prepare the report, PoC, and vulnerable application."
            }
          />
        )}
      </Panel>
      {labbed && (
        <Panel
          title="Lab"
          description="Builds the vulnerable application and runs this Proof in a disposable Lab, only after your Approval."
          actions={
            <button
              className="primary"
              disabled={!complete}
              title={complete ? undefined : "Complete the bundle first"}
              onClick={() => setApprove(true)}
            >
              <FlaskConical size={15} aria-hidden="true" />
              Start Lab
            </button>
          }
        >
          {finding.lab_runs.length ? (
            <div className="row-list">
              {finding.lab_runs.map((run, i) => (
                <article
                  className="lab-run"
                  key={typeof run.id === "string" ? run.id : i}
                >
                  <div className="analysis-header">
                    <Badge>
                      {typeof run.status === "string" ? run.status : "Recorded"}
                    </Badge>
                    {typeof run.pinned_version === "string" && (
                      <span className="muted">
                        Pinned version {run.pinned_version}
                      </span>
                    )}
                    <span className="analysis-time">
                      {typeof run.created_at === "string" && (
                        <Time value={run.created_at} absolute />
                      )}
                    </span>
                    {typeof run.job_id === "string" && (
                      <JobLink id={run.job_id} />
                    )}
                  </div>
                  <Evidence
                    value={run}
                    label="Pinned version, prerequisites & captured logs"
                  />
                </article>
              ))}
            </div>
          ) : (
            <Empty
              icon={FlaskConical}
              title="Not verified"
              description={
                complete
                  ? "Start Lab to run the Proof against the pinned vulnerable application."
                  : "Complete the required artifacts before a Lab can run the Proof."
              }
            />
          )}
        </Panel>
      )}
      <RemediationPRs finding={finding} refresh={refresh} />
      {generate && (
        <JobLaunch
          operation="finding_artifacts"
          path={`/findings/${finding.id}/artifact-generations`}
          initialProfile={application.data?.config.profiles.finding_artifacts}
          context={`${finding.title} · ${sourceLabel(finding)} · affected versions ${finding.affected_versions.join(", ") || "unknown"}`}
          onClose={() => setGenerate(false)}
          onSubmitted={refresh}
        />
      )}
      {upload && (
        <ArtifactUpload
          finding={finding}
          onClose={() => setUpload(false)}
          refresh={refresh}
        />
      )}
      {approve && (
        <Approval
          title="Approve the Lab"
          description="Asset Monitor builds the vulnerable application and runs the Proof in a disposable Lab. Enter your password to approve this Lab."
          path={`/findings/${finding.id}/lab-runs`}
          success="Lab started after Approval."
          icon={FlaskConical}
          onClose={() => setApprove(false)}
          refresh={refresh}
        />
      )}
    </>
  );
}
/** A06's Playbook steps. */
const stepLabels: Record<string, string> = {
  proof: "Proof",
  report: "Report",
  disclosure_report: "Disclosure report",
  static_proof: "Static Proof",
  detection_rule: "Detection rule",
  cleanup_report: "Cleanup report",
  remediation_pr: "Remediation PR",
  deployed_version_check: "Deployed version check",
};
/** Where a step stands, when its bare status does not say it. */
const stepStates: Record<string, string> = {
  waiting_for_approval: "Waiting for your Approval",
  waiting_for_release: "Waiting for a release that contains the fix",
  no_own_repository: "No Own repository: skipped",
  no_safe_release: "No release without the change to pin",
  no_package: "The Upstream link names no package to change",
  no_fixed_version: "No fixed version is known yet",
  not_direct: "Not a direct dependency: update the package that pulls it in",
  not_drafted: "Not drafted",
  pending: "Not validated yet",
  ...deployedLabels,
};
function stepState(step: string, status: string) {
  // A ready Remediation PR draft waits for the Approval of its diff.
  if (step === "remediation_pr" && status === "ready")
    return stepStates.waiting_for_approval;
  return stepStates[status] || humanize(status);
}
function stepTone(step: string, status: string) {
  if (stepState(step, status).startsWith("Waiting")) return "warm";
  if (
    ["verified", "validated", "ready", "merged", "serving_fix"].includes(status)
  )
    return "good";
  return ["failed", "draft_failed", "before_fix"].includes(status)
    ? "danger"
    : "neutral";
}
/** The steps of the Finding's Playbook cell (A06). A step that needs Approval waits, visibly,
 * without blocking the others. */
function PlaybookPanel({ steps }: { steps: Finding["playbook"] }) {
  return (
    <Panel
      title="Playbook"
      description="The steps this Verdict runs. A step that needs your Approval waits without blocking the others."
      padded
    >
      <DetailGrid
        items={steps.map(({ step, status }) => [
          stepLabels[step] || humanize(step),
          <Badge tone={stepTone(step, status)}>
            {stepState(step, status)}
          </Badge>,
        ])}
      />
    </Panel>
  );
}
/** The Disclosure report (A06, A15) as escaped text, for the Operator to copy into the Upstream
 * repository's GitHub private vulnerability reporting form. Asset Monitor never sends it. */
function DisclosureReportPanel({
  report,
}: {
  report: NonNullable<Finding["disclosure_report"]>;
}) {
  return (
    <Panel
      title="Disclosure report"
      description="For the Upstream repository's maintainers: copy it into their GitHub private vulnerability reporting form. Asset Monitor never sends it."
      actions={
        <>
          <CopyButton value={report.text} label="Copy the Disclosure report" />
          {report.form_url && (
            <ExternalLink className="secondary button" href={report.form_url}>
              Open the reporting form
            </ExternalLink>
          )}
        </>
      }
      padded
    >
      <pre className="json-view">{report.text}</pre>
    </Panel>
  );
}
/** Each feed's affected ranges, as the report writes them: "osv: >=20.0.0 <20.19.5 || …". */
function rangeLines(ranges: AdvisoryRanges) {
  return Object.entries(ranges).map(
    ([feed, lists]) =>
      `${feed}: ${lists.map((list) => list.map(([op, bound]) => op + bound).join(" ") || "all versions").join(" || ")}`,
  );
}
/** An Advisory check match on the Finding (A09, A06): its report, rendered by Asset Monitor from
 * the feeds' records, its aliases, each pin with its affected ranges, and the version its bump
 * moves to. Feed text is shown only as text. */
function AdvisoryPanel({
  advisory,
  finding,
}: {
  advisory: Finding["advisories"][number];
  finding: Finding;
}) {
  const bump = finding.remediation_prs.find(
    (pr) => pr.action === "bump" && pr.subject === advisory.vulnerability,
  )?.dependency;
  const step = finding.playbook.find((s) => s.step === "remediation_pr");
  const fixed = bump
    ? [
        ...(bump.edits
          ? [`${bump.name} ${bump.version}`]
          : Object.entries(bump.versions || {}).map(([n, v]) => `${n} ${v}`)),
        ...(bump.edits || []).map((e) => `${e.source}: ${e.from} → ${e.to}`),
      ].join(" · ")
    : finding.source === "advisory" && step
      ? stepState(step.step, step.status)
      : "None: an attached match drafts no bump of its own";
  return (
    <Panel
      title={`Advisory ${advisory.vulnerability}`}
      description="Rendered by Asset Monitor from the OSV, GHSA and NVD records, shown as text."
      actions={
        <CopyButton value={advisory.report} label="Copy the advisory report" />
      }
      padded
    >
      <DetailGrid
        items={[
          [
            "Aliases",
            <TextList
              items={advisory.aliases.filter(
                (name) => name !== advisory.vulnerability,
              )}
            />,
          ],
          [
            "Exposure",
            <Badge tone={exposureTones[advisory.state]}>
              {exposureLabels[advisory.state]}
            </Badge>,
          ],
          ["Feeds", advisory.feeds.join(", ").toUpperCase() || "None"],
          ["Lowest fixed version", fixed],
        ]}
      />
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">Pin</th>
              <th scope="col">Pinned version</th>
              <th scope="col">From</th>
              <th scope="col">Affected ranges</th>
              <th scope="col">Exposure</th>
            </tr>
          </thead>
          <tbody>
            {advisory.pins.map((pin, i) => (
              <tr key={i}>
                <td>
                  <span className="mono">{pin.name}</span>
                  <span className="table-subtitle">
                    {pin.ecosystem || "runtime"}
                  </span>
                </td>
                <td className="mono">{pin.version}</td>
                <td className="mono">{pin.sources.join(", ")}</td>
                <td>
                  {rangeLines(pin.ranges).map((line) => (
                    <div key={line} className="mono">
                      {line}
                    </div>
                  ))}
                </td>
                <td>
                  <Badge tone={exposureTones[pin.state]}>
                    {exposureLabels[pin.state]}
                  </Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <pre className="json-view">{advisory.report}</pre>
    </Panel>
  );
}
/** The Finding's lifecycle state, its cause and the Operator's actions on it (A11). */
function Lifecycle({
  finding,
  refresh,
}: {
  finding: Finding;
  refresh: () => void;
}) {
  const [reason, setReason] = useState("");
  const at = text(finding.cause, "at");
  return (
    <Panel
      title="Lifecycle"
      description="Every change of state records its cause and when it happened."
      padded
    >
      <DetailGrid
        items={[
          ["State", <Badge>{finding.status}</Badge>],
          [
            "Cause",
            <>
              {causeLabel(finding.cause)}
              {at && (
                <span className="muted">
                  {" "}
                  · <Time value={at} absolute />
                </span>
              )}
            </>,
          ],
        ]}
      />
      <label>
        Reason
        <textarea
          required
          maxLength={2000}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Why the Finding changes state"
        />
      </label>
      <div className="form-actions">
        {transitions.map(({ state, label, from }) => (
          <ActionButton
            key={state}
            className="secondary"
            disabled={!from.includes(finding.status) || !reason.trim()}
            onAction={async () => {
              await mutate(
                `/findings/${finding.id}/transitions`,
                findingSchema,
                {
                  state,
                  reason,
                },
              );
              notify(`Finding ${state}.`);
              setReason("");
              refresh();
            }}
          >
            {label}
          </ActionButton>
        ))}
      </div>
    </Panel>
  );
}
const proofStates = {
  validated: { label: "Validated", tone: "good" },
  failed: { label: "Failed", tone: "danger" },
  pending: { label: "Not validated yet", tone: "warm" },
};
const checkTones = { passed: "good", failed: "danger", skipped: "neutral" };
function ProofState({ proof }: { proof?: StaticProof | null }) {
  const state = proofStates[proof?.status || "pending"];
  return <Badge tone={state.tone}>{state.label}</Badge>;
}
/** Strings as escaped text, one per line (A15). */
function TextList({ items }: { items: string[] }) {
  return items.length ? (
    <ul className="gap-list">
      {items.map((item, i) => (
        <li key={i} className="mono">
          {item}
        </li>
      ))}
    </ul>
  ) : (
    <span className="muted">None</span>
  );
}
/** A Malicious change's static Proof (A07): the Detection rule, its validation checks and the indicators. */
function StaticProofPanel({ proof }: { proof: StaticProof }) {
  const indicators = proof.indicators;
  return (
    <Panel
      title="Static Proof"
      description="The Detection rule and the indicators extracted from the change. The payload is never run."
      actions={
        <>
          <ProofState proof={proof} />
          {proof.job_id && <JobLink id={proof.job_id} />}
        </>
      }
      padded
    >
      {proof.checks.length ? (
        <DetailGrid
          items={proof.checks.map((check) => [
            detectionChecks[check.name] || humanize(check.name),
            <>
              <Badge tone={checkTones[check.status]}>{check.status}</Badge>{" "}
              {check.message}
              {check.files.length > 0 && <TextList items={check.files} />}
            </>,
          ])}
        />
      ) : (
        <p className="muted">The Detection rule has not been validated yet.</p>
      )}
      <div className="field-block">
        <span className="field-label with-copy">
          Detection rule
          {proof.rule && (
            <CopyButton value={proof.rule} label="Copy the Detection rule" />
          )}
        </span>
        {proof.rule ? (
          <pre className="json-view">{proof.rule}</pre>
        ) : (
          <span className="muted">No Detection rule was drafted.</span>
        )}
      </div>
      {indicators && (
        <>
          <DetailGrid
            items={[
              [
                "Files",
                indicators.files.length ? (
                  <ul className="gap-list">
                    {indicators.files.map((f, i) => (
                      <li key={i}>
                        <span className="mono">{f.path}</span>{" "}
                        <span className="mono muted">{f.sha256}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="muted">None</span>
                ),
              ],
              ["Hosts", <TextList items={indicators.hosts} />],
              ["URLs", <TextList items={indicators.urls} />],
              ["Commands", <TextList items={indicators.commands} />],
            ]}
          />
          {indicators.rejected.length > 0 && (
            <div className="field-block">
              <span className="field-label">Rejected indicators</span>
              <TextList
                items={indicators.rejected.map(
                  (r) => `${r.kind} ${r.value}: ${r.reason}`,
                )}
              />
            </div>
          )}
        </>
      )}
    </Panel>
  );
}
/** A Malicious change's cleanup report (A07). It is shown here and never sent anywhere. */
function CleanupReportPanel({
  report,
  proof,
}: {
  report: CleanupReport;
  proof?: StaticProof | null;
}) {
  const indicators = proof?.indicators;
  return (
    <Panel
      title="Cleanup report"
      description="What to remove and which secrets to rotate. Asset Monitor never sends it."
      padded
    >
      <DetailGrid
        items={[
          [
            "Files the change added",
            <TextList items={indicators?.files.map((f) => f.path) || []} />,
          ],
          [
            "Indicators the change added",
            <TextList
              items={
                indicators
                  ? [
                      ...indicators.hosts,
                      ...indicators.urls,
                      ...indicators.commands,
                    ]
                  : []
              }
            />,
          ],
          [
            "Commits that contained it",
            <span className="chip-row">
              {report.commits.map((c) =>
                c.commit_id ? (
                  <Link
                    key={c.revision}
                    className="mono"
                    to={`/commits/${c.commit_id}`}
                  >
                    {c.revision.slice(0, 7)}
                  </Link>
                ) : (
                  <span key={c.revision} className="mono">
                    {c.revision.slice(0, 7)}
                  </span>
                ),
              )}
              {report.commits_truncated && <span>and more</span>}
            </span>,
          ],
          [
            "Releases",
            // From release-tag containment; null when the tags could not be read.
            report.releases?.length ? (
              <TextList items={report.releases} />
            ) : (
              <span className="muted">
                {report.releases ? "No release tag contains it" : "Unknown"}
              </span>
            ),
          ],
          ["Secrets to rotate", <TextList items={report.secrets} />],
          [
            "Detection rule to run on the server",
            <span className="with-copy">
              <ProofState proof={proof} />
              {proof?.rule && (
                <CopyButton
                  value={proof.rule}
                  label="Copy the Detection rule"
                />
              )}
            </span>,
          ],
        ]}
      />
    </Panel>
  );
}
/** One entry of a Finding's history: opened, linked, a transition, or a Numen record. */
function HistoryEvent({
  event,
  finding,
}: {
  event: Record<string, unknown>;
  finding: Finding;
}) {
  const action = text(event, "action") || "event";
  const commitId = text(event, "commit_id");
  const revision = (text(event, "revision") || "").slice(0, 7);
  const [title, detail] =
    action === "opened"
      ? [
          "Opened",
          `${sourceLabel({ source: finding.source, source_ref: text(event, "source_ref") })} · ${causeLabel(event.cause)}`,
        ]
      : action === "linked"
        ? [
            "Linked change",
            <>
              {commitId ? (
                <Link className="mono" to={`/commits/${commitId}`}>
                  {revision}
                </Link>
              ) : (
                <span className="mono">{revision}</span>
              )}
              {` · ${text(event, "verdict") || "No Verdict"}`}
            </>,
          ]
        : action === "transition"
          ? [
              `${humanize(text(event, "from") || "")} → ${humanize(text(event, "to") || "")}`,
              causeLabel(event.cause),
            ]
          : action === "approved"
            ? text(event, "approved") === "remediation_pr"
              ? [
                  "Approved · Remediation PR",
                  `${humanize(text(event, "remediation") || "")} · diff SHA-256 ${text(event, "diff_sha256") || "unknown"}`,
                ]
              : ["Approved · Lab", undefined]
            : action === "remediation_pr_opened"
              ? [
                  "Remediation PR opened",
                  `${humanize(text(event, "remediation") || "")} · ${text(event, "branch") || ""}`,
                ]
              : action === "remediation_pr_merged"
                ? [
                    "Remediation PR merged",
                    `${humanize(text(event, "remediation") || "")} · merge commit ${(text(event, "merge_commit_sha") || "").slice(0, 7)}`,
                  ]
                : [humanize(action), undefined];
  return (
    <li className="timeline-item">
      <span className="timeline-marker neutral" aria-hidden="true" />
      <div className="timeline-body">
        <div className="timeline-title">
          <strong>{title}</strong>
          <Time value={text(event, "created_at")} absolute />
        </div>
        {detail && <small>{detail}</small>}
      </div>
    </li>
  );
}
/** An Approval (A15): the Operator's password, checked on this request alone, then one job. */
function Approval({
  title,
  description,
  path,
  body = {},
  success,
  icon: Icon,
  onClose,
  refresh,
}: {
  title: string;
  description: string;
  path: string;
  body?: Record<string, unknown>;
  success: string;
  icon: LucideIcon;
  onClose: () => void;
  refresh: () => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <Modal title={title} description={description} onClose={onClose}>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            await queueJob(path, { ...body, password }, undefined, success);
            refresh();
            onClose();
          } catch (err) {
            setError(err instanceof Error ? err.message : "Approval failed.");
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Password
          <input
            required
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            data-autofocus
          />
        </label>
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <button className="secondary" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy || !password}>
            <Icon size={15} aria-hidden="true" />
            {busy ? "Approving…" : "Approve"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
const remediationTones: Record<string, string> = {
  drafting: "info",
  waiting_for_cap: "warm",
  draft_failed: "danger",
  approved: "info",
  open: "info",
  merged: "good",
};
// A new draft of an action is refused while one is drafting or past its Approval.
const remediationBusy = ["drafting", "approved", "open", "merged", "closed"];
// Bidi controls and zero-width characters make a diff read differently from what it does
// ("Trojan Source"), so the Approval screen shows each one as a visible escape.
const hiddenCharacters =
  /[\u061C\u200B-\u200F\u2028-\u202E\u2060-\u2069\uFEFF]/g;
const revealHidden = (text: string) =>
  text.replace(
    hiddenCharacters,
    (c) => `⟨U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}⟩`,
  );
/** A pull request link only for an http(s) URL. */
function pullLink(pr: RemediationPR) {
  return pr.pull_url && /^https?:\/\//.test(pr.pull_url) ? (
    <a href={pr.pull_url} target="_blank" rel="noreferrer">
      Pull request #{pr.pull_number}
    </a>
  ) : null;
}
/** The Finding's Remediation PRs (A08): each validated diff as text with its SHA-256, approved
 * with the Operator's password, then opened as a draft pull request on the Own repository. */
function RemediationPRs({
  finding,
  refresh,
}: {
  finding: Finding;
  refresh: () => void;
}) {
  const [approving, setApproving] = useState<RemediationPR>();
  const rows = finding.remediation_prs;
  const step = finding.playbook.find((s) => s.step === "remediation_pr");
  return (
    <Panel
      title="Remediation PRs"
      description="Draft pull requests on the Own repository: a patch, a revert, or a dependency pin or bump. Each opens only after your Approval of its exact diff, and you merge it."
      actions={finding.remediation_actions.map((action) => (
        <ActionButton
          key={action}
          className="secondary"
          disabled={rows.some(
            (r) => r.action === action && remediationBusy.includes(r.status),
          )}
          onAction={async () => {
            await queueJob(
              `/findings/${finding.id}/remediation-prs`,
              { action },
              undefined,
              `${humanize(action)} draft queued.`,
            );
            refresh();
          }}
        >
          <GitPullRequest size={15} aria-hidden="true" />
          Draft {action}
        </ActionButton>
      ))}
    >
      {!finding.own_repository && (
        <Empty
          icon={GitPullRequest}
          title="No Own repository: Remediation PR steps are skipped."
          description="Link an Own repository to the Application to draft patches and reverts."
        />
      )}
      {finding.own_repository && !rows.length && (
        <Empty
          icon={GitPullRequest}
          title={
            step && step.status !== "not_drafted"
              ? stepState(step.step, step.status)
              : "No Remediation PR drafted"
          }
          description={
            step?.status === "waiting_for_release"
              ? "The bump is drafted once a release tag contains the fix."
              : step?.status === "no_safe_release"
                ? "Every known release contains the change, or the release tags could not be read."
                : step?.status === "no_package"
                  ? "Only an Upstream link derived from a manifest or lockfile names the packages a pin or bump changes."
                  : finding.playbook.length && !step
                    ? "This Verdict's Playbook has no Remediation PR."
                    : finding.remediation_actions.length
                      ? "Its Verdict drafts one automatically, or draft one here."
                      : finding.source === "advisory"
                        ? "An Advisory check match is bumped only to a known fixed version of a direct dependency or a runtime pin."
                        : "Only a Vulnerability introduced or Malicious change commit of the Own repository gets a patch or revert, and an exposed Upstream Verdict a pin or bump."
          }
        />
      )}
      {rows.length > 0 && (
        <div className="row-list">
          {rows.map((pr) => (
            <article className="lab-run" key={pr.id}>
              <div className="analysis-header">
                <strong>{humanize(pr.action)}</strong>
                <Badge tone={remediationTones[pr.status]}>{pr.status}</Badge>
                <span className="analysis-time">
                  <Time value={pr.updated_at} absolute />
                </span>
                {pr.job_id && <JobLink id={pr.job_id} />}
                {["ready", "failed"].includes(pr.status) && pr.diff && (
                  <button className="primary" onClick={() => setApproving(pr)}>
                    <GitPullRequest size={15} aria-hidden="true" />
                    Approve
                  </button>
                )}
              </div>
              {pr.summary && <p className="readable-copy">{pr.summary}</p>}
              {describeError(pr.error) && (
                <ErrorNote>{describeError(pr.error)}</ErrorNote>
              )}
              {pr.flags.includes("workflows") && (
                <Callout tone="warm" title="CI workflow change">
                  This diff changes .github/workflows. Review it closely; the
                  write token needs the Workflows permission to push it.
                </Callout>
              )}
              <DetailGrid
                items={[
                  [
                    "Base revision",
                    <span className="mono">
                      {pr.base_ref?.slice(0, 12) || "Not drafted yet"}
                    </span>,
                  ],
                  [
                    "Branch",
                    pr.branch ? (
                      <span className="mono">{pr.branch}</span>
                    ) : (
                      <span className="muted">Not opened</span>
                    ),
                  ],
                  [
                    "Pull request",
                    pullLink(pr) || <span className="muted">Not opened</span>,
                  ],
                ]}
              />
              {pr.diff && revealHidden(pr.diff) !== pr.diff && (
                <Callout tone="warm" title="Hidden characters">
                  This diff holds bidirectional or zero-width characters, which
                  can make code read differently from what it does. Each is
                  shown as ⟨U+…⟩.
                </Callout>
              )}
              {pr.diff && (
                <div className="field-block">
                  <span className="field-label with-copy">
                    Diff SHA-256 <span className="mono">{pr.diff_sha256}</span>
                  </span>
                  <DiffView diff={revealHidden(pr.diff)} />
                </div>
              )}
            </article>
          ))}
        </div>
      )}
      {approving?.diff_sha256 && (
        <Approval
          title={`Approve the ${approving.action} Remediation PR`}
          description={`Asset Monitor opens one draft pull request on the Own repository from exactly the diff with SHA-256 ${approving.diff_sha256}. It never merges. Enter your password to approve it.`}
          path={`/findings/${finding.id}/remediation-prs/${approving.id}/approvals`}
          body={{ diff_sha256: approving.diff_sha256 }}
          success="Remediation PR approved: opening the draft pull request."
          icon={GitPullRequest}
          onClose={() => setApproving(undefined)}
          refresh={refresh}
        />
      )}
    </Panel>
  );
}
function ArtifactUpload({
  finding,
  onClose,
  refresh,
}: {
  finding: Finding;
  onClose: () => void;
  refresh: () => void;
}) {
  const [report, setReport] = useState<File>();
  const [poc, setPoc] = useState<File>();
  const [rule, setRule] = useState<File>();
  const [appFiles, setAppFiles] = useState<{ file: File; path: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <Modal
      title="Upload finding artifacts"
      description={
        finding.malicious_change
          ? "Uploads are passive. A new Detection rule is validated without running the payload."
          : "Uploads are passive. A Lab runs only after your Approval."
      }
      onClose={onClose}
    >
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          const form = new FormData();
          function append(file: File, path: string) {
            form.append("files", file);
            form.append("paths", path);
          }
          if (report) append(report, "report.md");
          if (poc) append(poc, "poc.py");
          if (rule) append(rule, "detection-rule.yar");
          appFiles.forEach((entry) => append(entry.file, entry.path));
          try {
            await request(`/findings/${finding.id}/artifacts`, findingSchema, {
              method: "POST",
              body: form,
            });
            notify("New artifact revision uploaded.");
            refresh();
            onClose();
          } catch (err) {
            setError(
              err instanceof Error ? err.message : "Artifact upload failed.",
            );
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Report (report.md)
          <input
            type="file"
            accept=".md,text/markdown,text/plain"
            onChange={(e) => setReport(e.target.files?.[0])}
          />
        </label>
        {finding.malicious_change ? (
          <label>
            Detection rule (detection-rule.yar)
            <input
              type="file"
              accept=".yar,.yara,text/plain"
              onChange={(e) => setRule(e.target.files?.[0])}
            />
          </label>
        ) : (
          <>
            <label>
              Python PoC (poc.py)
              <input
                type="file"
                accept=".py,text/plain"
                onChange={(e) => setPoc(e.target.files?.[0])}
              />
            </label>
            <label>
              Vulnerable application files
              <input
                type="file"
                multiple
                onChange={(e) =>
                  setAppFiles(
                    Array.from(e.target.files || []).map((file) => ({
                      file,
                      path: `vulnerable-app/${file.name}`,
                    })),
                  )
                }
              />
            </label>
            <label>
              Or select the application directory
              <input
                type="file"
                multiple
                {...{ webkitdirectory: "" }}
                onChange={(e) =>
                  setAppFiles(
                    Array.from(e.target.files || []).map((file) => {
                      const relative = file.webkitRelativePath
                        .split("/")
                        .slice(1)
                        .join("/");
                      return {
                        file,
                        path: `vulnerable-app/${relative || file.name}`,
                      };
                    }),
                  )
                }
              />
            </label>
            {appFiles.length > 0 && (
              <div className="upload-paths">
                <p className="hint">
                  Verify safe paths within vulnerable-app/. Include Dockerfile,
                  compose.yaml, README.md, and application.lock.json.
                </p>
                {appFiles.map((entry, i) => (
                  <label key={i}>
                    {entry.file.name}
                    <input
                      value={entry.path}
                      required
                      onChange={(e) =>
                        setAppFiles((files) =>
                          files.map((item, index) =>
                            index === i
                              ? { ...item, path: e.target.value }
                              : item,
                          ),
                        )
                      }
                    />
                  </label>
                ))}
              </div>
            )}
          </>
        )}
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <button className="secondary" type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="primary"
            disabled={busy || (!report && !poc && !rule && !appFiles.length)}
          >
            <Upload size={15} />
            {busy ? "Uploading…" : "Upload revision"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
