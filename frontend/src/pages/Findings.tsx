import { useState } from "react";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import {
  Download,
  FlaskConical,
  PencilLine,
  Trash2,
  Plus,
  Save,
  Sparkles,
  Target,
  Upload,
} from "lucide-react";
import { z } from "zod";
import { mutate, request } from "../api";
import { useResource } from "../hooks";
import {
  findingDeletionSchema,
  findingSchema,
  findingSummariesSchema,
  applicationSchema,
  applicationsSchema,
} from "../types";
import type { Finding, Application } from "../types";
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
  DetailGrid,
  Empty,
  ErrorNote,
  Evidence,
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
function findingIdentifier(
  finding: Pick<Finding, "id" | "cve_id" | "source_commit_id">,
) {
  return (
    finding.cve_id ||
    `${finding.source_commit_id ? "Commit finding" : "0day"} · ${finding.id.slice(0, 8)}`
  );
}
export function Findings() {
  return (
    <>
      <PageHeading
        eyebrow="Confirmed evidence"
        title="Findings"
        description="Reproducible reports, operator decisions, and the deployed asset’s exposure."
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
                  <th scope="col">Status</th>
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
                          {findingIdentifier(finding)}
                        </div>
                      </td>
                      <td>
                        <Badge>{finding.status}</Badge>
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
                          <Badge tone={lab.tone}>{lab.label}</Badge>
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
  const [kind, setKind] = useState(
    finding?.kind || (params.has("cve_id") ? "cve" : "0day"),
  );
  const [cveId, setCveId] = useState(
    finding?.cve_id || params.get("cve_id") || "",
  );
  const [title, setTitle] = useState(
    finding?.title || params.get("title") || "",
  );
  const [status, setStatus] = useState(finding?.status || "open");
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
                kind,
                cve_id: cveId || null,
                title,
                status,
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
              Finding type
              <select
                value={kind}
                onChange={(e) => {
                  if (e.target.value === "cve" || e.target.value === "0day")
                    setKind(e.target.value);
                }}
              >
                <option value="0day">0day — local identifier</option>
                <option value="cve">CVE</option>
              </select>
            </label>
            <label>
              {kind === "cve" ? "CVE identifier" : "CVE identifier (optional)"}
              <input
                required={kind === "cve"}
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
              Operator status
              <select
                value={status}
                onChange={(e) => {
                  if (e.target.value === "open" || e.target.value === "fixed")
                    setStatus(e.target.value);
                }}
              >
                <option value="open">Open</option>
                <option value="fixed">Fixed — operator confirmed</option>
              </select>
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
  const navigate = useNavigate();
  const application = useResource(
    `/applications/${finding.application_id}`,
    applicationSchema,
  );
  const complete = finding.artifact_state.status === "complete";
  const observed = application.data?.version;
  const lab = labState(finding.lab_runs[0]?.status);
  return (
    <>
      <PageHeading
        back={{ to: "/findings", label: "All findings" }}
        eyebrow={findingIdentifier(finding)}
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
            {finding.artifacts.length > 0 && (
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
            <Badge>{finding.status}</Badge>
            <span>
              Exposure <Badge>{finding.target_applicability}</Badge>
            </span>
            <span>
              Artifacts <Badge>{finding.artifact_state.status}</Badge>
            </span>
            <Badge tone={lab.tone}>{lab.label}</Badge>
          </>
        }
      />
      {finding.artifact_state.missing.length > 0 && (
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
          Missing: {finding.artifact_state.missing.join(", ")}. Lab verification
          is available once the bundle is complete.
        </Callout>
      )}
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
              ["Operator status", <Badge>{finding.status}</Badge>],
              [
                "Vulnerable lab version",
                finding.artifact_state.vulnerable_version || (
                  <span className="muted">Not declared</span>
                ),
              ],
            ]}
          />
          <p className="hint">
            An upstream fix does not confirm the remote target is remediated.
            New observations update exposure evidence and never change your
            status.
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
            ["Type", finding.kind === "cve" ? "CVE" : "0day"],
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
        {finding.events?.length ? (
          <Evidence
            value={finding.events}
            label="Operator decisions & linkage history"
          />
        ) : null}
        {finding.artifact_state.limitations.length > 0 && (
          <Evidence
            value={finding.artifact_state.limitations}
            label="Reproduction limitations"
          />
        )}
      </Panel>
      <Panel
        title="Reproducible artifacts"
        description="Report, Python PoC, and the pinned vulnerable application."
        actions={
          <>
            <button className="secondary" onClick={() => setUpload(true)}>
              <Upload size={15} aria-hidden="true" />
              Upload
            </button>
            <button className="secondary" onClick={() => setGenerate(true)}>
              <Sparkles size={15} aria-hidden="true" />
              Generate
            </button>
          </>
        }
      >
        {finding.artifacts.length ? (
          <ArtifactBrowser
            key={finding.artifact_revision}
            artifacts={finding.artifacts}
            grouped
          />
        ) : (
          <Empty
            title="No artifacts yet"
            description="Upload files or request generation to prepare the report, PoC, and vulnerable application."
          />
        )}
      </Panel>
      <Panel
        title="Lab verification"
        description="Runs this artifact set against its isolated vulnerable Docker application."
        actions={
          <ActionButton
            className="primary"
            disabled={!complete}
            title={complete ? undefined : "Complete the bundle first"}
            onAction={() =>
              queueJob(
                `/findings/${finding.id}/lab-runs`,
                {},
                undefined,
                "Lab verification queued.",
              )
            }
          >
            <FlaskConical size={15} aria-hidden="true" />
            Verify in lab
          </ActionButton>
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
                ? "Verify in lab to record a result for the pinned vulnerable application."
                : "Complete the required artifacts before requesting isolated lab verification."
            }
          />
        )}
      </Panel>
      {generate && (
        <JobLaunch
          operation="finding_artifacts"
          path={`/findings/${finding.id}/artifact-generations`}
          initialProfile={application.data?.config.profiles.finding_artifacts}
          context={`${finding.title} · ${finding.cve_id || "0day"} · affected versions ${finding.affected_versions.join(", ") || "unknown"}`}
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
    </>
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
  const [appFiles, setAppFiles] = useState<{ file: File; path: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <Modal
      title="Upload finding artifacts"
      description="Uploads are passive. Lab execution requires a separate explicit action."
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
                        index === i ? { ...item, path: e.target.value } : item,
                      ),
                    )
                  }
                />
              </label>
            ))}
          </div>
        )}
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <button className="secondary" type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="primary"
            disabled={busy || (!report && !poc && !appFiles.length)}
          >
            <Upload size={15} />
            {busy ? "Uploading…" : "Upload revision"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
