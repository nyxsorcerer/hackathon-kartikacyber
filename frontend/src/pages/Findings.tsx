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
  Plus,
  Save,
  Sparkles,
  Target,
  Upload,
} from "lucide-react";
import { mutate, request } from "../api";
import { useResource } from "../hooks";
import {
  findingSchema,
  findingsSchema,
  programSchema,
  programsSchema,
} from "../types";
import type { Finding, Program } from "../types";
import { JobLaunch, queueJob } from "../components/JobLaunch";
import { ArtifactBrowser } from "../components/ArtifactPreview";
import {
  ActionButton,
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
  Tabs,
  Time,
} from "../components/ui";
function labState(finding: Finding) {
  const status = finding.lab_runs[0]?.status;
  if (typeof status !== "string")
    return { label: "Lab unverified", tone: "neutral" };
  return status === "verified"
    ? { label: "Lab verified", tone: "good" }
    : {
        label: `Lab ${status.replaceAll("_", " ")}`,
        tone: status === "failed" ? "danger" : "warm",
      };
}
function findingIdentifier(finding: Finding) {
  return finding.cve_id || `0day · ${finding.id.slice(0, 8)}`;
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
export function FindingsList({ program }: { program?: Program }) {
  const [cursor, setCursor] = useState("");
  const params = new URLSearchParams();
  if (program) params.set("program_id", program.id);
  if (cursor) params.set("cursor", cursor);
  const resource = useResource(
    `/findings${params.size ? `?${params}` : ""}`,
    findingsSchema,
    0,
    true,
  );
  return (
    <Panel
      title="Finding register"
      description="Upstream remediation and target exposure are tracked independently."
      actions={
        program && (
          <Link
            className="secondary button"
            to={`/findings/new?program_id=${program.id}`}
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
        {resource.data?.items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Finding</th>
                  <th scope="col">Status</th>
                  <th scope="col">Upstream fixed in</th>
                  <th scope="col">Target exposure</th>
                  <th scope="col">Artifacts</th>
                  <th scope="col">Updated</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.items.map((finding) => {
                  const lab = labState(finding);
                  return (
                    <tr key={finding.id}>
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
                        {finding.fixed_versions.join(", ") || (
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
                to={`/findings/new${program ? `?program_id=${program.id}` : ""}`}
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
  const programs = useResource("/programs", programsSchema);
  const [programId, setProgramId] = useState(
    finding?.program_id || params.get("program_id") || "",
  );
  const [kind, setKind] = useState(
    finding?.kind || (params.has("cve_id") ? "cve" : "0day"),
  );
  const [cveId, setCveId] = useState(
    finding?.cve_id || params.get("cve_id") || "",
  );
  const [title, setTitle] = useState(finding?.title || "");
  const [status, setStatus] = useState(finding?.status || "open");
  const [affected, setAffected] = useState(
    finding?.affected_versions.join("\n") || "",
  );
  const [fixed, setFixed] = useState(finding?.fixed_versions.join("\n") || "");
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
                program_id: programId,
                kind,
                cve_id: cveId || null,
                title,
                status,
                affected_versions: affected.split("\n").filter(Boolean),
                fixed_versions: fixed.split("\n").filter(Boolean),
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
              Program
              <select
                required
                value={programId}
                onChange={(e) => setProgramId(e.target.value)}
              >
                <option value="">Select a program</option>
                {programs.data?.items.map((p) => (
                  <option value={p.id} key={p.id}>
                    {p.asset_name} · {p.product_name}
                  </option>
                ))}
              </select>
              {programs.error && (
                <span className="field-error">{programs.error}</span>
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
          <button className="primary" disabled={busy || programs.loading}>
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
const artifactTabs = [
  {
    id: "report",
    label: "Report",
    noun: "report",
    match: (path: string) =>
      path === "report.md" || path.endsWith("/report.md"),
  },
  {
    id: "poc",
    label: "Python PoC",
    noun: "PoC",
    match: (path: string) => path === "poc.py" || path.endsWith("/poc.py"),
  },
  {
    id: "app",
    label: "Vulnerable app",
    noun: "vulnerable app",
    match: (path: string) => path.startsWith("vulnerable-app/"),
  },
];
function FindingBody({
  finding,
  refresh,
}: {
  finding: Finding;
  refresh: () => void;
}) {
  const [tab, setTab] = useState("report");
  const [generate, setGenerate] = useState(false);
  const [upload, setUpload] = useState(false);
  const program = useResource(`/programs/${finding.program_id}`, programSchema);
  const activeTab = artifactTabs.find((t) => t.id === tab) || artifactTabs[0];
  const artifacts = finding.artifacts.filter((a) => activeTab.match(a.path));
  const complete = finding.artifact_state.status === "complete";
  const observed = program.data?.version;
  const lab = labState(finding);
  return (
    <>
      <PageHeading
        back={{ to: "/findings", label: "All findings" }}
        eyebrow={findingIdentifier(finding)}
        title={finding.title}
        description={
          program.data && (
            <Link to={`/programs/${finding.program_id}?tab=findings`}>
              {program.data.asset_name} · {program.data.product_name}
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
            {complete && (
              <a
                className="primary button"
                download
                href={`/api/findings/${finding.id}/download`}
              >
                <Download size={15} aria-hidden="true" />
                Download bundle
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
                finding.fixed_versions.join(", ") || (
                  <span className="muted">Unknown</span>
                ),
              ],
              [
                "Affected versions",
                finding.affected_versions.join(", ") || (
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
        <Tabs
          label="Artifact type"
          items={artifactTabs.map((t) => ({
            id: t.id,
            label: t.label,
            count: finding.artifacts.filter((a) => t.match(a.path)).length,
          }))}
          active={tab}
          onChange={setTab}
        />
        {artifacts.length ? (
          <ArtifactBrowser artifacts={artifacts} />
        ) : (
          <Empty
            title={`No ${activeTab.noun} yet`}
            description="Upload files or request generation to prepare this part of the bundle."
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
          initialProfile={program.data?.config.profiles.finding_artifacts}
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
