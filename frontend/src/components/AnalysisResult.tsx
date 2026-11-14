import { Link } from "react-router-dom";
import { Download } from "lucide-react";
import { useResource } from "../hooks";
import { jobSchema } from "../types";
import type { Analysis } from "../types";
import { versionLabels } from "../versions";
import { confidenceText } from "../jobSummary";
import { ArtifactBrowser } from "./ArtifactPreview";
import {
  Badge,
  Callout,
  DataState,
  describeError,
  DetailGrid,
  Evidence,
  humanize,
  JobLink,
  Markdown,
  Time,
} from "./ui";

function strings(value: unknown) {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}
function versions(value: unknown) {
  return versionLabels(value).join("; ") || "Not reported";
}
function confidenceLabel(value: unknown) {
  if (typeof value === "string") return value;
  if (typeof value !== "object" || value === null) return "Not reported";
  const fields = Object.fromEntries(Object.entries(value));
  const label = fields.level || fields.overall;
  return typeof label === "string" ? label : "See evidence";
}

export function AnalysisResult({
  analysis,
  kind = "cve",
}: {
  analysis: Analysis;
  kind?: "cve" | "commit";
}) {
  const job = useResource(
    analysis.job_id ? `/jobs/${encodeURIComponent(analysis.job_id)}` : null,
    jobSchema,
  );
  const result = analysis.result;
  const artifacts = analysis.artifacts || [];
  const report = artifacts.find((a) => a.path === "report.md");
  const poc = artifacts.find((a) => a.path === "poc.py");
  // An Upstream Proof is never exported (A15): only its reports are shown.
  const exportable = analysis.exportable !== false;
  const questions = strings(result?.open_questions);
  const artifactsId =
    kind === "cve" ? "cve-analysis-artifacts" : "commit-analysis-artifacts";
  const confidence = confidenceText(result?.confidence);
  const addresses = result?.addresses || [];
  return (
    <>
      <section
        className="analysis-result-summary"
        aria-label="Analysis summary"
      >
        <div className="analysis-result-heading">
          <h3>
            {kind === "commit"
              ? result?.title || "Analysis summary"
              : "Analysis summary"}
          </h3>
          <Time value={analysis.created_at} absolute />
          {analysis.superseded && <Badge tone="warm">Criteria changed</Badge>}
        </div>
        <DataState
          loading={job.loading}
          error={job.error}
          retry={job.refresh}
          hasData={!!job.data}
        >
          {job.data && (
            <div className="chip-row">
              <Badge>{job.data.status}</Badge>
              {["failed", "cancelled"].includes(job.data.status) && (
                <span className="hint">Partial output retained</span>
              )}
            </div>
          )}
        </DataState>
        {kind === "commit" && result?.verdict && (
          <div className="chip-row">
            <Badge>{result.verdict}</Badge>
            {confidence && <Badge tone="neutral">{humanize(confidence)}</Badge>}
          </div>
        )}
        {job.data?.error != null && (
          <Callout tone="warm" title="This run did not complete">
            {describeError(job.data.error)}. Review the retained files and job
            details before running another analysis.
          </Callout>
        )}
        <p className="analysis-summary">
          {result?.summary ||
            analysis.summary ||
            "No summary was provided. Review the saved report and source evidence."}
        </p>
        <DetailGrid
          items={
            kind === "commit"
              ? [
                  [
                    "Vulnerable revision",
                    result?.vulnerable_ref ? (
                      <code>{result.vulnerable_ref}</code>
                    ) : (
                      "Not identified"
                    ),
                  ],
                  [
                    "Addresses",
                    addresses.length ? (
                      <span className="finding-links">
                        {addresses.map((address) => (
                          <code key={address}>{address}</code>
                        ))}
                      </span>
                    ) : (
                      "None reported"
                    ),
                  ],
                ]
              : [
                  ["Affected versions", versions(result?.affected_versions)],
                  ["Fixed in", versions(result?.fixed_versions)],
                  [
                    "Target at analysis",
                    <Badge>
                      {typeof result?.applicability === "string"
                        ? result.applicability
                        : "Unknown"}
                    </Badge>,
                  ],
                  ["Confidence", confidenceLabel(result?.confidence)],
                ]
          }
        />
        {kind === "commit" && artifacts.length > 0 && (
          <p className="hint">
            Drafts are not reproduced: Analysis builds and runs nothing. A Lab
            verifies a drafted Proof bundle only after your Approval.
          </p>
        )}
        {analysis.profile && (
          <p className="hint">
            {analysis.profile.agent} · {analysis.profile.model_id} ·{" "}
            {analysis.profile.reasoning_effort || "Provider managed"}
          </p>
        )}
        {analysis.superseded && (
          <p className="hint warning">
            The product match or score criteria have changed since this run. Its
            report describes the inputs saved at that time.
          </p>
        )}
        <div className="analysis-result-actions">
          {artifacts.length > 0 && (
            <a className="secondary button" href={`#${artifactsId}`}>
              Browse artifacts
            </a>
          )}
          {exportable && analysis.id && artifacts.length > 0 && (
            <a
              className="primary button"
              download
              href={`/api/analyses/${encodeURIComponent(analysis.id)}/download`}
            >
              <Download size={15} aria-hidden="true" />
              Download analysis bundle
            </a>
          )}
          {report && (
            <a
              className="secondary button"
              download="report.md"
              href={`/api/artifacts/${encodeURIComponent(report.id)}/content`}
            >
              Download report
            </a>
          )}
          {exportable && poc && (
            <a
              className="secondary button"
              download="poc.py"
              href={`/api/artifacts/${encodeURIComponent(poc.id)}/content`}
            >
              Download PoC
            </a>
          )}
          {analysis.job_id && <JobLink id={analysis.job_id} />}
          {result?.finding_id && (
            <Link
              className="secondary button"
              to={`/findings/${encodeURIComponent(result.finding_id)}`}
            >
              View finding artifacts
            </Link>
          )}
          {result?.finding_removed && (
            <span className="muted">The finding it created was deleted.</span>
          )}
        </div>
        {exportable && artifacts.length > 0 && (
          <p className="hint">
            The ZIP contains this run’s saved files and integrity manifest, with
            application directories preserved. Review lab verification on the
            finding.
          </p>
        )}
      </section>
      {kind === "commit" && (
        <section className="analysis-comparison" aria-label="Before and after">
          {typeof result?.before_after === "string" && (
            <>
              <h3>Before / after</h3>
              <p className="readable-copy">{result.before_after}</p>
            </>
          )}
          {typeof result?.affected_behavior === "string" && (
            <>
              <h3>Affected behavior</h3>
              <p className="readable-copy">{result.affected_behavior}</p>
            </>
          )}
        </section>
      )}
      {questions.length > 0 && (
        <section className="analysis-open-questions">
          <h3>Open questions</h3>
          <ul>
            {questions.map((question, index) => (
              <li key={index}>{question}</li>
            ))}
          </ul>
        </section>
      )}
      <section
        id={artifactsId}
        tabIndex={-1}
        className="analysis-result-artifacts"
        aria-label="Analysis artifacts"
      >
        <h3>Report & artifacts</h3>
        {artifacts.length > 0 ? (
          <ArtifactBrowser
            artifacts={artifacts}
            exportable={exportable}
            grouped
          />
        ) : analysis.report || result?.report ? (
          <Markdown>{result?.report || analysis.report || ""}</Markdown>
        ) : (
          <p className="hint">
            No files were saved for this run. Check its job details for the
            failure and retained evidence.
          </p>
        )}
      </section>
      <div className="analysis-source-evidence">
        {typeof result?.confidence === "object" && (
          <Evidence label="Confidence evidence" value={result.confidence} />
        )}
        {result?.evidence !== undefined && (
          <Evidence label="Source evidence" value={result.evidence} />
        )}
        <Evidence label="Full analysis result" value={analysis} />
      </div>
    </>
  );
}
