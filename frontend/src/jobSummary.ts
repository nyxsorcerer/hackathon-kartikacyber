import { detectionChecks, operationNames } from "./types";
import type { Job, JobSubject } from "./types";
import { describeError, humanize, sentence } from "./components/ui";

export function jobName(kind: string) {
  return kind in operationNames
    ? operationNames[kind as keyof typeof operationNames]
    : humanize(kind);
}
/** A title that names what the job acted on, e.g. "CVE analysis: CVE-2026-1234". */
export function jobTitle(job: Job) {
  return job.subject
    ? `${jobName(job.kind)}: ${job.subject.label}`
    : jobName(job.kind);
}
const subjectLinks: Record<string, string> = {
  commit: "Open commit",
  cve: "Open CVE",
  finding: "Open finding",
  account: "Open connections",
  notification: "Open notified item",
  source: "Open repositories",
  advisory: "Open Advisories",
  version: "Open version evidence",
  audit: "Open audit context",
  cves: "Open CVE records",
};
/** Text for the link to a job's subject, e.g. "Open commit". */
export function subjectLinkText(subject: JobSubject) {
  return subjectLinks[subject.type] || `Open ${humanize(subject.type)}`;
}
/** How a subject's short reference reads after its link text. */
export function subjectRefText(subject: JobSubject) {
  if (!subject.ref) return "";
  if (subject.type === "commit") return subject.ref;
  if (subject.type === "account") return `(${subject.ref})`;
  return `at ${subject.ref}`;
}
export function jobError(job: Job) {
  return job.error ? describeError(job.error) || "Failed without a reason" : "";
}
function field(value: unknown, key: string): unknown {
  return typeof value === "object" && value !== null && key in value
    ? Reflect.get(value, key)
    : undefined;
}
function text(value: unknown, key: string) {
  const found = field(value, key);
  return typeof found === "string" && found ? found : undefined;
}
function count(value: unknown, key: string) {
  const found = field(value, key);
  return typeof found === "number" ? found : undefined;
}
function list(value: unknown, key: string): unknown[] {
  const found = field(value, key);
  return Array.isArray(found) ? found : [];
}
function plural(n: number, one: string, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}
/** Confidence arrives as a number, a level, or `{level, score}`. */
export function confidenceText(value: unknown) {
  if (typeof value === "number" && Number.isFinite(value))
    return `${Math.round(value * 100)}% confidence`;
  if (typeof value === "string" && value) return `${value} confidence`;
  const level = text(value, "level");
  const score = count(value, "score");
  if (level) return `${level} confidence`;
  if (score !== undefined) return `${Math.round(score * 100)}% confidence`;
}
/** Runs one minute or longer read as minutes; hours keep their minutes. */
export function duration(start?: string | null, end?: string | null) {
  if (!start || !end) return;
  const seconds = Math.round((Date.parse(end) - Date.parse(start)) / 1000);
  if (!Number.isFinite(seconds) || seconds < 0) return;
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  return `${Math.floor(minutes / 60)} h ${String(minutes % 60).padStart(2, "0")} min`;
}
const triageDecisions: Record<string, string> = {
  security_candidate: "Flagged as a security candidate",
  unrelated: "Judged unrelated to security",
  insufficient_context:
    "Flagged: not enough context to rule out a security issue",
};
/** One plain sentence describing what a successful job produced. */
function successSummary(job: Job): {
  summary: string;
  facts: string[];
  tone?: Tone;
} {
  const r = job.result;
  const facts: string[] = [];
  const confidence = confidenceText(field(r, "confidence"));
  switch (job.kind) {
    case "source_check": {
      const imported = count(r, "imported") || 0;
      const ref = text(r, "source_ref");
      if (ref) facts.push(`Upstream at ${ref.slice(0, 10)}`);
      return {
        summary:
          field(r, "baseline") === true
            ? "Set the Baseline at the head; earlier commits are not imported"
            : imported
              ? `Imported ${plural(imported, "new revision")}`
              : "No new upstream revisions",
        facts,
      };
    }
    case "backfill": {
      const imported = count(r, "imported") || 0;
      return {
        summary: `Backfill imported ${plural(imported, "earlier revision")}`,
        facts,
      };
    }
    case "derive_upstreams": {
      const added = list(r, "added").length;
      const removed = list(r, "removed").length;
      const unresolved = count(r, "unresolved") || 0;
      if (added) facts.push(`${added} added`);
      if (removed) facts.push(`${removed} removed`);
      if (unresolved) facts.push(plural(unresolved, "unresolved package"));
      return {
        summary: `Found ${plural(count(r, "repositories") || 0, "Upstream repository", "Upstream repositories")}`,
        facts,
      };
    }
    case "advisory_check": {
      const unknown = count(r, "unknown") || 0;
      const matches = count(r, "matches") || 0;
      const opened = count(r, "opened") || 0;
      const attached = count(r, "attached") || 0;
      if (unknown)
        facts.push(
          `${plural(unknown, "unreadable version")}, counted as exposed`,
        );
      if (matches)
        facts.push(
          plural(
            matches,
            "exposed or unknown match",
            "exposed or unknown matches",
          ),
        );
      if (attached) facts.push(`Attached to ${plural(attached, "Finding")}`);
      const pins = `Collected ${count(r, "runtimes") || 0} runtime and ${plural(count(r, "packages") || 0, "package pin")}`;
      return {
        summary: opened
          ? `${pins} · ${plural(opened, "Finding")} opened`
          : pins,
        facts,
        tone: opened ? "warm" : undefined,
      };
    }
    case "cve_sync": {
      const imported = count(r, "imported") || 0;
      return {
        summary: imported
          ? `Imported ${plural(imported, "CVE record")}`
          : "No new or changed CVE records",
        facts,
      };
    }
    case "commit_triage": {
      const decision = text(r, "decision") || "";
      return {
        summary:
          triageDecisions[decision] ||
          (decision ? `Triage decided ${humanize(decision)}` : "Triage saved"),
        facts,
        tone: decision === "security_candidate" ? "warm" : undefined,
      };
    }
    case "commit_analysis": {
      const verdict = text(r, "verdict") || "Analysis saved";
      if (confidence) facts.push(humanize(confidence));
      return {
        summary: text(r, "finding_id")
          ? `${verdict} · finding created`
          : verdict,
        facts,
      };
    }
    case "cve_analysis": {
      const affected = list(r, "affected_versions")
        .map((v) => text(v, "range"))
        .filter(Boolean);
      const fixed = list(r, "fixed_versions")
        .map((v) => text(v, "fixedIn") || text(v, "version"))
        .filter(Boolean);
      if (affected.length) facts.push(`Affected ${affected.join("; ")}`);
      if (fixed.length) facts.push(`Fixed in ${fixed.join(", ")}`);
      if (confidence) facts.push(humanize(confidence));
      return {
        summary: text(r, "finding_id")
          ? "Analysis saved · finding created"
          : "Analysis saved",
        facts,
      };
    }
    case "version_check": {
      const version = text(r, "version");
      const candidates = list(r, "candidates").length;
      if (confidence) facts.push(humanize(confidence));
      return {
        summary: version
          ? `Detected version ${version}`
          : candidates
            ? `Narrowed to ${plural(candidates, "candidate version")}`
            : "No version could be determined from the target",
        facts,
        tone: version ? undefined : "warm",
      };
    }
    case "version_recipe": {
      const checks = list(field(r, "validation"), "checks");
      const passed = checks.filter((c) => field(c, "passed") === true).length;
      return {
        summary: checks.length
          ? `Recipe validated: ${passed} of ${plural(checks.length, "check")} passed`
          : "Recipe saved",
        facts,
      };
    }
    case "audit_context": {
      const coverage = field(r, "coverage");
      const selected = count(coverage, "selected");
      const completed = count(coverage, "completed") || 0;
      const failed = count(coverage, "failed") || 0;
      const reused = count(coverage, "reused_functions") || 0;
      const removed = count(coverage, "removed") || 0;
      const deferred = count(coverage, "deferred") || 0;
      const refreshed = field(coverage, "refresh") !== undefined;
      if (failed) facts.push(`${plural(failed, "function")} failed`);
      if (removed) facts.push(`${plural(removed, "function")} removed`);
      if (deferred)
        facts.push(`${plural(deferred, "function")} over the limit`);
      return {
        summary: refreshed
          ? `Refreshed: analysed ${completed - reused} again, reused ${reused}`
          : selected !== undefined
            ? `Analysed ${completed} of ${plural(selected, "function")}`
            : "Audit context saved",
        facts,
        tone: failed ? "warm" : undefined,
      };
    }
    case "finding_artifacts": {
      const state = field(r, "artifact_state");
      const status = text(state, "status");
      const missing = list(state, "missing").length;
      const version = text(state, "vulnerable_version");
      if (version) facts.push(`Vulnerable version ${version}`);
      if (missing) facts.push(`${plural(missing, "file")} missing`);
      return {
        summary:
          status === "complete"
            ? "Artifact bundle is complete"
            : `Artifact bundle is ${humanize(status || "saved").toLowerCase()}`,
        facts,
        tone: status === "complete" ? undefined : "warm",
      };
    }
    case "lab_run": {
      const exit = count(r, "exit_code");
      const version = text(r, "vulnerable_version");
      if (exit !== undefined) facts.push(`PoC exit code ${exit}`);
      if (version) facts.push(`Against version ${version}`);
      return field(r, "verified") === true
        ? { summary: "Reproduced: the Proof reproduced in the Lab", facts }
        : {
            summary: "Not reproduced: the Proof did not reproduce",
            facts,
            tone: "warm",
          };
    }
    case "detection_rule": {
      if (field(r, "current") === false)
        return { summary: "Validated an earlier revision", facts };
      const failed = text(
        list(r, "checks").find((c) => field(c, "status") === "failed"),
        "name",
      );
      return failed
        ? {
            summary: `Detection rule failed: ${detectionChecks[failed] || humanize(failed)}`,
            facts,
            tone: "warm",
          }
        : { summary: "Detection rule validated", facts };
    }
    case "patch_drafting":
    case "remediation_draft": {
      const hash = text(r, "diff_sha256");
      if (hash) facts.push(`Diff SHA-256 ${hash.slice(0, 12)}…`);
      return field(r, "current") === false
        ? { summary: "Drafted; a later draft replaced it", facts }
        : {
            summary: `${humanize(text(r, "action") || "Remediation PR")} drafted: ready for Approval`,
            facts,
          };
    }
    case "remediation_pr": {
      const branch = text(r, "branch");
      if (branch) facts.push(`Branch ${branch}`);
      return {
        summary: `Opened draft pull request #${count(r, "pull_number") ?? "?"}`,
        facts,
      };
    }
    case "notification": {
      const status = text(r, "status");
      return status === "delivered"
        ? { summary: "Delivered to Discord", facts }
        : status === "disabled"
          ? {
              summary: "Not sent: the Discord webhook is disabled",
              facts,
              tone: "neutral",
            }
          : { summary: humanize(status || "processed"), facts };
    }
    case "account_capabilities": {
      const models = list(r, "models").length;
      const errors = list(r, "capability_errors").length;
      if (errors) facts.push(`${plural(errors, "capability check")} failed`);
      return {
        summary: `${plural(models, "model")} available`,
        facts,
        tone: errors ? "warm" : undefined,
      };
    }
    case "account_check":
    case "account_login": {
      const status = text(r, "status");
      return {
        summary:
          status === "ready"
            ? "Connection is ready"
            : status === "signed_in"
              ? "Signed in"
              : humanize(status || "completed"),
        facts,
      };
    }
    case "credential_cleanup":
      return {
        summary:
          text(r, "status") === "deleted"
            ? "Temporary runtime credentials deleted"
            : "Cleanup completed",
        facts,
      };
  }
  return { summary: "Completed", facts };
}
/** What to do about a failure, keyed by the API's error code. */
const failureHints: Record<string, string> = {
  source_not_checked:
    "Run a source check for this application first, then retry this job.",
  source_snapshot_limit:
    "The application source is larger than the bounded snapshot. Narrow the source path or focus, then retry.",
  audit_scope_limit:
    "Orientation selected too many functions. Narrow the audit focus, then retry.",
  broker_unavailable:
    "The runner broker could not be reached. Check that the runner-broker service is healthy, then retry.",
  broker_error:
    "The runner broker rejected the request. Check its logs and the runtime configuration.",
  workload_failed:
    "The agent workload stopped early. Review the job's agent session and execution events; if it repeats, check the connection and model.",
  runtime_error:
    "The runtime failed. Check the runtime configuration and provider access for this connection.",
  timeout:
    "The workload hit its execution deadline. Retry with a faster model or lower reasoning effort.",
  incomplete_bundle:
    "The agent's finding bundle was missing required files. Retry, or choose a stronger model.",
  invalid_agent_output:
    "The agent's final output did not match the expected format. Retry the job.",
  missing_context_entry:
    "The agent did not return the required report file. Retry the job.",
  recipe_validation_failed:
    "The generated recipe failed its fixture checks. Retry to generate a new recipe.",
  credential_required:
    "Add credentials or finish the native login for this connection, then run the check again.",
  input_changed:
    "The connection's credentials changed after this job was queued. Run the check again.",
  cve_selectors_required:
    "Add product or CPE selectors to the application, then retry.",
  upstream_error:
    "The upstream source refused the request. Check the source URL and access, then retry.",
  source_unavailable:
    "The upstream source could not be reached. A retry resumes from the retained cursor.",
  internal_job_error:
    "An unexpected error stopped the job and no output was published. Check the job's execution events.",
  cancelled: "The operator cancelled this job.",
  api_key_required:
    "Automated runs use only Provider accounts that hold an API key. Select an API-key account for this operation, or start the run by hand.",
  triage_codex_unsupported:
    "Triage cannot run on Codex. Choose Pi, Claude or Jev for Triage in the Application settings.",
  analysis_codex_unsupported:
    "Analysis and CVE analysis cannot run on Codex, which always has a shell. Choose Pi or Claude Code for this operation in the Application settings or the default profiles.",
  github_write_token_required:
    "Add a GitHub write token under Settings → Integrations, then approve again.",
  verdict_not_allowed:
    "Served content can only be Malicious change, Security hardening, Unrelated or Insufficient context. Retry the Analysis.",
};
const labFailure =
  "A Lab is not retried: fix the cause, then start a new Lab from its Finding with a new Approval.";
const remediationFailure =
  "A Remediation PR is not retried: fix the cause, then approve it again from its Finding.";
const draftFailure =
  "A draft is not retried: fix the cause, then draft it again from its Finding.";
const analysisTimeout =
  "Analysis stopped at its 30-minute deadline. The change stays pending and is never read as Unrelated. Retry, or choose a faster model or lower reasoning effort.";
const failureActions: Record<
  string,
  (job: Job) => { label: string; to: string } | undefined
> = {
  source_not_checked: (job) =>
    job.application_id
      ? { label: "Open application", to: `/applications/${job.application_id}` }
      : undefined,
  cve_selectors_required: (job) =>
    job.application_id
      ? {
          label: "Edit application",
          to: `/applications/${job.application_id}/edit`,
        }
      : undefined,
  credential_required: () => ({
    label: "Open connections",
    to: "/settings?tab=accounts",
  }),
  input_changed: () => ({
    label: "Open connections",
    to: "/settings?tab=accounts",
  }),
  api_key_required: () => ({
    label: "Open connections",
    to: "/settings?tab=accounts",
  }),
  triage_codex_unsupported: (job) =>
    job.application_id
      ? {
          label: "Edit application",
          to: `/applications/${job.application_id}/edit`,
        }
      : undefined,
  analysis_codex_unsupported: (job) =>
    job.application_id
      ? {
          label: "Edit application",
          to: `/applications/${job.application_id}/edit`,
        }
      : undefined,
  github_write_token_required: () => ({
    label: "Open integrations",
    to: "/settings?tab=integrations",
  }),
  runtime_error: () => ({
    label: "Open connections",
    to: "/settings?tab=accounts",
  }),
};
export type Tone = "good" | "danger" | "warm" | "info" | "neutral";
export type JobOutcome = {
  tone: Tone;
  summary: string;
  /** What to do next, for failures. */
  hint?: string;
  facts: string[];
  action?: { label: string; to: string };
};
/** A plain-language account of where a job stands and what it produced. */
export function jobOutcome(job: Job): JobOutcome {
  const stage = text(job.progress, "stage");
  const progress = text(job.progress, "status");
  switch (job.status) {
    case "queued":
      return {
        tone: "info",
        summary: "Waiting for a worker to start it",
        facts: [],
      };
    case "running":
      return {
        tone: "info",
        summary: stage
          ? `Running · ${humanize(stage)}${progress && progress !== "running" ? ` · ${progress}` : ""}`
          : "Running",
        facts: [],
      };
    case "cancelling":
      return {
        tone: "warm",
        summary: "Stopping the workload; partial output will be kept",
        facts: [],
      };
    case "cancelled":
      return {
        tone: "neutral",
        summary: job.result
          ? "Cancelled · partial output was kept"
          : "Cancelled before it produced output",
        facts: [],
      };
    case "failed": {
      const code = text(job.error, "code") || "";
      const retryable = field(job.error, "retryable") === true;
      // A Lab or Remediation PR is never retried (A15): each needs its own
      // Approval. A Remediation PR draft is drafted again from its Finding.
      const lab = job.kind === "lab_run";
      const pr = job.kind === "remediation_pr";
      const draft = ["patch_drafting", "remediation_draft"].includes(job.kind);
      const facts = [
        ...(code ? [`Error code ${code}`] : []),
        ...(stage ? [`Stopped during ${humanize(stage).toLowerCase()}`] : []),
        ...(lab || pr || draft
          ? []
          : [
              retryable
                ? "Temporary: retrying should work"
                : "Fix the cause before retrying",
            ]),
      ];
      return {
        tone: "danger",
        summary: sentence(jobError(job)),
        hint:
          (lab
            ? labFailure
            : pr || draft
              ? failureHints[code] || (pr ? remediationFailure : draftFailure)
              : job.kind === "commit_analysis" &&
                  ["timeout", "runtime_timeout"].includes(code)
                ? analysisTimeout
                : failureHints[code]) ||
          (retryable
            ? "This failure is temporary. Retry the job."
            : "Check the job's execution events for the cause before retrying."),
        facts,
        action: failureActions[code]?.(job),
      };
    }
    case "succeeded": {
      const { summary, facts, tone } = successSummary(job);
      const took = duration(job.started_at, job.finished_at);
      return {
        tone: tone || "good",
        summary,
        facts: took ? [...facts, `Took ${took}`] : facts,
      };
    }
  }
  return { tone: "neutral", summary: humanize(job.status), facts: [] };
}
