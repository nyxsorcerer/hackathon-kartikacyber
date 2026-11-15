import { z } from "zod";
export const profileSchema = z.object({
  agent: z.enum(["pi", "claude", "codex"]),
  connection_id: z.string(),
  model_id: z.string(),
  reasoning_effort: z.string().nullable(),
});
export type Profile = z.infer<typeof profileSchema>;
export const operations = [
  "commit_triage",
  "commit_analysis",
  "version_recipe",
  "audit_context",
  "cve_analysis",
  "finding_artifacts",
  "patch_drafting",
] as const;
export type Operation = (typeof operations)[number];
export const operationNames: Record<Operation, string> = {
  commit_triage: "Commit triage",
  commit_analysis: "Commit analysis",
  version_recipe: "Version recipe",
  audit_context: "Audit context",
  cve_analysis: "CVE analysis",
  finding_artifacts: "Finding artifacts",
  patch_drafting: "Patch drafting",
};
const unknownRecord = z.record(z.string(), z.unknown());
export const modelSchema = z.object({
  id: z.string(),
  name: z.string(),
  reasoning_efforts: z.array(z.string()),
  default_effort: z.string().nullable(),
});
export const accountSchema = z.object({
  id: z.string(),
  label: z.string(),
  provider: z.string(),
  auth_type: z.string(),
  supported_agents: z.array(z.string()),
  status: z.string(),
  credential_configured: z.boolean(),
  models: z.array(modelSchema),
  agent_models: z.record(z.string(), z.array(modelSchema)).optional(),
  usage: z.unknown().nullable().optional(),
  last_checked_at: z.string().nullable().optional(),
  error: z.unknown().optional(),
  capability_errors: z.unknown().optional(),
  selection_error: z.string().nullable().optional(),
});
export type Account = z.infer<typeof accountSchema>;
export const artifactSchema = z.object({
  id: z.string(),
  path: z.string(),
  size: z.number(),
  sha256: z.string(),
  content_type: z.string().optional(),
});
export type Artifact = z.infer<typeof artifactSchema>;
export const versionSchema = z.object({
  id: z.string(),
  status: z.string(),
  version: z.string().nullable().optional(),
  candidates: z.array(z.string()).optional(),
  method: z.string().optional(),
  evidence: z.unknown().optional(),
  confidence: z.unknown().optional(),
  limitations: z.array(z.string()).optional(),
  checked_at: z.string().optional(),
  origin: z.string().optional(),
  recipe_id: z.string().nullable().optional(),
  application_id: z.string().optional(),
  source_generation: z.number().optional(),
  profile: profileSchema.nullable().optional(),
  error: z.unknown().optional(),
});
export const configSchema = z
  .object({
    triage_mode: z.string().default("disabled"),
    profiles: z.record(z.string(), profileSchema).default({}),
    cve_selectors: z
      .array(
        z
          .object({ type: z.enum(["cpe", "keyword"]), value: z.string() })
          .passthrough(),
      )
      .default([]),
    cve_min_score: z.number().nullable().optional(),
    cve_versions: z.array(z.string()).default([]),
    cve_auto_analyze: z.boolean().default(false),
    // Applications saved before this setting existed keep it off.
    audit_auto_refresh: z.boolean().default(false),
    active_recipe_id: z.string().nullable().optional(),
    version_scheme: z.enum(["semver", "php", "unknown"]).optional(),
    version_monitor_enabled: z.boolean().optional(),
    asset_origins: z.array(z.string()).optional(),
    jev_connection_id: z.string().nullable().optional(),
    jev_model_id: z.string().nullable().optional(),
    monitor_interval_inherited: z.boolean().optional(),
  })
  .passthrough();
/** B02: an Own repository's Push webhook. Its push id and secret are shown once, never here. */
export const pushWebhookSchema = z.object({
  created_at: z.string(),
  last_accepted: z
    .object({
      at: z.string(),
      event: z.enum(["push", "ping"]),
      delivery_id: z.string(),
    })
    .nullable(),
  // reason: wrong_signature, event_not_accepted, delivery_id_missing, body_too_large, rate_limited.
  last_refusal: z.object({ at: z.string(), reason: z.string() }).nullable(),
});
/** Set up and Regenerate: the path to append to the Public tunnel's URL and the secret, once. */
export const pushWebhookSecretSchema = z.object({
  path: z.string(),
  secret: z.string(),
});
export type PushWebhookSecret = z.infer<typeof pushWebhookSecretSchema>;
/** An Own or Upstream repository as one Application links it. */
export const repositoryLinkSchema = z.object({
  repository_id: z.string(),
  role: z.enum(["own", "upstream"]),
  enabled: z.boolean(),
  removed_at: z.string().nullable(),
  locked_version: z.string().nullable(),
  locked_version_source: z.string().nullable(),
  release_branch: z.string().nullable(),
  // "unknown" is shown as "release branch unknown".
  release_branch_status: z.enum(["pending", "matched", "unknown"]).nullable(),
  // A derived Upstream link: the packages it stands for ("npm:react"); hand-added links: [].
  packages: z.array(z.string()).default([]),
  source_kind: z.enum(["github", "wordpress"]),
  source_url: z.string(),
  plugin_slug: z.string().nullable(),
  source_ref: z.string().nullable(),
  source_path: z.string().nullable(),
  cursor: z.string().nullable(),
  baseline_revision: z.string().nullable(),
  last_check_at: z.string().nullable(),
  last_error: z.unknown().nullable(),
  push_webhook: pushWebhookSchema.nullable().default(null),
});
export type RepositoryLink = z.infer<typeof repositoryLinkSchema>;
export const applicationSchema = z.object({
  id: z.string(),
  asset_name: z.string(),
  asset_url: z.string(),
  product_kind: z.string(),
  product_name: z.string(),
  monitor_interval_seconds: z.number().nullable(),
  monitor_enabled: z.boolean(),
  archived: z.boolean(),
  source_generation: z.number(),
  last_check_at: z.string().nullable(),
  next_check_at: z.string().nullable(),
  repositories: z.array(repositoryLinkSchema).default([]),
  // Direct dependencies of the Own repository with no GitHub source repository.
  unresolved_dependencies: z
    .array(
      z.object({
        ecosystem: z.enum(["npm", "composer"]),
        name: z.string(),
        version: z.string().nullable(),
        reason: z.string(),
      }),
    )
    .default([]),
  version: versionSchema.nullable(),
  latest_version_check: versionSchema.nullable().optional(),
  config: configSchema,
});
export type Application = z.infer<typeof applicationSchema>;
export function repositoryLabel(repository: RepositoryLink) {
  return repository.source_kind === "wordpress"
    ? `WordPress · ${repository.plugin_slug}`
    : repository.source_url.replace("https://github.com/", "");
}
/** Polled repositories whose last check failed. */
export function failingRepositories(application: Application) {
  return application.repositories.filter(
    (r) => r.enabled && !r.removed_at && r.last_error,
  );
}
export function applicationState(application: Application) {
  return application.archived
    ? "archived"
    : failingRepositories(application).length
      ? "error"
      : application.monitor_enabled
        ? "monitoring"
        : "paused";
}
/** The outcome of Analysis, in the glossary's words. */
export const verdicts = [
  "Vulnerability fix",
  "Vulnerability introduced",
  "Malicious change",
  "Security hardening",
  "Unrelated",
  "Insufficient context",
] as const;
/** The Verdicts that open a Finding with a drafted Proof bundle. */
export const findingVerdicts: string[] = verdicts.slice(0, 2);
const analysisResultSchema = z
  .object({
    verdict: z.string().optional(),
    // low|medium|high; "unknown" for Verdicts carried over from Numen. CVE analysis keeps an object.
    confidence: z.union([z.string(), unknownRecord]).optional(),
    // Commit SHAs or advisory ids the change addresses.
    addresses: z.array(z.string()).optional(),
    title: z.string().optional(),
    vulnerable_ref: z.string().nullable().optional(),
    summary: z.string().optional(),
    report: z.string().optional(),
    finding_id: z.string().nullable().optional(),
    /** The finding this analysis created was later deleted. */
    finding_removed: z.boolean().optional(),
  })
  .passthrough();
export const analysisSchema = z
  .object({
    id: z.string().optional(),
    job_id: z.string().optional(),
    superseded: z.boolean().optional(),
    summary: z.string().optional(),
    created_at: z.string().optional(),
    profile: profileSchema.optional(),
    report: z.string().optional(),
    result: analysisResultSchema.optional(),
    artifacts: z.array(artifactSchema).optional(),
    /** False for an Upstream Proof, which is never exported (A15): only its reports are shown. */
    exportable: z.boolean().optional(),
  })
  .passthrough();
export type Analysis = z.infer<typeof analysisSchema>;
/** Changed paths arrive as objects from source imports, or as bare paths. */
const commitFileSchema = z.union([
  z.string().transform((path) => ({
    path,
    status: null as string | null,
    previous_path: null as string | null,
  })),
  z.object({
    path: z.string(),
    status: z.string().nullable().optional().default(null),
    previous_path: z.string().nullable().optional().default(null),
  }),
]);
export type CommitFile = z.infer<typeof commitFileSchema>;
/** An Application's Exposure to an Upstream Verdict (A05), from release-tag containment. */
export const exposureSchema = z.object({
  application_id: z.string(),
  application_name: z.string().nullable().optional(),
  verdict: z.string(),
  /** unknown counts as exposed. */
  state: z.enum(["exposed", "not_exposed", "unknown"]),
  reason: z.string().nullable().optional(),
  locked_version: z.string().nullable().optional(),
  tag: z.string().nullable().optional(),
  /** The release a pin or bump moves to. */
  target: z
    .object({ tag: z.string(), version: z.string() })
    .nullable()
    .optional(),
});
export type Exposure = z.infer<typeof exposureSchema>;
export const exposureLabels: Record<Exposure["state"], string> = {
  exposed: "Exposed",
  not_exposed: "Not exposed",
  unknown: "Unknown (counts as exposed)",
};
export const exposureTones: Record<Exposure["state"], string> = {
  exposed: "danger",
  not_exposed: "good",
  unknown: "warm",
};
export const commitSchema = z.object({
  id: z.string(),
  repository_id: z.string().optional(),
  /** The first Application linking the commit's repository. */
  application_id: z.string().nullable(),
  revision: z.string(),
  message: z.string(),
  author: z.string().nullable().optional(),
  committed_at: z.string().nullable().optional(),
  url: z.string().nullable().optional(),
  files: z.array(commitFileSchema).default([]),
  diff: z.string().nullable().optional(),
  diff_complete: z.boolean(),
  triage_status: z.string(),
  triage_result: z.unknown().nullable(),
  review_decision: z.string(),
  /** The newest Analysis's Verdict. */
  verdict: z.string().nullable().default(null),
  /** Where the latest Analysis stands: queued, waiting_for_cap, timed_out, blocked, failed, completed. */
  analysis_state: z
    .object({
      status: z.string(),
      since: z.string().optional(),
      cap: z.string().optional(),
      job_id: z.string().optional(),
      error: z.unknown().optional(),
    })
    .nullable()
    .default(null),
  /** Pre-filter flags: each rule the change matched and the paths that matched it. */
  prefilter: z
    .array(z.object({ rule: z.string(), paths: z.array(z.string()) }))
    .default([]),
  analyses: z.array(analysisSchema).default([]),
  /** Findings this revision opened (source) or was linked to (linked), in every Application. */
  findings: z
    .array(
      z.object({
        id: z.string(),
        title: z.string(),
        status: z.string(),
        source: z.string().optional(),
        application_id: z.string(),
        application_name: z.string(),
        relation: z.enum(["source", "linked"]).optional(),
      }),
    )
    .default([]),
  /** Each Application's Exposure to this Upstream Verdict, not-exposed ones included (A05). */
  exposures: z.array(exposureSchema).default([]),
});
export type Commit = z.infer<typeof commitSchema>;
/** One decision applied to many revisions; `previous` lets the change be undone. */
export const reviewBatchSchema = z.object({
  items: z.array(
    z.object({
      id: z.string(),
      previous: z.string(),
      review_decision: z.string(),
    }),
  ),
});
/** Most revisions one batch analysis may queue; each runs as its own agent job. */
export const analysisBatchMax = 50;
export const analysisBatchSchema = z.object({
  items: z.array(
    z.object({
      id: z.string(),
      job_id: z.string().nullable(),
      // historical_source: from an earlier source generation; analysis_active: already queued.
      skipped: z.string().nullable(),
    }),
  ),
});
export const findingDeletionSchema = z.object({ deleted: z.array(z.string()) });
export const promptTemplateSchema = z.object({
  name: z.string(),
  // An operation renders a job's prompt; a section is shared by the operations including it.
  kind: z.enum(["operation", "section"]),
  description: z.string(),
  source: z.string(),
  default_source: z.string(),
  customized: z.boolean(),
  updated_at: z.string().nullable(),
  default_changed: z.boolean(),
  includes: z.array(z.string()),
  used_by: z.array(z.string()),
});
export type PromptTemplate = z.infer<typeof promptTemplateSchema>;
export const promptTemplatesSchema = z.object({
  items: z.array(promptTemplateSchema),
  variables: z.record(z.string(), z.string()),
});
export const promptPreviewSchema = z.object({
  prompt: z.string(),
  templates: z.array(z.string()),
});
export const scoreSchema = z.object({
  version: z.string(),
  base_score: z.number(),
  vector: z.string(),
  source: z.string(),
});
export const cveSchema = z.object({
  id: z.string(),
  application_id: z.string(),
  title: z.string(),
  description: z.string(),
  published_at: z.string().nullable().optional(),
  modified_at: z.string().nullable().optional(),
  scores: z.array(
    z.object({
      version: z.string(),
      base_score: z.number(),
      vector: z.string(),
      source: z.string(),
    }),
  ),
  match_status: z.string(),
  eligible: z.boolean(),
  eligibility_reason: z.string().nullable().optional(),
  qualifying_score: scoreSchema.nullable().optional(),
  applicability: z.string(),
  affected_versions: z.array(z.string()).default([]),
  fixed_versions: z.array(z.string()).default([]),
  references: z.array(z.unknown()).default([]),
  analyses: z.array(analysisSchema).default([]),
  analysis_blocked: z
    .object({ code: z.string(), message: z.string() })
    .nullable()
    .optional(),
});
export type CVE = z.infer<typeof cveSchema>;
/** A07's Detection rule validation checks, in the order application code runs them. */
export const detectionChecks: Record<string, string> = {
  rule: "Rule compiles",
  changed: "Matches a file the commit changed",
  parent: "Matches nothing in the parent tree",
  baseline: "Matches nothing in the Baseline",
};
/** The same checks of a served-content change's rule, scanned against stored fetches. */
export const servedDetectionChecks: Record<string, string> = {
  ...detectionChecks,
  changed: "Matches the changed fetch",
  parent: "Matches nothing in the previous fetch",
  baseline: "Matches nothing in the Baseline fetch",
};
/** A Malicious change's static Proof: its Detection rule, checked indicators and validation. */
export const staticProofSchema = z.object({
  analysis_id: z.string().optional(),
  artifact_revision: z.string().optional(),
  rule: z.string().nullable().default(null),
  status: z.enum(["pending", "validated", "failed"]).default("pending"),
  checks: z
    .array(
      z.object({
        name: z.string(),
        status: z.enum(["passed", "failed", "skipped"]),
        message: z.string(),
        files: z.array(z.string()).default([]),
        count: z.number().optional(),
      }),
    )
    .default([]),
  indicators: z
    .object({
      files: z.array(z.object({ path: z.string(), sha256: z.string() })),
      hosts: z.array(z.string()),
      urls: z.array(z.string()),
      commands: z.array(z.string()),
      rejected: z.array(
        z.object({ kind: z.string(), value: z.string(), reason: z.string() }),
      ),
    })
    .optional(),
  job_id: z.string().nullable().optional(),
});
export type StaticProof = z.infer<typeof staticProofSchema>;
/** What a Malicious change's cleanup report adds to its indicators; application code computes it. */
export const cleanupReportSchema = z.object({
  commits: z
    .array(z.object({ revision: z.string(), commit_id: z.string().nullable() }))
    .default([]),
  commits_truncated: z.boolean().default(false),
  // null: unknown, such as a WordPress plugin or tags that could not be read.
  releases: z.array(z.string()).nullable().default(null),
  // Served content's (A10): the Watched page and user agent, and the fetches that served the change.
  page_url: z.string().optional(),
  user_agent: z.string().optional(),
  fetch_ids: z.array(z.string()).default([]),
  first_seen: z.string().optional(),
  secrets: z.array(z.string()),
});
export type CleanupReport = z.infer<typeof cleanupReportSchema>;
/** A Remediation PR (A08): its validated draft diff, its Approval and the pull request it opened. */
export const remediationPRSchema = z.object({
  id: z.string(),
  action: z.enum(["patch", "revert", "pin", "bump"]),
  /** drafting, waiting_for_cap, draft_failed, ready, approved, failed, open, merged or closed */
  status: z.string(),
  base_ref: z.string().nullable().optional(),
  branch: z.string().nullable().optional(),
  diff: z.string().nullable().optional(),
  diff_sha256: z.string().nullable().optional(),
  paths: z.array(z.string()).default([]),
  flags: z.array(z.string()).default([]),
  summary: z.string().nullable().optional(),
  error: z.unknown().optional(),
  job_id: z.string().nullable().optional(),
  pull_number: z.number().nullable().optional(),
  pull_url: z.string().nullable().optional(),
  merge_commit_sha: z.string().nullable().optional(),
  /** A commit id, or an Advisory check's vulnerability id. */
  subject: z.string().optional(),
  /** What a pin or bump moves to: packages to `version` (each to its own in `versions`), or a
   * runtime's pins through its `edits`. */
  dependency: z
    .object({
      ecosystem: z.string().optional(),
      name: z.string().optional(),
      version: z.string().nullish(),
      versions: z.record(z.string(), z.string()).optional(),
      edits: z
        .array(
          z.object({ source: z.string(), from: z.string(), to: z.string() }),
        )
        .optional(),
    })
    .nullable()
    .optional(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type RemediationPR = z.infer<typeof remediationPRSchema>;
const pinExposureSchema = z.enum(["exposed", "not_exposed", "unknown"]);
/** A runtime or package pin the Advisory check collected (A09). A null version cannot be read:
 * its `reason` says why and its Exposure is unknown, which counts as exposed. */
export const advisoryPinSchema = z.object({
  name: z.string(),
  version: z.string().nullable(),
  source: z.string(),
  reason: z.string().nullable().optional(),
  /** A runtime's: dockerfile, nvmrc, engines or platform, and a Dockerfile's image and tag. */
  field: z.string().optional(),
  image: z.string().nullable().optional(),
  tag: z.string().nullable().optional(),
  /** A package's. */
  ecosystem: z.string().nullable().optional(),
  direct: z.boolean().optional(),
  /** null until a feed answers. */
  exposure: pinExposureSchema.nullable(),
});
export type AdvisoryPin = z.infer<typeof advisoryPinSchema>;
/** Each feed's affected ranges: lists of [operator, version] comparators, any one of which holds. */
const advisoryRangesSchema = z.record(
  z.string(),
  z.array(z.array(z.tuple([z.string(), z.string()]))),
);
export type AdvisoryRanges = z.infer<typeof advisoryRangesSchema>;
/** One (Application, vulnerability) match of the Advisory check, its OSV, GHSA and CVE aliases as one. */
export const advisoryMatchSchema = z.object({
  id: z.string(),
  vulnerability: z.string(),
  aliases: z.array(z.string()),
  state: pinExposureSchema,
  finding_id: z.string().nullable(),
  summary: z.string().nullable().optional(),
  severity: z.string().nullable().optional(),
  feeds: z.array(z.string()).default([]),
  pins: z
    .array(
      z.object({
        kind: z.string(),
        ecosystem: z.string().nullable(),
        name: z.string(),
        version: z.string(),
        sources: z.array(z.string()),
        ranges: advisoryRangesSchema,
        state: pinExposureSchema,
      }),
    )
    .default([]),
  updated_at: z.string().nullable().optional(),
});
export type AdvisoryMatch = z.infer<typeof advisoryMatchSchema>;
/** GET /applications/{id}/advisories: the pins the last Advisory check collected, and its matches. */
export const advisoriesSchema = z.object({
  repository_id: z.string().nullable(),
  revision: z.string().nullable(),
  collected_at: z.string().nullable(),
  feeds: z.record(
    z.string(),
    z.object({ records: z.number().optional(), error: z.unknown().optional() }),
  ),
  runtimes: z.array(advisoryPinSchema),
  packages: z.array(advisoryPinSchema),
  matches: z.array(advisoryMatchSchema).default([]),
});
/** What changed from one Content fingerprint's summary to another, by summary key. */
const servedDiffSchema = z.record(
  z.string(),
  z.object({ added: z.array(z.string()), removed: z.array(z.string()) }),
);
export type ServedDiff = z.infer<typeof servedDiffSchema>;
/** One user agent's fetch of a Watched page in a Served-content check (A10). */
const servedFetchSchema = z.object({
  id: z.string(),
  /** fetched, or failed: the page did not answer 200. */
  status: z.string(),
  fingerprint: z.string().nullable(),
  created_at: z.string(),
  error: z
    .object({
      status: z.number().nullable().optional(),
      error: z.string().nullable().optional(),
    })
    .nullable(),
});
export type ServedFetch = z.infer<typeof servedFetchSchema>;
/** A fingerprint unlike the Baseline, triaged at most once, with its Analysis and Finding. */
export const servedChangeSchema = z.object({
  id: z.string(),
  triage_status: z.string(),
  triage_result: unknownRecord.nullable(),
  review_decision: z.string(),
  verdict: z.string().nullable(),
  analysis_state: z.object({ status: z.string() }).passthrough().nullable(),
  finding_id: z.string().nullable(),
});
export type ServedChange = z.infer<typeof servedChangeSchema>;
/** GET /applications/{id}/watched-pages: each page with each user agent's latest fetch and Baseline. */
export const watchedPageSchema = z.object({
  id: z.string(),
  url: z.string(),
  homepage: z.boolean(),
  user_agents: z.array(
    z.object({
      user_agent: z.string(),
      latest: servedFetchSchema.nullable(),
      baseline: z.object({ fetch_id: z.string(), fingerprint: z.string() }).nullable(),
      state: z.enum(["awaiting_baseline", "matches", "changed", "failed"]),
      diff: servedDiffSchema.nullable(),
      change: servedChangeSchema.nullable(),
      accept_allowed: z.boolean(),
    }),
  ),
});
export type WatchedPage = z.infer<typeof watchedPageSchema>;
export const watchedPagesSchema = z.object({ items: z.array(watchedPageSchema) });
export const userAgentLabels: Record<string, string> = {
  browser: "Browser",
  googlebot: "Googlebot",
};
/** The stored record of one Triage or Analysis run, with secrets removed (A14). */
export const transcriptSummarySchema = z.object({
  id: z.string(),
  kind: z.enum(["triage", "analysis"]),
  job_id: z.string(),
  subject_id: z.string(),
  /** The Analysis, and so the Verdict, an Analysis Transcript belongs to. */
  analysis_id: z.string().nullable(),
  status: z.string().nullable(),
  created_at: z.string(),
});
export const transcriptSchema = transcriptSummarySchema.extend({
  text: z.string(),
});
const serverFileSchema = z.object({ root: z.string(), path: z.string(), sha256: z.string() });
export const findingSchema = z.object({
  id: z.string(),
  application_id: z.string(),
  source: z.enum(["commit", "served_content", "advisory", "cve", "server_files"]),
  /** Short SHA, Watched page or advisory id of what opened the Finding. */
  source_ref: z.string().nullable().optional(),
  cve_id: z.string().nullable(),
  title: z.string(),
  status: z.enum(["open", "confirmed", "dismissed", "remediated"]),
  /** Who or what set the current status, and when. */
  cause: unknownRecord.nullable().optional(),
  /** Shown apart from the lifecycle: before_fix, serving_fix or unknown (A06). */
  deployed_version: z.string().default("unknown"),
  /** The last Deployed version check of an Own-repository Vulnerability fix. */
  deployed_version_check: z
    .object({
      state: z.string(),
      version: z.string().nullable().optional(),
      reason: z.string().nullable().optional(),
      observation_id: z.string().nullable().optional(),
      checked_at: z.string().optional(),
    })
    .nullable()
    .optional(),
  // Findings created by a commit analysis may not record version ranges yet.
  affected_versions: z.array(z.union([z.string(), unknownRecord])).default([]),
  fixed_versions: z.array(z.union([z.string(), unknownRecord])).default([]),
  target_applicability: z.string(),
  evidence: z.array(z.unknown()).default([]),
  source_commit_id: z.string().nullable().optional(),
  source_analysis_id: z.string().nullable().optional(),
  artifact_revision: z.string().nullable().optional(),
  events: z.array(unknownRecord).optional(),
  artifact_state: z.object({
    status: z.enum(["draft", "complete"]),
    missing: z.array(z.string()),
    limitations: z.array(z.string()),
    vulnerable_version: z.string().nullable(),
  }),
  artifacts: z.array(artifactSchema),
  /** False for an Upstream Finding, whose Proof is never exported (A15). */
  exportable: z.boolean().default(true),
  lab_runs: z.array(unknownRecord),
  /** A Malicious change never runs: no Lab and no Lab bundle generation (ADR-0004). */
  malicious_change: z.boolean().default(false),
  static_proof: staticProofSchema.nullable().optional(),
  cleanup_report: cleanupReportSchema.nullable().optional(),
  /** An exposed Upstream Malicious change's Detection rule run over the Application's stored served content (A06). */
  served_content_sweep: z
    .object({
      job_id: z.string(),
      status: z.string(),
      truncated: z.boolean(),
      matches: z.array(
        z.object({
          page_url: z.string(),
          user_agent: z.string(),
          url: z.string().nullable(),
          sha256: z.string(),
          fetched_at: z.string(),
        }),
      ),
    })
    .nullable()
    .optional(),
  /** The steps of the Finding's A06 Playbook cell and where each stands; [] without a cell. */
  playbook: z
    .array(z.object({ step: z.string(), status: z.string() }))
    .default([]),
  /** Its Application's Exposure to the Upstream commit that opened it. */
  exposure: exposureSchema.nullable().optional(),
  /** Shown for the Operator to copy into the Upstream repository's reporting form; never sent. */
  disclosure_report: z
    .object({ text: z.string(), form_url: z.string().nullable() })
    .nullable()
    .optional(),
  /** The Advisory check matches attached to it, each with its report as plain text. */
  advisories: z
    .array(advisoryMatchSchema.extend({ report: z.string() }))
    .default([]),
  /** Without one, the Remediation PR steps are skipped (A06). */
  own_repository: z.boolean().default(false),
  /** The drafts the Operator may start by hand: patch and/or revert, or a pin or bump. */
  remediation_actions: z.array(z.string()).default([]),
  remediation_prs: z.array(remediationPRSchema).default([]),
  /** The Triage and Analysis Transcripts of what it is about, oldest first (A14). */
  transcripts: z.array(transcriptSummarySchema).default([]),
  /** B07: the server files a server_files Finding names, and when a named SHA-256 was seen again. */
  server_files: z.array(serverFileSchema).optional(),
  regressed_at: z.string().nullable().optional(),
  /** B07: its Quarantine list and hash, each Quarantine and Restore command with the agent's verified result. */
  quarantine: z
    .object({
      agent_id: z.string().nullable(),
      agent_name: z.string().nullable(),
      agent_status: z.string().nullable(),
      list: z.array(serverFileSchema),
      list_sha256: z.string(),
      commands: z.array(
        z.object({
          id: z.string(),
          name: z.string(),
          sequence: z.number(),
          status: z.string(),
          reason: z.string().nullable().optional(),
          expires_at: z.string().nullable(),
          created_at: z.string(),
          list_sha256: z.string().optional(),
          entries_sha256: z.string().optional(),
          files: z.array(
            z.object({
              root: z.string().optional(),
              path: z.string().optional(),
              sha256: z.string().optional(),
              quarantine_id: z.string().optional(),
              status: z.string(),
              detail: z.string().optional(),
            }),
          ),
          restore: z
            .object({ entries: z.array(z.string()), entries_sha256: z.string() })
            .nullable()
            .optional(),
        }),
      ),
      quarantined: z.array(
        z.object({
          quarantine_id: z.string(),
          command_id: z.string(),
          root: z.string().nullable(),
          path: z.string().nullable(),
          sha256: z.string().nullable(),
        }),
      ),
    })
    .nullable()
    .optional(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type Finding = z.infer<typeof findingSchema>;
export const findingSummarySchema = findingSchema
  .pick({
    id: true,
    application_id: true,
    source: true,
    source_ref: true,
    cve_id: true,
    title: true,
    status: true,
    cause: true,
    deployed_version: true,
    malicious_change: true,
    affected_versions: true,
    fixed_versions: true,
    target_applicability: true,
    source_commit_id: true,
    source_analysis_id: true,
    artifact_revision: true,
    artifact_state: true,
    created_at: true,
    updated_at: true,
  })
  .extend({ lab_status: z.string().nullable() });
export type FindingSummary = z.infer<typeof findingSummarySchema>;
/** What a job acts on, resolved by the API into a label and dashboard link. */
export const jobSubjectSchema = z.object({
  type: z.string(),
  label: z.string(),
  detail: z.string().nullable().optional(),
  ref: z.string().nullable().optional(),
  link: z.string().nullable().optional(),
});
export type JobSubject = z.infer<typeof jobSubjectSchema>;
export const jobSchema = z.object({
  id: z.string(),
  kind: z.string(),
  application_id: z.string().nullable().optional(),
  application_name: z.string().nullable().optional(),
  subject: jobSubjectSchema.nullable().optional(),
  status: z.string(),
  progress: z.unknown(),
  profile: profileSchema.nullable().optional(),
  created_at: z.string(),
  started_at: z.string().nullable().optional(),
  finished_at: z.string().nullable().optional(),
  error: z.unknown().nullable(),
  result: z.unknown().nullable(),
  events: z.array(z.unknown()).default([]),
});
export type Job = z.infer<typeof jobSchema>;
export const settingsSchema = z
  .object({
    monitor_interval_seconds: z.number().nullable(),
    default_profiles: z.record(z.string(), profileSchema).default({}),
    webhook_enabled: z.boolean().default(false),
    webhook_configured: z.boolean().default(false),
    webhook_masked: z.string().nullable().optional(),
    dashboard_url: z.string().nullable().optional(),
  })
  .passthrough();
export type Settings = z.infer<typeof settingsSchema>;
export const pluginSchema = z.object({
  id: z.string(),
  name: z.string().optional(),
  source: z.string(),
  version: z.string().nullable().optional(),
  pinned_version: z.string().nullable().optional(),
  integrity: z.string().optional(),
  health: z.unknown(),
  provider: z.string().nullable().optional(),
  provider_contribution: z.unknown().optional(),
});
export const auditSchema = z.object({
  id: z.string(),
  source_ref: z.string(),
  source_generation: z.number().optional(),
  skill_revision: z.string(),
  coverage: z.unknown(),
  status: z.string(),
  created_at: z.string(),
  artifacts: z.array(artifactSchema),
  job_id: z.string().optional(),
});
export type AuditContextRecord = z.infer<typeof auditSchema>;
const auditUnitSchema = z
  .object({
    id: z.string().optional(),
    path: z.string().optional(),
    name: z.string().optional(),
  })
  .passthrough();
/** Progress and gaps recorded by each audit-context checkpoint. */
export const auditCoverageSchema = z
  .object({
    selected: z.number().optional(),
    completed: z.number().optional(),
    failed: z.number().optional(),
    omitted: z.number().optional(),
    // Functions whose file the refreshed revision deleted.
    removed: z.number().optional(),
    // Functions orientation selected beyond the limit, recorded but not analysed.
    deferred: z.number().optional(),
    deferred_units: z
      .array(z.object({ name: z.unknown(), path: z.unknown() }).passthrough())
      .optional(),
    reused_functions: z.number().optional(),
    resumed_from: z.string().optional(),
    // Present when this context refreshed an earlier one.
    refresh: z
      .object({
        from: z.string(),
        from_revision: z.string(),
        changed_files: z.array(z.string()).default([]),
        changed_files_total: z.number().default(0),
        removed_units: z
          .array(
            z.object({ name: z.unknown(), path: z.unknown() }).passthrough(),
          )
          .default([]),
      })
      .passthrough()
      .optional(),
    failed_units: z
      .array(
        z.object({ unit: auditUnitSchema, error: z.unknown() }).passthrough(),
      )
      .optional(),
    stage: z.string().optional(),
    scope: z.string().optional(),
    interrupted: z.boolean().optional(),
    error: z.unknown().optional(),
    reason: z.string().optional(),
  })
  .passthrough();
export type AuditCoverage = z.infer<typeof auditCoverageSchema>;
/** orientation.json: the significant functions chosen for analysis, in order. */
export const auditOrientationSchema = z
  .object({
    functions: z.array(auditUnitSchema).optional(),
    overview: z.string().optional(),
  })
  .passthrough();
export const sessionSchema = z.object({
  authenticated: z.boolean(),
  username: z.string().optional(),
  csrf_token: z.string().optional(),
});
export type Session = z.infer<typeof sessionSchema>;
export const dashboardSchema = z.object({
  applications: z.number(),
  security_reviews: z.number(),
  eligible_cves: z.number(),
  open_findings: z.number(),
  running_jobs: z.number(),
  failed_jobs: z.number(),
  recent_events: z.array(z.unknown()),
  due_applications: z.array(z.unknown()),
  /** The newest 20 changes of the Review queue, and how many it holds. */
  review_queue: z.array(
    z.object({
      id: z.string(),
      title: z.string(),
      revision: z.string(),
      application_id: z.string().nullable(),
      committed_at: z.string().nullable().optional(),
      /** Where a served-content change is judged; a commit has none and opens its own page. */
      link: z.string().optional(),
    }),
  ),
  review_queue_count: z.number(),
});
export const agentSessionSchema = z.object({
  runs: z.array(z.string()),
  run_id: z.string(),
  agent: z.string().nullable().optional(),
  agent_status: z.string(),
  screen: z.string(),
  held: z.boolean(),
  live: z.boolean().optional(),
});
export const jobAcceptedSchema = z.object({
  job_id: z.string(),
  status_url: z.string(),
});
/** Check now queues one source check per polled repository. */
export const checksAcceptedSchema = z.object({
  items: z.array(jobAcceptedSchema.extend({ repository_id: z.string() })),
});
export const listSchema = <T extends z.ZodType>(schema: T) =>
  z.object({ items: z.array(schema), next_cursor: z.string().nullable() });
export const recordsSchema = listSchema(unknownRecord);
export const loginStatusSchema = z.object({
  status: z.string(),
  job_id: z.string().nullable().optional(),
  events: z.array(z.unknown()).default([]),
  error: z.unknown().nullable().optional(),
});
export function readable(value: unknown): string {
  if (value === null || value === undefined) return "Unknown";
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}
export function safeHref(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const u = new URL(value, window.location.origin);
    return ["https:", "http:"].includes(u.protocol) ? u.href : undefined;
  } catch {
    return undefined;
  }
}
export const applicationsSchema = listSchema(applicationSchema);
export const accountsSchema = listSchema(accountSchema);
export const commitsSchema = listSchema(commitSchema);
export const cvesSchema = listSchema(cveSchema);
export const findingsSchema = listSchema(findingSchema);
export const findingSummariesSchema = listSchema(findingSummarySchema);
export const jobsSchema = listSchema(jobSchema);
export const pluginsSchema = listSchema(pluginSchema);
export const versionsSchema = listSchema(versionSchema);
export const auditsSchema = listSchema(auditSchema);

export const recipeSchema = z.object({
  id: z.string(),
  created_at: z.string(),
  status: z.string(),
  artifacts: z.array(artifactSchema),
  metadata: z.unknown(),
  profile: profileSchema.nullable().optional(),
  source_ref: z.string().nullable().optional(),
  source_generation: z.number().optional(),
});
export const recipesSchema = listSchema(recipeSchema);
/** B04: a configuration or Agent command signed for an On-server agent, and the agent's answer. */
export const agentMessageSchema = z.object({
  id: z.string(),
  type: z.string(),
  name: z.string().nullable(),
  sequence: z.number(),
  status: z.string(),
  reason: z.string().nullable(),
  result: z.record(z.string(), z.unknown()).nullable(),
  expires_at: z.string().nullable(),
  created_at: z.string(),
});
export type AgentMessage = z.infer<typeof agentMessageSchema>;
/** B05: one file or symbolic link of a File manifest, as the agent reported it. */
const manifestEntrySchema = z.object({
  root: z.string(),
  path: z.string(),
  type: z.string(),
  sha256: z.string().nullable(),
  size: z.number(),
  mode: z.number(),
  uid: z.number(),
  gid: z.number(),
  target: z.string().optional(),
  secret: z.boolean().optional(),
  over_hash_limit: z.boolean().optional(),
});
const incompleteSchema = z.array(
  z.object({
    reason: z.string(),
    root: z.string().optional(),
    path: z.string().optional(),
  }),
);
/** A Server change: a File manifest unlike the Baseline, with its Triage, Verdict and Finding. */
const serverChangeSchema = servedChangeSchema.extend({
  fingerprint: z.string(),
  diff: z.object({
    added: z.array(manifestEntrySchema),
    modified: z.array(
      z.object({ before: manifestEntrySchema, after: manifestEntrySchema }),
    ),
    removed: z.array(manifestEntrySchema),
  }),
  incomplete: incompleteSchema,
  // The SHA-256 values of its added and changed files whose bytes are held.
  held: z.array(z.string()),
  created_at: z.string(),
});
/** An On-server agent of an Application. Everything it reports is shown as text only. */
export const agentSchema = z.object({
  id: z.string(),
  name: z.string(),
  url: z.string(),
  // awaiting_enrollment, pending, enrolled or revoked
  status: z.string(),
  fingerprint: z.string().nullable(),
  key_id: z.string().nullable(),
  allowed_paths: z.array(z.string()),
  watched_roots: z.array(z.string()),
  version: z.string().nullable(),
  os: z.string().nullable(),
  arch: z.string().nullable(),
  last_seen_at: z.string().nullable(),
  last_refusal: z
    .object({ at: z.string(), route: z.string(), reason: z.string() })
    .nullable(),
  configuration: agentMessageSchema.nullable(),
  commands: z.array(agentMessageSchema),
  baseline: z
    .object({
      manifest_id: z.string(),
      sha256: z.string(),
      accepted_at: z.string().nullable(),
    })
    .nullable()
    .default(null),
  latest_manifest: z
    .object({
      id: z.string(),
      sequence: z.number(),
      sha256: z.string(),
      status: z.string(),
      file_count: z.number(),
      incomplete: incompleteSchema,
      created_at: z.string(),
    })
    .nullable()
    .default(null),
  accept_allowed: z.boolean().default(false),
  changes: z.array(serverChangeSchema).default([]),
});
export type Agent = z.infer<typeof agentSchema>;
export type ManifestEntry = z.infer<typeof manifestEntrySchema>;
export type ServerChange = z.infer<typeof serverChangeSchema>;
export const agentsSchema = z.object({
  agent_url: z.string(),
  items: z.array(agentSchema),
});
/** Add agent's answer: the enroll command and the one-time Enrollment code, shown once. */
export const enrollmentSchema = z.object({
  agent: agentSchema,
  enrollment: z.object({
    code: z.string(),
    command: z.string(),
    url: z.string(),
    tls_pin: z.string(),
    dashboard_key: z.string(),
    key_id: z.string(),
    agent_id: z.string(),
    expires_at: z.string(),
  }),
});
export type Enrollment = z.infer<typeof enrollmentSchema>["enrollment"];
