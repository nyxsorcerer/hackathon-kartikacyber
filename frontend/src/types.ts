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
] as const;
export type Operation = (typeof operations)[number];
export const operationNames: Record<Operation, string> = {
  commit_triage: "Commit triage",
  commit_analysis: "Commit analysis",
  version_recipe: "Version recipe",
  audit_context: "Audit context",
  cve_analysis: "CVE analysis",
  finding_artifacts: "Finding artifacts",
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
  program_id: z.string().optional(),
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
    active_recipe_id: z.string().nullable().optional(),
    version_scheme: z.enum(["semver", "php", "unknown"]).optional(),
    version_monitor_enabled: z.boolean().optional(),
    asset_origins: z.array(z.string()).optional(),
    jev_connection_id: z.string().nullable().optional(),
    jev_model_id: z.string().nullable().optional(),
    monitor_interval_inherited: z.boolean().optional(),
  })
  .passthrough();
export const programSchema = z.object({
  id: z.string(),
  asset_name: z.string(),
  asset_url: z.string(),
  product_kind: z.string(),
  product_name: z.string(),
  source_kind: z.enum(["github", "wordpress"]),
  source_url: z.string().nullable().optional(),
  source_ref: z.string().nullable().optional(),
  source_path: z.string().nullable().optional(),
  plugin_slug: z.string().nullable().optional(),
  monitor_interval_days: z.number().nullable(),
  monitor_enabled: z.boolean(),
  archived: z.boolean(),
  source_generation: z.number(),
  last_check_at: z.string().nullable(),
  next_check_at: z.string().nullable(),
  last_error: z.unknown().nullable(),
  version: versionSchema.nullable(),
  latest_version_check: versionSchema.nullable().optional(),
  config: configSchema,
});
export type Program = z.infer<typeof programSchema>;
export function programState(program: Program) {
  return program.archived
    ? "archived"
    : program.last_error
      ? "error"
      : program.monitor_enabled
        ? "monitoring"
        : "paused";
}
const analysisResultSchema = z
  .object({
    category: z.string().optional(),
    summary: z.string().optional(),
    report: z.string().optional(),
    finding_id: z.string().optional(),
  })
  .passthrough();
export const analysisSchema = z
  .object({
    id: z.string().optional(),
    category: z.string().optional(),
    summary: z.string().optional(),
    created_at: z.string().optional(),
    profile: profileSchema.optional(),
    report: z.string().optional(),
    result: analysisResultSchema.optional(),
    artifacts: z.array(artifactSchema).optional(),
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
export const commitSchema = z.object({
  id: z.string(),
  program_id: z.string(),
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
  analyses: z.array(analysisSchema).default([]),
});
export type Commit = z.infer<typeof commitSchema>;
export const scoreSchema = z.object({
  version: z.string(),
  base_score: z.number(),
  vector: z.string(),
  source: z.string(),
});
export const cveSchema = z.object({
  id: z.string(),
  program_id: z.string(),
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
export const findingSchema = z.object({
  id: z.string(),
  program_id: z.string(),
  kind: z.enum(["cve", "0day"]),
  cve_id: z.string().nullable(),
  title: z.string(),
  status: z.enum(["open", "fixed"]),
  affected_versions: z.array(z.string()),
  fixed_versions: z.array(z.string()),
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
  lab_runs: z.array(unknownRecord),
  created_at: z.string(),
  updated_at: z.string(),
});
export type Finding = z.infer<typeof findingSchema>;
export const jobSchema = z.object({
  id: z.string(),
  kind: z.string(),
  program_id: z.string().nullable().optional(),
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
    monitor_interval_days: z.number().nullable(),
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
  enabled: z.boolean(),
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
  programs: z.number(),
  security_reviews: z.number(),
  eligible_cves: z.number(),
  open_findings: z.number(),
  running_jobs: z.number(),
  failed_jobs: z.number(),
  recent_events: z.array(z.unknown()),
  due_programs: z.array(z.unknown()),
});
export const agentSessionSchema = z.object({
  runs: z.array(z.string()),
  run_id: z.string(),
  agent: z.string().nullable().optional(),
  agent_status: z.string(),
  screen: z.string(),
  held: z.boolean(),
});
export const jobAcceptedSchema = z.object({
  job_id: z.string(),
  status_url: z.string(),
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
export const programsSchema = listSchema(programSchema);
export const accountsSchema = listSchema(accountSchema);
export const commitsSchema = listSchema(commitSchema);
export const cvesSchema = listSchema(cveSchema);
export const findingsSchema = listSchema(findingSchema);
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
