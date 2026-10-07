import { useId, useState } from "react";
import type { ReactNode } from "react";
import { LoaderCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { mutate } from "../api";
import { useResource } from "../hooks";
import {
  accountsSchema,
  jobAcceptedSchema,
  operationNames,
  settingsSchema,
} from "../types";
import type { Operation, Profile } from "../types";
import { ProfileSelect, emptyProfile, isProfileReady } from "./ProfileSelect";
import { DataState, ErrorNote, Modal, notify } from "./ui";
export async function queueJob(
  path: string,
  body: unknown = {},
  key = crypto.randomUUID(),
  message = "Background job submitted.",
) {
  const job = await mutate(path, jobAcceptedSchema, body, "POST", key);
  notify(message, `/jobs/${encodeURIComponent(job.job_id)}`);
  return job;
}
export function JobLaunch({
  path,
  operation,
  initialProfile,
  context,
  onClose,
  onSubmitted,
  submit,
  submitLabel,
  refresh,
}: {
  path: string;
  operation: Operation;
  initialProfile?: Profile;
  context: ReactNode;
  onClose: () => void;
  onSubmitted?: () => void;
  /** Sends the request instead of queueing one job at `path`, e.g. for a batch. */
  submit?: (body: Record<string, unknown>, key: string) => Promise<void>;
  submitLabel?: string;
  /** Audit context only: refresh this context instead of building one. */
  refresh?: { id: string; revision: string };
}) {
  const accounts = useResource("/accounts", accountsSchema);
  const settings = useResource("/settings", settingsSchema);
  const [override, setOverride] = useState<Profile>();
  const [focus, setFocus] = useState("");
  const [maxFunctions, setMaxFunctions] = useState("24");
  const [fresh, setFresh] = useState(false);
  const [sourceRef, setSourceRef] = useState("");
  const sourceRefLabel = useId();
  const sourceRefHint = useId();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [key, setKey] = useState(() => crypto.randomUUID());
  const profile =
    override ||
    initialProfile ||
    settings.data?.default_profiles[operation] ||
    emptyProfile;
  const valid = isProfileReady(profile, accounts.data?.items || []);
  const pinnable =
    operation === "cve_analysis" || operation === "finding_artifacts";
  return (
    <Modal
      title={operationNames[operation]}
      description={
        refresh
          ? `Analyse again only the functions in files changed since ${refresh.revision.slice(0, 12)}; the rest of that context is reused with its orientation and scope.`
          : operation === "cve_analysis" || operation === "commit_analysis"
            ? "Prepare a report, Python PoC, and vulnerable application from the affected source."
            : "Review the execution profile before starting a background job."
      }
      onClose={onClose}
    >
      <div className="job-context">
        <span className="eyebrow">Inputs</span>
        <div className="job-context-body">{context}</div>
        <small>
          {override
            ? "Using your selection for this job."
            : initialProfile
              ? "Using the program’s execution profile. You can change it below."
              : "Using the global execution profile. You can change it below."}
        </small>
      </div>
      <DataState
        loading={accounts.loading || settings.loading}
        error={accounts.error || settings.error}
        hasData={!!accounts.data && !!settings.data}
        retry={() => {
          accounts.refresh();
          settings.refresh();
        }}
      >
        <form
          aria-busy={busy}
          onSubmit={async (e) => {
            e.preventDefault();
            if (busy) return;
            setBusy(true);
            setError(undefined);
            try {
              const body = {
                profile,
                ...(operation === "audit_context" && !refresh
                  ? { focus, max_functions: Number(maxFunctions), fresh }
                  : {}),
                ...(refresh ? { refresh_from: refresh.id } : {}),
                ...(pinnable && sourceRef.trim()
                  ? { source_ref: sourceRef.trim() }
                  : {}),
              };
              if (submit) await submit(body, key);
              else await queueJob(path, body, key);
              onSubmitted?.();
              onClose();
            } catch (err) {
              setError(
                err instanceof Error
                  ? err.message
                  : "Could not submit this job.",
              );
            } finally {
              setBusy(false);
            }
          }}
        >
          <fieldset className="job-launch-section" disabled={busy}>
            <legend>Execution profile</legend>
            <ProfileSelect
              value={profile}
              accounts={accounts.data?.items || []}
              onChange={(next) => {
                setOverride(next);
                setKey(crypto.randomUUID());
                setError(undefined);
              }}
            />
          </fieldset>
          {operation === "audit_context" && !refresh && (
            <label>
              Focus (optional)
              <textarea
                value={focus}
                onChange={(e) => {
                  setFocus(e.target.value);
                  setKey(crypto.randomUUID());
                }}
                placeholder="Functions, modules, or assumptions to examine"
              />
            </label>
          )}
          {operation === "audit_context" && !refresh && (
            <label>
              Max functions
              <input
                type="number"
                required
                min={1}
                max={100}
                step={1}
                value={maxFunctions}
                onChange={(e) => {
                  setMaxFunctions(e.target.value);
                  setKey(crypto.randomUUID());
                }}
              />
              <small>
                Each selected function is analyzed in its own agent run.
              </small>
            </label>
          )}
          {operation === "audit_context" && !refresh && (
            <label className="check-label">
              <input
                type="checkbox"
                checked={fresh}
                onChange={(e) => {
                  setFresh(e.target.checked);
                  setKey(crypto.randomUUID());
                }}
              />
              Start fresh instead of continuing an interrupted audit with the
              same scope and profile
            </label>
          )}
          {pinnable && (
            <label>
              <span id={sourceRefLabel}>Vulnerable revision (optional)</span>
              <input
                name="source_ref"
                autoComplete="off"
                spellCheck={false}
                aria-labelledby={sourceRefLabel}
                aria-describedby={sourceRefHint}
                disabled={busy}
                value={sourceRef}
                onChange={(e) => {
                  setSourceRef(e.target.value);
                  setKey(crypto.randomUUID());
                }}
                placeholder="Tag, branch, or commit…"
              />
              <small id={sourceRefHint}>
                Use a tag, branch, or commit that contains the vulnerability.
                Leave empty to resolve an affected release when version criteria
                are available.
              </small>
            </label>
          )}
          {!valid && (
            <p className="hint warning">
              Start job is unavailable until you choose a ready account, an
              available model, and a supported effort.{" "}
              <Link to="/settings?tab=accounts" onClick={onClose}>
                Manage accounts
              </Link>
            </p>
          )}
          {error && <ErrorNote>{error}</ErrorNote>}
          <div className="form-actions">
            <button type="button" className="secondary" onClick={onClose}>
              Cancel
            </button>
            <button className="primary" disabled={!valid || busy}>
              {busy && (
                <LoaderCircle size={15} className="spin" aria-hidden="true" />
              )}
              {busy
                ? "Submitting…"
                : submitLabel ||
                  (refresh && "Start refresh") ||
                  (operation === "cve_analysis" ||
                  operation === "commit_analysis"
                    ? "Start analysis"
                    : "Start job")}
            </button>
          </div>
        </form>
      </DataState>
    </Modal>
  );
}
