import { useState } from "react";
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
}: {
  path: string;
  operation: Operation;
  initialProfile?: Profile;
  context: string;
  onClose: () => void;
  onSubmitted?: () => void;
}) {
  const accounts = useResource("/accounts", accountsSchema);
  const settings = useResource("/settings", settingsSchema);
  const [override, setOverride] = useState<Profile>();
  const [focus, setFocus] = useState("");
  const [maxFunctions, setMaxFunctions] = useState("24");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [key, setKey] = useState(() => crypto.randomUUID());
  const profile =
    override ||
    initialProfile ||
    settings.data?.default_profiles[operation] ||
    emptyProfile;
  const valid = isProfileReady(profile, accounts.data?.items || []);
  return (
    <Modal
      title={operationNames[operation]}
      description="Review the execution profile before starting a background job."
      onClose={onClose}
    >
      <div className="job-context">
        <span className="eyebrow">Inputs</span>
        <p>{context}</p>
        <small>
          Profile resolution: job selection, then program override, then global
          default.
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
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(undefined);
            try {
              await queueJob(
                path,
                {
                  profile,
                  ...(operation === "audit_context"
                    ? { focus, max_functions: Number(maxFunctions) }
                    : {}),
                },
                key,
              );
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
          <ProfileSelect
            value={profile}
            accounts={accounts.data?.items || []}
            onChange={(next) => {
              setOverride(next);
              setKey(crypto.randomUUID());
              setError(undefined);
            }}
          />
          {operation === "audit_context" && (
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
          {operation === "audit_context" && (
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
              <small>Each selected function is analyzed in its own agent run.</small>
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
              {busy ? "Submitting…" : "Start job"}
            </button>
          </div>
        </form>
      </DataState>
    </Modal>
  );
}
