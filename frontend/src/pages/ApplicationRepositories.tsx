import { useState } from "react";
import type { ReactNode } from "react";
import { GitBranch } from "lucide-react";
import { ApiError, mutate } from "../api";
import {
  jobAcceptedSchema,
  pushWebhookSecretSchema,
  repositoryLabel,
  repositoryLinkSchema,
} from "../types";
import type { Application, PushWebhookSecret, RepositoryLink } from "../types";
import {
  ActionButton,
  Badge,
  CopyButton,
  describeError,
  DetailGrid,
  Empty,
  ErrorNote,
  ExternalLink,
  Modal,
  notify,
  Panel,
  sentence,
  Time,
} from "../components/ui";

type Props = { application: Application; refresh: () => void };
const path = (application: Application, link?: RepositoryLink) =>
  `/applications/${application.id}/repositories${link ? `/${link.repository_id}` : ""}`;
/** An API error as text, with each field message (a Pydantic "Value error, " prefix dropped). */
export function errorText(err: unknown) {
  if (!(err instanceof Error)) return "The request failed.";
  const fields =
    err instanceof ApiError
      ? Object.values(err.fields).map((v) =>
          String(v).replace(/^Value error, /, ""),
        )
      : [];
  return [err.message, ...fields].join(" · ");
}
/** The Own repository, its Upstream repositories, unresolved packages and the add form. */
export function ApplicationRepositories({ application, refresh }: Props) {
  const [backfill, setBackfill] = useState<RepositoryLink>();
  const own = application.repositories.find(
    (r) => r.role === "own" && !r.removed_at,
  );
  const upstream = application.repositories
    .filter((r) => r.role === "upstream")
    .sort((a, b) => Number(!!a.removed_at) - Number(!!b.removed_at));
  const backfillButton = (link: RepositoryLink) => (
    <button
      type="button"
      className="secondary"
      disabled={!!link.removed_at || !link.baseline_revision}
      title={
        link.baseline_revision
          ? undefined
          : "Check this repository once to set its Baseline first"
      }
      onClick={() => setBackfill(link)}
    >
      Backfill
    </button>
  );
  return (
    <div className="column-stack">
      <Panel
        title="Own repository"
        description="The GitHub repository that holds this Application's own code. Upstream repositories are worked out from its manifests and lockfiles (package.json, composer.json, package-lock.json, pnpm-lock.yaml, yarn.lock, composer.lock) and again whenever a commit changes one."
        actions={
          own && (
            <>
              {backfillButton(own)}
              <ActionButton
                className="secondary"
                confirm="Confirm remove"
                onAction={async () => {
                  await mutate(
                    path(application, own),
                    repositoryLinkSchema,
                    {},
                    "DELETE",
                  );
                  notify("Own repository removed. Its commits are kept.");
                  refresh();
                }}
              >
                Remove
              </ActionButton>
            </>
          )
        }
        padded
      >
        {own ? (
          <>
            {!!own.last_error && (
              <ErrorNote>
                {sentence(
                  describeError(own.last_error) ||
                    "The repository could not be checked",
                )}
              </ErrorNote>
            )}
            <DetailGrid
              items={[
                [
                  "Repository",
                  <ExternalLink href={own.source_url}>
                    {repositoryLabel(own)}
                  </ExternalLink>,
                ],
                ["Branch", own.source_ref || "Default branch"],
                ["Baseline", <Revision value={own.baseline_revision} />],
                ["Last check", <Time value={own.last_check_at} />],
              ]}
            />
            <p className="hint">
              To replace it, remove it and add the new one. Its commits stay in
              the Commits tab.
            </p>
          </>
        ) : (
          <OwnForm application={application} refresh={refresh} />
        )}
      </Panel>
      {own && (
        <PushWebhookPanel
          application={application}
          link={own}
          refresh={refresh}
        />
      )}
      <Panel
        title="Upstream repositories"
        description="Watched for commits, never changed. A repository shared with other Applications is polled and triaged once."
      >
        {upstream.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Repository</th>
                  <th scope="col">Packages</th>
                  <th scope="col">Locked version</th>
                  <th scope="col">Status</th>
                  <th scope="col">On</th>
                  <th scope="col">Last check</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {upstream.map((link) => (
                  <UpstreamRow
                    key={`${link.repository_id}:${link.locked_version}`}
                    application={application}
                    link={link}
                    refresh={refresh}
                    backfill={backfillButton(link)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            icon={GitBranch}
            title="No Upstream repositories yet"
            description="Add an Own repository to work them out from its dependencies, or add one by hand below."
          />
        )}
      </Panel>
      {application.unresolved_dependencies.length > 0 && (
        <Panel
          title="Unresolved packages"
          description="Direct dependencies of the Own repository with no GitHub source repository. They are not watched."
        >
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Package</th>
                  <th scope="col">Version</th>
                  <th scope="col">Reason</th>
                </tr>
              </thead>
              <tbody>
                {application.unresolved_dependencies.map((d) => (
                  <tr key={`${d.ecosystem}:${d.name}`}>
                    <td>
                      <span className="mono">{d.name}</span>
                      <span className="table-subtitle">{d.ecosystem}</span>
                    </td>
                    <td>
                      {d.version || <span className="muted">Unknown</span>}
                    </td>
                    <td>{d.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
      <UpstreamForm application={application} refresh={refresh} />
      {backfill && (
        <Backfill
          application={application}
          link={backfill}
          onClose={() => setBackfill(undefined)}
          refresh={refresh}
        />
      )}
    </div>
  );
}
/** Why the push listener refused the last Push delivery; a code it learns later shows as is. */
const REFUSALS: Record<string, string> = {
  wrong_signature: "Wrong signature",
  event_not_accepted: "Event not accepted",
  delivery_id_missing: "Delivery id missing",
  body_too_large: "Body too large",
  rate_limited: "Too many deliveries",
};
/** B02: the Own repository's Push webhook. Its path and secret are shown once, in the setup
 * dialog, and dropped when it closes. Every value is rendered as text. */
function PushWebhookPanel({
  application,
  link,
  refresh,
}: Props & { link: RepositoryLink }) {
  const [shown, setShown] = useState<PushWebhookSecret>();
  const url = `${path(application, link)}/push-webhook`;
  const webhook = link.push_webhook;
  async function reveal(target: string) {
    setShown(await mutate(target, pushWebhookSecretSchema));
    refresh();
  }
  return (
    <Panel
      title="Push webhook"
      description="GitHub reports each push through your Public tunnel, and the Own repository is checked within about 15 s. Commits are still read from the GitHub API, and scheduled checks go on."
      actions={
        webhook ? (
          <>
            <ActionButton
              className="secondary"
              confirm="Confirm regenerate"
              onAction={() => reveal(`${url}/secret`)}
            >
              Regenerate
            </ActionButton>
            <ActionButton
              className="secondary"
              confirm="Confirm turn off"
              onAction={async () => {
                await mutate(url, repositoryLinkSchema, {}, "DELETE");
                notify("Push webhook turned off. Its push id is refused now.");
                refresh();
              }}
            >
              Turn off
            </ActionButton>
          </>
        ) : (
          <ActionButton className="primary" onAction={() => reveal(url)}>
            Set up push webhook
          </ActionButton>
        )
      }
      padded
    >
      {webhook ? (
        <DetailGrid
          items={[
            ["Set up", <Time value={webhook.created_at} />],
            [
              "Last accepted delivery",
              webhook.last_accepted ? (
                <>
                  <Time value={webhook.last_accepted.at} />
                  {webhook.last_accepted.event === "ping"
                    ? " · ping received · "
                    : " · push · "}
                  <span className="mono">
                    {webhook.last_accepted.delivery_id}
                  </span>
                </>
              ) : (
                <span className="muted">None yet</span>
              ),
            ],
            [
              "Last refusal",
              webhook.last_refusal ? (
                <>
                  <Time value={webhook.last_refusal.at} />
                  {" · "}
                  {REFUSALS[webhook.last_refusal.reason] ??
                    webhook.last_refusal.reason}
                </>
              ) : (
                <span className="muted">None</span>
              ),
            ],
          ]}
        />
      ) : (
        <p className="hint">
          Off. The Own repository is checked at its interval and on Check now.
        </p>
      )}
      {shown && (
        <Modal
          title="Register the Push webhook in GitHub"
          description="In the repository's Settings, under Webhooks, add a webhook with these values."
          onClose={() => setShown(undefined)}
        >
          <DetailGrid
            items={[
              [
                "Payload URL",
                <>
                  Your Public tunnel URL followed by{" "}
                  <code>{shown.path}</code>{" "}
                  <CopyButton value={shown.path} label="Copy the path" />
                </>,
              ],
              ["Content type", <code>application/json</code>],
              [
                "Secret",
                <>
                  <code>{shown.secret}</code>{" "}
                  <CopyButton value={shown.secret} label="Copy the secret" />
                </>,
              ],
              ["Which events", "Just the push event"],
            ]}
          />
          <p className="hint">
            The secret is shown only now. The push listener accepts the push id
            within 15 s, and GitHub's first ping then shows as the last accepted
            delivery.
          </p>
          <div className="form-actions">
            <button
              type="button"
              className="primary"
              onClick={() => setShown(undefined)}
            >
              Done
            </button>
          </div>
        </Modal>
      )}
    </Panel>
  );
}
function Revision({ value }: { value: string | null }) {
  return value ? (
    <span className="mono">{value.slice(0, 10)}</span>
  ) : (
    <span className="muted">Set by the first check</span>
  );
}
function releaseBadge(link: RepositoryLink) {
  if (link.release_branch_status === "matched")
    return <Badge tone="neutral">Release branch {link.release_branch}</Badge>;
  if (link.release_branch_status === "unknown")
    // Lower-case as A02 words it; a fragment keeps Badge from capitalising it.
    return (
      <Badge tone="warm">
        <>release branch unknown</>
      </Badge>
    );
  if (link.release_branch_status === "pending")
    return <Badge tone="info">Release branch pending</Badge>;
  return null;
}
function statusBadge(link: RepositoryLink) {
  if (link.removed_at) return <Badge tone="neutral">Removed</Badge>;
  if (link.last_error) return <Badge tone="danger">Error</Badge>;
  if (!link.enabled) return <Badge tone="neutral">Off</Badge>;
  return <Badge tone="good">Watching</Badge>;
}
function UpstreamRow({
  application,
  link,
  refresh,
  backfill,
}: Props & { link: RepositoryLink; backfill: ReactNode }) {
  const [locked, setLocked] = useState(link.locked_version || "");
  const [error, setError] = useState<string>();
  const removed = !!link.removed_at;
  async function patch(body: Record<string, unknown>) {
    setError(undefined);
    try {
      await mutate(
        path(application, link),
        repositoryLinkSchema,
        body,
        "PATCH",
      );
      refresh();
    } catch (err) {
      setError(errorText(err));
    }
  }
  return (
    <tr className={removed ? "dimmed" : undefined}>
      <td>
        <ExternalLink className="table-title" href={link.source_url}>
          {repositoryLabel(link)}
        </ExternalLink>
        {error && (
          <span className="field-error" role="alert">
            {error}
          </span>
        )}
      </td>
      <td>
        {link.packages.length ? (
          <div className="chip-row">
            {link.packages.map((p) => (
              <code className="chip" key={p}>
                {p}
              </code>
            ))}
          </div>
        ) : (
          <span className="muted">Added by hand</span>
        )}
      </td>
      <td>
        <form
          className="inline-actions"
          onSubmit={(e) => {
            e.preventDefault();
            void patch({ locked_version: locked.trim() || null });
          }}
        >
          <input
            aria-label="Locked version"
            value={locked}
            disabled={removed}
            maxLength={100}
            placeholder="Unknown"
            onChange={(e) => setLocked(e.target.value)}
          />
          <button className="secondary" disabled={removed}>
            Save
          </button>
        </form>
        {link.locked_version_source && (
          <Badge tone="neutral">{link.locked_version_source}</Badge>
        )}
      </td>
      <td>
        <div className="chip-row">
          {statusBadge(link)}
          {releaseBadge(link)}
        </div>
        {!!link.last_error && !removed && (
          <span className="table-subtitle">
            {sentence(describeError(link.last_error) || "The check failed")}
          </span>
        )}
      </td>
      <td>
        <label className="check-label">
          <input
            type="checkbox"
            checked={link.enabled}
            disabled={removed}
            onChange={(e) => void patch({ enabled: e.target.checked })}
          />
          Watch
        </label>
      </td>
      <td>
        <Time value={link.last_check_at} />
      </td>
      <td>{backfill}</td>
    </tr>
  );
}
function OwnForm({ application, refresh }: Props) {
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
          await mutate(path(application), repositoryLinkSchema, {
            role: "own",
            source_kind: "github",
            source_url: url.trim(),
          });
          notify("Own repository added. Its first check sets the Baseline.");
          refresh();
        } catch (err) {
          setError(errorText(err));
        } finally {
          setBusy(false);
        }
      }}
    >
      <label>
        Own repository URL
        <input
          required
          value={url}
          aria-invalid={!!error}
          placeholder="https://github.com/owner/repository"
          onChange={(e) => setUrl(e.target.value)}
        />
      </label>
      {error && <ErrorNote>{error}</ErrorNote>}
      <div className="form-actions">
        <button className="primary" disabled={busy}>
          Add Own repository
        </button>
      </div>
    </form>
  );
}
function UpstreamForm({ application, refresh }: Props) {
  const [kind, setKind] = useState<"github" | "wordpress">("github");
  const [source, setSource] = useState("");
  const [locked, setLocked] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <Panel
      title="Add Upstream repository"
      description="For a dependency that is not in the Own repository's manifests, or an Application with no Own repository. Without a Locked version, Exposure is unknown."
    >
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            await mutate(path(application), repositoryLinkSchema, {
              role: "upstream",
              source_kind: kind,
              ...(kind === "github"
                ? { source_url: source.trim() }
                : { plugin_slug: source.trim() }),
              locked_version: locked.trim() || null,
            });
            notify(
              "Upstream repository added. Its first check sets the Baseline.",
            );
            setSource("");
            setLocked("");
            refresh();
          } catch (err) {
            setError(errorText(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="form-grid">
          <label>
            Kind
            <select
              value={kind}
              onChange={(e) =>
                setKind(e.target.value === "wordpress" ? "wordpress" : "github")
              }
            >
              <option value="github">GitHub</option>
              <option value="wordpress">WordPress plugin</option>
            </select>
          </label>
          <label>
            {kind === "github" ? "GitHub URL" : "Plugin slug"}
            <input
              required
              value={source}
              placeholder={
                kind === "github"
                  ? "https://github.com/owner/repository"
                  : "akismet"
              }
              onChange={(e) => setSource(e.target.value)}
            />
          </label>
          <label>
            Locked version (optional)
            <input
              value={locked}
              maxLength={100}
              onChange={(e) => setLocked(e.target.value)}
            />
          </label>
        </div>
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <button className="primary" disabled={busy}>
            Add Upstream repository
          </button>
        </div>
      </form>
    </Panel>
  );
}
function Backfill({
  application,
  link,
  onClose,
  refresh,
}: Props & { link: RepositoryLink; onClose: () => void }) {
  const [count, setCount] = useState("20");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <Modal
      title={`Backfill ${repositoryLabel(link)}`}
      description="Commits older than the Baseline are imported and triaged only on request. A Backfill imports the last N commits up to the Baseline."
      onClose={onClose}
    >
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            const job = await mutate(
              `${path(application, link)}/backfills`,
              jobAcceptedSchema,
              { count: Number(count) },
            );
            notify(
              "Backfill queued",
              `/jobs/${encodeURIComponent(job.job_id)}`,
            );
            refresh();
            onClose();
          } catch (err) {
            setError(errorText(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Commits to backfill
          <input
            data-autofocus
            required
            type="number"
            min={1}
            max={100}
            step={1}
            value={count}
            onChange={(e) => setCount(e.target.value)}
          />
        </label>
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy}>
            Queue Backfill
          </button>
        </div>
      </form>
    </Modal>
  );
}
