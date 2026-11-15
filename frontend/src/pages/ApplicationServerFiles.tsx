import { useState } from "react";
import { RefreshCw, Server } from "lucide-react";
import { z } from "zod";
import { mutate } from "../api";
import { useResource } from "../hooks";
import { agentsSchema, enrollmentSchema } from "../types";
import type {
  Agent,
  AgentMessage,
  Application,
  Enrollment,
  ManifestEntry,
  ServerChange,
} from "../types";
import {
  ActionButton,
  Badge,
  CopyButton,
  DataState,
  DetailGrid,
  Empty,
  ErrorNote,
  humanize,
  Modal,
  notify,
  Panel,
  Time,
} from "../components/ui";
import { errorText } from "./ApplicationRepositories";
import { Change } from "./ApplicationServedContent";

const STATUS: Record<string, [string, string]> = {
  awaiting_enrollment: ["Awaiting Enrollment", "warm"],
  pending: ["Pending: confirm the fingerprint", "warm"],
  enrolled: ["Enrolled", "good"],
  revoked: ["Revoked", "neutral"],
};
function Message({ message }: { message: AgentMessage }) {
  return (
    <span className="table-subtitle">
      {humanize(message.name || message.type)} #{message.sequence}:{" "}
      {humanize(message.status)}
      {message.reason ? ` (${message.reason})` : ""}
    </span>
  );
}
/** One manifest entry as text: its path, SHA-256 prefix, mode, owner and whether its bytes are held. */
function Entry({
  sign,
  entry,
  held,
}: {
  sign: string;
  entry: ManifestEntry;
  held: string[];
}) {
  const bytes =
    entry.type !== "file"
      ? `link to ${entry.target ?? "?"}`
      : entry.secret
        ? "secret: hash only"
        : entry.sha256 && held.includes(entry.sha256)
          ? "bytes held"
          : "bytes not held";
  return (
    <span className="mono table-subtitle">
      {sign} {entry.root}/{entry.path} · {entry.sha256?.slice(0, 12) || "no hash"}{" "}
      · mode {entry.mode.toString(8)} · {entry.uid}:{entry.gid} · {bytes}
    </span>
  );
}
function ChangeRow({
  change,
  refresh,
}: {
  change: ServerChange;
  refresh: () => void;
}) {
  return (
    <tr>
      <td>
        <Time value={change.created_at} />
        <span className="mono table-subtitle">
          {change.fingerprint.slice(0, 12)}
        </span>
      </td>
      <td>
        {change.diff.added.map((entry) => (
          <Entry
            key={`a${entry.root}/${entry.path}`}
            sign="+"
            entry={entry}
            held={change.held}
          />
        ))}
        {change.diff.modified.map(({ after }) => (
          <Entry
            key={`m${after.root}/${after.path}`}
            sign="~"
            entry={after}
            held={change.held}
          />
        ))}
        {change.diff.removed.map((entry) => (
          <Entry
            key={`r${entry.root}/${entry.path}`}
            sign="-"
            entry={entry}
            held={change.held}
          />
        ))}
      </td>
      <td>
        {change.incomplete.length ? (
          change.incomplete.map((item, index) => (
            <span key={index} className="table-subtitle">
              {item.reason}
              {item.path ? `: ${item.path}` : ""}
            </span>
          ))
        ) : (
          <span className="muted">Complete</span>
        )}
      </td>
      <td>
        <Change
          change={change}
          refresh={refresh}
          route="server-changes"
          noun="Server"
        />
      </td>
    </tr>
  );
}
/** B05: an agent's Baseline, its latest File manifest, Accept Baseline and its Server changes. */
function ServerChanges({
  agent,
  refresh,
}: {
  agent: Agent;
  refresh: () => void;
}) {
  const latest = agent.latest_manifest;
  return (
    <Panel
      title={`Server changes · ${agent.name}`}
      description="Each File manifest is compared with the Baseline by path, SHA-256, mode and owner; a change to the modification time alone is ignored. Uploaded bytes are evidence only: never run or rendered."
    >
      <DetailGrid
        items={[
          [
            "Baseline",
            agent.baseline ? (
              <>
                <span className="mono">
                  {agent.baseline.sha256.slice(0, 12)}
                </span>{" "}
                accepted <Time value={agent.baseline.accepted_at} />
              </>
            ) : (
              "None yet: accept the first File manifest"
            ),
          ],
          [
            "Latest File manifest",
            latest ? (
              <>
                #{latest.sequence} · {latest.file_count} files ·{" "}
                {humanize(latest.status)} ·{" "}
                <span className="mono">{latest.sha256.slice(0, 12)}</span>{" "}
                <Time value={latest.created_at} />
                {latest.incomplete.map((item, index) => (
                  <span key={index} className="table-subtitle">
                    Incomplete: {item.reason}
                    {item.path ? `: ${item.path}` : ""}
                  </span>
                ))}
              </>
            ) : (
              "No report yet"
            ),
          ],
        ]}
      />
      {latest && agent.accept_allowed && (
        <div className="form-actions">
          <ActionButton
            className="primary"
            onAction={async () => {
              await mutate(`/agents/${agent.id}/baselines`, z.unknown(), {
                manifest_id: latest.id,
                manifest_sha256: latest.sha256,
              });
              notify("Baseline accepted.");
              refresh();
            }}
          >
            Accept Baseline
          </ActionButton>
        </div>
      )}
      {agent.changes.length ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th scope="col">Seen</th>
                <th scope="col">Files</th>
                <th scope="col">Incomplete</th>
                <th scope="col">Triage and Verdict</th>
              </tr>
            </thead>
            <tbody>
              {agent.changes.map((change) => (
                <ChangeRow key={change.id} change={change} refresh={refresh} />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="hint">No Server change since the Baseline.</p>
      )}
    </Panel>
  );
}
/** Add agent, then its enroll command and one-time Enrollment code in a dialog, shown only once:
 * they are dropped when it closes, and the dashboard stores only the code's hash. */
function AddAgent({
  application,
  agentUrl,
  refresh,
}: {
  application: Application;
  agentUrl: string;
  refresh: () => void;
}) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [shown, setShown] = useState<Enrollment>();
  return (
    <>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            const added = await mutate(
              `/applications/${application.id}/agents`,
              enrollmentSchema,
              { name: name.trim(), url: (url ?? agentUrl).trim() },
            );
            setShown(added.enrollment);
            setName("");
            refresh();
          } catch (err) {
            setError(errorText(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Agent name
          <input
            required
            maxLength={100}
            value={name}
            placeholder="web-1"
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label>
          Agent listener URL as the server sees it
          <input
            required
            value={url ?? agentUrl}
            onChange={(e) => setUrl(e.target.value)}
          />
        </label>
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <button className="primary" disabled={busy}>
            Add agent
          </button>
        </div>
      </form>
      {shown && (
        <Modal
          title="Enroll the agent on the server"
          description="Run the command as root on the server, then type the Enrollment code when it asks. Change --allow to the directories the agent may watch."
          onClose={() => setShown(undefined)}
        >
          <DetailGrid
            items={[
              [
                "Enroll command",
                <>
                  <code>{shown.command}</code>{" "}
                  <CopyButton value={shown.command} label="Copy the command" />
                </>,
              ],
              [
                "Enrollment code",
                <>
                  <code>{shown.code}</code>{" "}
                  <CopyButton value={shown.code} label="Copy the code" />
                </>,
              ],
              ["Code expires", <Time value={shown.expires_at} absolute />],
              ["Dashboard key id", <code>{shown.key_id}</code>],
            ]}
          />
          <p className="hint">
            The command and the code are shown only now. The code works once,
            within one hour. enroll prints the Agent key fingerprint: compare it
            with the one this tab shows before you confirm.
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
    </>
  );
}
/** The Server files tab (B04): the Application's On-server agents, their Enrollment and their
 * signed messages. Everything an agent reports is rendered as text. */
export function ApplicationServerFiles({
  application,
}: {
  application: Application;
}) {
  const resource = useResource(
    `/applications/${application.id}/agents`,
    agentsSchema,
    15000,
  );
  const agents = resource.data?.items || [];
  const act = async (
    agent: Agent,
    route: string,
    body: object,
    done: string,
  ) => {
    await mutate(`/agents/${agent.id}/${route}`, z.unknown(), body);
    notify(done);
    resource.refresh();
  };
  return (
    <div className="column-stack">
      <Panel
        title="Server files"
        description="An On-server agent runs as root on the server behind this Asset, dials out to the agent listener, and reports the files under its Watched roots. It acts only on commands signed with the Dashboard key."
        padded
      >
        <DataState
          loading={resource.loading}
          error={resource.error}
          retry={resource.refresh}
          hasData={!!resource.data}
        >
          <AddAgent
            application={application}
            agentUrl={resource.data?.agent_url || ""}
            refresh={resource.refresh}
          />
        </DataState>
      </Panel>
      <Panel
        title="On-server agents"
        description="Confirm a pending agent only when its fingerprint matches the one enroll printed on the server."
      >
        {agents.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Agent</th>
                  <th scope="col">Status</th>
                  <th scope="col">Fingerprint</th>
                  <th scope="col">Allowed paths</th>
                  <th scope="col">Version</th>
                  <th scope="col">Last seen</th>
                  <th scope="col">Last refusal</th>
                  <th scope="col">Signed messages</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent) => {
                  const [label, tone] = STATUS[agent.status] || [
                    humanize(agent.status),
                    "neutral",
                  ];
                  return (
                    <tr key={agent.id}>
                      <td>
                        {agent.name}
                        <span className="table-subtitle mono">{agent.url}</span>
                      </td>
                      <td>
                        <Badge tone={tone}>{label}</Badge>
                      </td>
                      <td>
                        <span className="mono">
                          {agent.fingerprint || "Not enrolled yet"}
                        </span>
                      </td>
                      <td>
                        {agent.allowed_paths.map((path) => (
                          <span key={path} className="mono table-subtitle">
                            {path}
                          </span>
                        ))}
                      </td>
                      <td>
                        {agent.version
                          ? `${agent.version} · ${agent.os}/${agent.arch}`
                          : "Unknown"}
                      </td>
                      <td>
                        <Time value={agent.last_seen_at} />
                      </td>
                      <td>
                        {agent.last_refusal ? (
                          <>
                            {agent.last_refusal.reason}
                            <span className="table-subtitle">
                              {agent.last_refusal.route} ·{" "}
                              <Time value={agent.last_refusal.at} />
                            </span>
                          </>
                        ) : (
                          <span className="muted">None</span>
                        )}
                      </td>
                      <td>
                        {agent.configuration && (
                          <Message message={agent.configuration} />
                        )}
                        {agent.commands.slice(0, 3).map((message) => (
                          <Message key={message.id} message={message} />
                        ))}
                      </td>
                      <td>
                        <span className="inline-actions">
                          {agent.status === "pending" && agent.fingerprint && (
                            <ActionButton
                              className="primary"
                              confirm="It matches: enroll"
                              onAction={() =>
                                act(
                                  agent,
                                  "confirmations",
                                  { fingerprint: agent.fingerprint },
                                  "Agent enrolled. Its first configuration is signed.",
                                )
                              }
                            >
                              Confirm fingerprint
                            </ActionButton>
                          )}
                          {agent.status === "enrolled" && (
                            <ActionButton
                              className="secondary"
                              onAction={() =>
                                act(
                                  agent,
                                  "rescans",
                                  {},
                                  "Rescan command signed.",
                                )
                              }
                            >
                              <RefreshCw size={15} aria-hidden="true" />
                              Check now
                            </ActionButton>
                          )}
                          {agent.status !== "revoked" && (
                            <ActionButton
                              className="secondary"
                              confirm="Confirm revoke"
                              onAction={() =>
                                act(
                                  agent,
                                  "revocations",
                                  {},
                                  "Agent revoked. Its key is refused from now on.",
                                )
                              }
                            >
                              Revoke
                            </ActionButton>
                          )}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            icon={Server}
            title="No On-server agents"
            description="Add an agent, then run the enroll command on the server."
          />
        )}
      </Panel>
      {agents
        .filter((agent) => agent.latest_manifest || agent.changes.length)
        .map((agent) => (
          <ServerChanges
            key={agent.id}
            agent={agent}
            refresh={resource.refresh}
          />
        ))}
    </div>
  );
}
