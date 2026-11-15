import { Link } from "react-router-dom";
import { RefreshCw, ShieldCheck } from "lucide-react";
import { useResource } from "../hooks";
import {
  advisoriesSchema,
  exposureLabels,
  exposureTones,
  repositoryLabel,
} from "../types";
import type { AdvisoryPin, Application } from "../types";
import { queueJob } from "../components/JobLaunch";
import {
  ActionButton,
  Badge,
  DataState,
  describeError,
  DetailGrid,
  Empty,
  Panel,
  Time,
} from "../components/ui";

const feedNames: Record<string, string> = {
  osv: "OSV",
  ghsa: "GHSA",
  nvd: "NVD",
};
/** A pin's version, or Unknown with why it cannot be read. */
function Version({ pin }: { pin: AdvisoryPin }) {
  return pin.version ? (
    <span className="mono">{pin.version}</span>
  ) : (
    <>
      <Badge tone="warm">Unknown</Badge> {pin.reason}
    </>
  );
}
function Exposure({ pin }: { pin: AdvisoryPin }) {
  return pin.exposure ? (
    <Badge tone={exposureTones[pin.exposure]}>
      {exposureLabels[pin.exposure]}
    </Badge>
  ) : (
    <span className="muted">Not matched yet</span>
  );
}
/** The Advisories tab (A09): the runtime and package pins the last Advisory check collected, with
 * where each came from, each feed's state and the matches. Feed text is shown as text. */
export function ApplicationAdvisories({
  application,
}: {
  application: Application;
}) {
  const resource = useResource(
    `/applications/${application.id}/advisories`,
    advisoriesSchema,
    30000,
  );
  const data = resource.data;
  const repository = application.repositories.find(
    (r) => r.repository_id === data?.repository_id,
  );
  return (
    <DataState
      loading={resource.loading}
      error={resource.error}
      retry={resource.refresh}
      hasData={!!data}
    >
      {data && (
        <div className="column-stack">
          <Panel
            title="Advisory check"
            description="Daily, after a manifest, lockfile, .nvmrc or Dockerfile changes on the Own repository's default branch, and when you ask, GarudaNetra reads these pins from the head of the Own repository (else the source repository) and matches them against OSV, GHSA and NVD. A version that cannot be read is unknown, which counts as exposed."
            actions={
              <ActionButton
                className="secondary"
                onAction={async () => {
                  await queueJob(
                    `/applications/${application.id}/advisory-checks`,
                    {},
                    undefined,
                    "Advisory check queued.",
                  );
                  resource.refresh();
                }}
              >
                <RefreshCw size={15} aria-hidden="true" />
                Run Advisory check
              </ActionButton>
            }
            padded
          >
            <DetailGrid
              items={[
                [
                  "Read from",
                  repository ? (
                    repositoryLabel(repository)
                  ) : (
                    <span className="muted">Not checked yet</span>
                  ),
                ],
                [
                  "Revision",
                  <span className="mono">
                    {data.revision?.slice(0, 12) || "None"}
                  </span>,
                ],
                ["Collected", <Time value={data.collected_at} />],
                ...Object.entries(data.feeds).map(
                  ([feed, state]): [string, string] => [
                    feedNames[feed] || feed,
                    state.error
                      ? `Failed: ${describeError(state.error) || "no reason given"}`
                      : `${state.records ?? 0} ${state.records === 1 ? "record" : "records"}`,
                  ],
                ),
              ]}
            />
          </Panel>
          <Panel
            title="Runtimes"
            description="From Dockerfile FROM image tags, .nvmrc, package.json engines and the composer.json platform setting."
          >
            {data.runtimes.length ? (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Runtime</th>
                      <th scope="col">Version</th>
                      <th scope="col">Image</th>
                      <th scope="col">Source</th>
                      <th scope="col">Exposure</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.runtimes.map((pin, i) => (
                      <tr key={i}>
                        <td className="mono">{pin.name}</td>
                        <td>
                          <Version pin={pin} />
                        </td>
                        <td className="mono">
                          {pin.image ? (
                            `${pin.image}${pin.tag ? `:${pin.tag}` : ""}`
                          ) : (
                            <span className="muted">None</span>
                          )}
                        </td>
                        <td>
                          <span className="mono">{pin.source}</span>
                          <span className="table-subtitle">{pin.field}</span>
                        </td>
                        <td>
                          <Exposure pin={pin} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty
                icon={ShieldCheck}
                title="No runtime pins"
                description="No Dockerfile, .nvmrc, engines or platform setting pins node or php."
              />
            )}
          </Panel>
          <Panel
            title="Packages"
            description="From the lockfiles, with a Locked version you entered or the Deployed version gave in place of the lockfile's."
          >
            {data.packages.length ? (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Ecosystem</th>
                      <th scope="col">Package</th>
                      <th scope="col">Version</th>
                      <th scope="col">Source</th>
                      <th scope="col">Direct</th>
                      <th scope="col">Exposure</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.packages.map((pin) => (
                      <tr key={`${pin.ecosystem}:${pin.name}`}>
                        <td>{pin.ecosystem}</td>
                        <td className="mono">{pin.name}</td>
                        <td>
                          <Version pin={pin} />
                        </td>
                        <td className="mono">{pin.source}</td>
                        <td>{pin.direct ? "Yes" : "No"}</td>
                        <td>
                          <Exposure pin={pin} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty
                icon={ShieldCheck}
                title="No package pins"
                description="No package.json, composer.json or lockfile was found."
              />
            )}
          </Panel>
          <Panel
            title="Matches"
            description="One row per vulnerability: OSV, GHSA and CVE aliases count as one. An exposed or unknown match opens a Finding, or attaches to the commit or CVE Finding that already carries one of its aliases."
          >
            {data.matches.length ? (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Vulnerability</th>
                      <th scope="col">Pins</th>
                      <th scope="col">Exposure</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.matches.map((match) => (
                      <tr key={match.id}>
                        <td>
                          {match.finding_id ? (
                            <Link
                              className="mono"
                              to={`/findings/${match.finding_id}`}
                            >
                              {match.vulnerability}
                            </Link>
                          ) : (
                            <span className="mono">{match.vulnerability}</span>
                          )}
                          {match.summary && (
                            <span className="table-subtitle">
                              {match.summary}
                            </span>
                          )}
                          {match.aliases
                            .filter((name) => name !== match.vulnerability)
                            .map((name) => (
                              <span key={name} className="table-subtitle mono">
                                {name}
                              </span>
                            ))}
                        </td>
                        <td>
                          {match.pins
                            .map((pin) => `${pin.name} ${pin.version}`)
                            .join(", ")}
                        </td>
                        <td>
                          <Badge tone={exposureTones[match.state]}>
                            {exposureLabels[match.state]}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty
                icon={ShieldCheck}
                title="No matches"
                description="No feed lists an advisory for these pins."
              />
            )}
          </Panel>
        </div>
      )}
    </DataState>
  );
}
