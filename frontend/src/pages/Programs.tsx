import { useState } from "react";
import { Link } from "react-router-dom";
import { LoaderCircle, Plus, Radar, Search, X } from "lucide-react";
import { useDebounced, useResource } from "../hooks";
import { programState, programsSchema } from "../types";
import type { Program } from "../types";
import {
  Badge,
  DataState,
  describeError,
  Empty,
  PageHeading,
  Panel,
  Pagination,
  Time,
} from "../components/ui";
export function VersionCell({ program }: { program: Program }) {
  const version = program.version;
  if (!version) return <span className="muted">Not observed</span>;
  return (
    <>
      <strong className="version-text">
        {version.version || version.candidates?.join(" / ") || "Unknown"}
      </strong>
      <div className="cell-meta">
        {version.origin === "manual" ? (
          <Badge tone="neutral">Manual</Badge>
        ) : (
          version.status !== "detected" && <Badge>{version.status}</Badge>
        )}
        <Time value={version.checked_at} />
      </div>
    </>
  );
}
export function Programs() {
  const [cursor, setCursor] = useState("");
  const [search, setSearch] = useState("");
  const query = useDebounced(search.trim());
  const params = new URLSearchParams();
  if (query) params.set("q", query);
  if (cursor) params.set("cursor", cursor);
  const resource = useResource(
    `/programs${params.size ? `?${params}` : ""}`,
    programsSchema,
    0,
    true,
  );
  const items = resource.data?.items;
  return (
    <>
      <PageHeading
        eyebrow="Asset inventory"
        title="Programs"
        description="Each program pairs a deployed asset with the software and upstream source it runs."
        actions={
          <Link className="primary button" to="/programs/new">
            <Plus size={16} aria-hidden="true" />
            Insert program
          </Link>
        }
      />
      <Panel>
        <div className="table-toolbar">
          <div className="search-field">
            <Search size={16} aria-hidden="true" />
            <input
              type="search"
              aria-label="Search programs"
              placeholder="Search assets, software, or URL"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setCursor("");
              }}
            />
            {resource.refreshing && resource.data ? (
              <LoaderCircle className="spin" size={15} aria-label="Searching" />
            ) : (
              search && (
                <button
                  type="button"
                  className="icon-button"
                  aria-label="Clear search"
                  onClick={() => setSearch("")}
                >
                  <X size={15} />
                </button>
              )
            )}
          </div>
          <span className="muted" role="status">
            {items
              ? `${items.length} ${items.length === 1 ? "program" : "programs"}${resource.data?.next_cursor ? " on this page" : ""}`
              : ""}
          </span>
        </div>
        <DataState
          loading={resource.loading}
          error={resource.error}
          retry={resource.refresh}
          hasData={!!resource.data}
        >
          {items?.length ? (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Asset / software</th>
                    <th scope="col">Upstream source</th>
                    <th scope="col">Observed version</th>
                    <th scope="col">Last check</th>
                    <th scope="col">Next check</th>
                    <th scope="col">State</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((p) => (
                    <tr key={p.id}>
                      <td>
                        <Link className="table-title" to={`/programs/${p.id}`}>
                          {p.asset_name}
                        </Link>
                        <div className="table-subtitle">
                          {p.product_name} · {p.product_kind}
                        </div>
                        <div className="table-url">{p.asset_url}</div>
                      </td>
                      <td>
                        {p.source_kind === "wordpress"
                          ? "WordPress plugin"
                          : "GitHub"}
                        <div className="table-subtitle mono">
                          {p.plugin_slug ||
                            p.source_url?.replace("https://github.com/", "")}
                          {" · "}
                          {p.source_ref || "default branch"}
                        </div>
                      </td>
                      <td>
                        <VersionCell program={p} />
                      </td>
                      <td>
                        <Time value={p.last_check_at} />
                      </td>
                      <td>
                        {p.monitor_enabled && !p.archived ? (
                          <Time value={p.next_check_at} fallback="Pending" />
                        ) : (
                          <span className="muted">Paused</span>
                        )}
                      </td>
                      <td>
                        <Badge>{programState(p)}</Badge>
                        {!!p.last_error && (
                          <div className="table-subtitle danger-text clamp">
                            {describeError(p.last_error) || "Last check failed"}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={query ? Search : Radar}
              title={query ? "No matching programs" : "No programs yet"}
              description={
                query
                  ? `Nothing matches “${query}”. Try an asset name, software name, or URL.`
                  : "Register your first asset to start collecting source and version evidence."
              }
              action={
                !query && (
                  <Link className="primary button" to="/programs/new">
                    <Plus size={16} aria-hidden="true" />
                    Insert program
                  </Link>
                )
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
    </>
  );
}
