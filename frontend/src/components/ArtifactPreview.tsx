import { useEffect, useState } from "react";
import { Download, FileCode2, FileText, FolderArchive } from "lucide-react";
import type { Artifact } from "../types";
import { date, ErrorNote, Markdown, SearchField, Segmented, Tabs } from "./ui";

const textFile =
  /\.(py|md|json|ya?ml|txt|php|[cm]?jsx?|[cm]?tsx?|css|s[ac]ss|html?|xml|svg|sh|sql|ini|toml|conf|properties|lock)$|(^|\/)(Dockerfile|Makefile|README|LICENSE|\.gitignore|\.env(?:\.[\w.-]+)?)$/i;

export function ArtifactPreview({
  artifact,
  relatedArtifacts = [],
  onOpen,
  exportable = true,
}: {
  artifact: Artifact;
  relatedArtifacts?: Artifact[];
  onOpen?: (id: string) => void;
  /** False for an Upstream Proof (A15): no download, and only its reports are read. */
  exportable?: boolean;
}) {
  const [content, setContent] = useState<string>();
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [revision, setRevision] = useState(0);
  const [view, setView] = useState("rendered");
  const markdown = /\.md$/i.test(artifact.path);
  // The only files of an Upstream Proof the page reads (A15), as the API allows.
  const report = ["report.md", "disclosure-report.md"].includes(artifact.path);
  useEffect(() => {
    const controller = new AbortController();
    setContent(undefined);
    setError(undefined);
    setNotice(undefined);
    if (!exportable && !report) {
      setNotice(
        "Upstream Proofs are never exported, so only their reports are shown.",
      );
      return;
    }
    if (artifact.size > 512000) {
      setNotice(
        "This file is too large for an inline preview." +
          (exportable ? " Download it to inspect the complete content." : ""),
      );
      return;
    }
    fetch(`/api/artifacts/${encodeURIComponent(artifact.id)}/content`, {
      credentials: "same-origin",
      signal: controller.signal,
    })
      .then(async (r) => {
        if (!r.ok) throw new Error(`Unable to read artifact (${r.status}).`);
        if (
          r.headers.get("content-type")?.includes("application/octet-stream") &&
          !textFile.test(artifact.path)
        ) {
          if (!controller.signal.aborted)
            setNotice("This binary file is available as a download.");
          return;
        }
        const value = await r.text();
        if (!controller.signal.aborted) setContent(value);
      })
      .catch((e: unknown) => {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : "Artifact preview failed.");
      });
    return () => controller.abort();
  }, [
    artifact.id,
    artifact.path,
    artifact.size,
    revision,
    exportable,
    report,
  ]);
  return (
    <div className="artifact-preview">
      <div className="artifact-meta">
        <div className="artifact-filename">
          <strong className="mono">{artifact.path}</strong>
          <small>{artifact.size.toLocaleString()} bytes</small>
        </div>
        <div className="artifact-preview-actions">
          {markdown && (
            <Segmented
              label="Report view"
              value={view}
              onChange={setView}
              options={[
                { value: "rendered", label: "Rendered" },
                { value: "source", label: "Source" },
              ]}
            />
          )}
          {exportable && (
            <a
              className="secondary button"
              download={artifact.path.split("/").at(-1)}
              href={`/api/artifacts/${encodeURIComponent(artifact.id)}/content`}
            >
              <Download size={14} aria-hidden="true" />
              Download file
            </a>
          )}
        </div>
      </div>
      <details className="integrity-line">
        <summary>File integrity · SHA-256</summary>
        <code>{artifact.sha256}</code>
      </details>
      {error && (
        <ErrorNote>
          {error}{" "}
          <button
            type="button"
            className="text-button"
            onClick={() => setRevision((n) => n + 1)}
          >
            Retry preview
          </button>
        </ErrorNote>
      )}
      {notice && <p className="hint artifact-notice">{notice}</p>}
      {content === undefined && !error && !notice ? (
        <p className="hint" role="status">
          Loading artifact…
        </p>
      ) : content !== undefined ? (
        markdown && view === "rendered" ? (
          <Markdown
            artifactLink={(href) => {
              if (!onOpen || href.startsWith("#")) return undefined;
              try {
                const target = new URL(
                  href,
                  new URL(artifact.path, "https://artifact.invalid/"),
                );
                if (target.origin !== "https://artifact.invalid")
                  return undefined;
                const related = relatedArtifacts.find(
                  (file) =>
                    file.path === decodeURIComponent(target.pathname.slice(1)),
                );
                return related
                  ? {
                      url: `/api/artifacts/${encodeURIComponent(related.id)}/content`,
                      open: () => onOpen(related.id),
                    }
                  : undefined;
              } catch {
                return undefined;
              }
            }}
          >
            {content}
          </Markdown>
        ) : (
          <pre
            className="source-code"
            tabIndex={0}
            aria-label={`${artifact.path} source`}
          >
            {content}
          </pre>
        )
      ) : null}
    </div>
  );
}

const groups = [
  { id: "report", label: "Report" },
  { id: "poc", label: "Python PoC" },
  { id: "app", label: "Vulnerable app" },
  { id: "support", label: "Supporting files" },
];
function groupOf(artifact: Artifact) {
  if (artifact.path.startsWith("vulnerable-app/")) return "app";
  if (artifact.path === "report.md") return "report";
  if (artifact.path === "poc.py") return "poc";
  return "support";
}
function preferredArtifact(artifacts: Artifact[]) {
  return (
    artifacts.find((a) => a.path.endsWith("audit-context-building.md")) ||
    artifacts.find((a) => a.path === "report.md") ||
    artifacts.find((a) => a.path === "vulnerable-app/README.md") ||
    artifacts.find((a) => a.path === "vulnerable-app/Dockerfile") ||
    artifacts.find((a) => a.path.endsWith("report.md")) ||
    artifacts[0]
  );
}
const appEntryFiles = [
  "vulnerable-app/README.md",
  "vulnerable-app/compose.yaml",
  "vulnerable-app/Dockerfile",
  "vulnerable-app/application.lock.json",
];
function filesInGroup(artifacts: Artifact[], grouped: boolean, group: string) {
  const files = grouped
    ? artifacts.filter((a) => groupOf(a) === group)
    : artifacts;
  if (!grouped || group !== "app") return files;
  return [
    ...appEntryFiles.flatMap((path) => files.filter((a) => a.path === path)),
    ...files.filter((a) => !appEntryFiles.includes(a.path)),
  ];
}

export function ArtifactBrowser({
  artifacts,
  createdAt,
  grouped = false,
  exportable = true,
}: {
  artifacts: Artifact[];
  createdAt?: string;
  grouped?: boolean;
  /** False for an Upstream Proof (A15): no download links, and only its reports are previewed. */
  exportable?: boolean;
}) {
  const [selected, setSelected] = useState<string>();
  const [group, setGroup] = useState("report");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const files = filesInGroup(artifacts, grouped, group);
  const filtered = files.filter((a) =>
    query
      .toLowerCase()
      .split(/\s+/)
      .every((term) => a.path.toLowerCase().includes(term)),
  );
  const pages = Math.ceil(filtered.length / 50);
  const currentPage = Math.min(page, Math.max(0, pages - 1));
  const shown = filtered.slice(currentPage * 50, (currentPage + 1) * 50);
  const artifact =
    files.find((a) => a.id === selected) || preferredArtifact(files);
  function open(id: string) {
    const target = artifacts.find((a) => a.id === id);
    if (!target) return;
    setSelected(id);
    setGroup(groupOf(target));
    setQuery("");
    const targetFiles = filesInGroup(artifacts, grouped, groupOf(target));
    setPage(Math.floor(targetFiles.indexOf(target) / 50));
  }
  if (!artifacts.length)
    return <p className="hint">No artifacts available for this revision.</p>;
  return (
    <div className="artifact-workspace">
      {grouped && (
        <Tabs
          label="Artifact type"
          items={groups.map((g) => ({
            ...g,
            count: artifacts.filter((a) => groupOf(a) === g.id).length,
          }))}
          active={group}
          onChange={(next) => {
            setGroup(next);
            setSelected(undefined);
            setQuery("");
            setPage(0);
          }}
        />
      )}
      {createdAt && <p className="hint artifact-date">{date(createdAt)}</p>}
      {artifact ? (
        <div
          className={`artifact-browser ${files.length === 1 ? "artifact-browser-single" : ""}`}
        >
          {files.length > 1 && (
            <div className="artifact-navigation">
              <SearchField
                label="Search artifact files"
                placeholder="Search file paths…"
                value={query}
                onChange={(value) => {
                  setQuery(value);
                  setPage(0);
                }}
              />
              <p className="hint artifact-count" role="status">
                {filtered.length.toLocaleString()}{" "}
                {filtered.length === 1 ? "file" : "files"}
                {query && ` matching “${query}”`}
              </p>
              <nav className="artifact-file-list" aria-label="Artifact files">
                {shown.map((a) => (
                  <button
                    type="button"
                    key={a.id}
                    className={a.id === artifact.id ? "selected" : ""}
                    aria-pressed={a.id === artifact.id}
                    aria-label={a.path}
                    title={a.path}
                    onClick={() => setSelected(a.id)}
                  >
                    {a.path.endsWith(".md") ? (
                      <FileText size={15} aria-hidden="true" />
                    ) : (
                      <FileCode2 size={15} aria-hidden="true" />
                    )}
                    <span>
                      <strong>{a.path.split("/").at(-1)}</strong>
                      <small>
                        {a.path.includes("/")
                          ? a.path.slice(0, a.path.lastIndexOf("/"))
                          : "Analysis output"}
                      </small>
                    </span>
                  </button>
                ))}
                {!filtered.length && (
                  <p className="hint">
                    No files match. Try a different path or clear the search.
                  </p>
                )}
              </nav>
              {pages > 1 && (
                <div className="artifact-pager">
                  <button
                    type="button"
                    className="secondary"
                    disabled={currentPage === 0}
                    onClick={() => setPage(currentPage - 1)}
                  >
                    Previous
                  </button>
                  <span>
                    {currentPage + 1} / {pages.toLocaleString()}
                  </span>
                  <button
                    type="button"
                    className="secondary"
                    disabled={currentPage === pages - 1}
                    onClick={() => setPage(currentPage + 1)}
                  >
                    Next
                  </button>
                </div>
              )}
            </div>
          )}
          <ArtifactPreview
            key={artifact.id}
            artifact={artifact}
            relatedArtifacts={artifacts}
            onOpen={open}
            exportable={exportable}
          />
        </div>
      ) : (
        <div className="artifact-empty">
          <FolderArchive size={22} aria-hidden="true" />
          <h3>
            No {groups.find((g) => g.id === group)?.label.toLowerCase()}{" "}
            available
          </h3>
          <p className="hint">
            This run did not produce these files. Available output remains in
            the other tabs{exportable ? " and the bundle download" : ""}.
          </p>
        </div>
      )}
    </div>
  );
}
