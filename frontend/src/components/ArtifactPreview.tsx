import { useEffect, useState } from "react";
import { Download } from "lucide-react";
import type { Artifact } from "../types";
import { date, ErrorNote, Markdown } from "./ui";
export function ArtifactPreview({
  artifact,
  relatedArtifacts = [],
  onOpen,
}: {
  artifact: Artifact;
  relatedArtifacts?: Artifact[];
  onOpen?: (id: string) => void;
}) {
  const [content, setContent] = useState<string>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    const controller = new AbortController();
    setContent(undefined);
    setError(undefined);
    if (artifact.size > 512000) {
      setError(
        "This file is too large for an inline preview. Download it to inspect the complete content.",
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
          !/\.(py|md|json|ya?ml|txt)$|Dockerfile$/.test(artifact.path)
        )
          throw new Error("This binary file is available as a download.");
        return r.text();
      })
      .then((value) => {
        if (!controller.signal.aborted) setContent(value);
      })
      .catch((e: unknown) => {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : "Artifact preview failed.");
      });
    return () => controller.abort();
  }, [artifact.id, artifact.path, artifact.size]);
  return (
    <div className="artifact-preview">
      <div className="artifact-meta">
        <strong className="mono">{artifact.path}</strong>
        <a
          className="secondary button"
          download
          href={`/api/artifacts/${encodeURIComponent(artifact.id)}/content`}
        >
          <Download size={14} />
          Download
        </a>
      </div>
      <div className="integrity-line">
        {artifact.size.toLocaleString()} bytes · SHA-256{" "}
        <code>{artifact.sha256}</code>
      </div>
      {error && <ErrorNote>{error}</ErrorNote>}
      {content === undefined && !error ? (
        <p className="hint" role="status">
          Loading artifact…
        </p>
      ) : content !== undefined ? (
        artifact.path.endsWith(".md") ? (
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
          <pre className="source-code">{content}</pre>
        )
      ) : null}
    </div>
  );
}
export function ArtifactBrowser({
  artifacts,
  createdAt,
}: {
  artifacts: Artifact[];
  createdAt?: string;
}) {
  const [selected, setSelected] = useState<string>();
  const artifact =
    artifacts.find((a) => a.id === selected) ||
    artifacts.find((a) => a.path.endsWith("audit-context-building.md")) ||
    artifacts.find((a) => a.path.endsWith("report.md")) ||
    artifacts[0];
  if (!artifact)
    return <p className="hint">No artifacts available for this revision.</p>;
  return (
    <div className="artifact-browser">
      <div className="artifact-file-list">
        {createdAt && <span className="hint">{date(createdAt)}</span>}
        {artifacts.map((a) => (
          <button
            key={a.id}
            className={a.id === artifact.id ? "selected" : ""}
            onClick={() => setSelected(a.id)}
          >
            {a.path}
          </button>
        ))}
      </div>
      <ArtifactPreview
        key={artifact.id}
        artifact={artifact}
        relatedArtifacts={artifacts}
        onOpen={setSelected}
      />
    </div>
  );
}
