import { useId, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  CornerDownLeft,
  FileText,
  GitCommitHorizontal,
  LayoutDashboard,
  Radar,
  Search,
  Settings2,
  ShieldAlert,
  Target,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useCollection, useResource } from "../hooks";
import {
  commitsSchema,
  cvesSchema,
  findingSummariesSchema,
  applicationsSchema,
} from "../types";
import { Kbd, matches, Modal } from "./ui";
type Item = {
  id: string;
  group: string;
  title: string;
  detail?: string;
  to: string;
  icon: LucideIcon;
  /** Extra text that matches the query without being shown. */
  keywords?: string;
};
const pages: Item[] = [
  ["Dashboard", "/", LayoutDashboard, "home overview"],
  ["Applications", "/applications", Radar, "assets inventory"],
  ["Insert application", "/applications/new", Radar, "add new create"],
  ["Commit review", "/reviews", GitCommitHorizontal, "commits queue"],
  ["CVEs", "/cves", ShieldAlert, "vulnerabilities"],
  ["Eligible CVEs", "/cves?elig=eligible", ShieldAlert, "score criteria"],
  ["Findings", "/findings", Target, "reports"],
  ["Create finding", "/findings/new", Target, "add new"],
  ["Jobs", "/jobs", Activity, "background operations"],
  ["Failed jobs", "/jobs?status=failed", Activity, "errors"],
  [
    "Settings · Accounts",
    "/settings?tab=accounts",
    Settings2,
    "providers login",
  ],
  [
    "Settings · Defaults",
    "/settings?tab=defaults",
    Settings2,
    "profiles interval",
  ],
  [
    "Settings · Integrations",
    "/settings?tab=integrations",
    Settings2,
    "github nvd",
  ],
  [
    "Settings · Discord",
    "/settings?tab=discord",
    Settings2,
    "webhook notifications",
  ],
  ["Settings · Pi plugins", "/settings?tab=plugins", Settings2, ""],
].map(([title, to, icon, keywords]) => ({
  id: `page:${to}`,
  group: "Pages",
  title: title as string,
  to: to as string,
  icon: icon as LucideIcon,
  keywords: keywords as string,
}));
const GROUP_LIMIT = 6;
export const isMac =
  typeof navigator !== "undefined" &&
  /Mac|iPhone|iPad/.test(navigator.platform);
/** Command palette for jumping to any page or record. */
export function QuickJump({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const listId = useId();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const applications = useResource("/applications", applicationsSchema);
  const cves = useCollection("/cves", cvesSchema);
  // Commit lists carry full diffs, so the palette searches one page of them.
  const commits = useCollection("/commits", commitsSchema, 0, 200);
  const findings = useCollection(
    "/findings?view=summary",
    findingSummariesSchema,
  );
  const loading =
    applications.loading || cves.loading || commits.loading || findings.loading;
  const results = useMemo(() => {
    const q = query.trim();
    const applicationName = (id: string) =>
      applications.data?.items.find((p) => p.id === id)?.asset_name;
    const groups: Record<string, Item[]> = {
      Pages: pages,
      Applications: (applications.data?.items || []).map((p) => ({
        id: `application:${p.id}`,
        group: "Applications",
        title: p.asset_name,
        detail: `${p.product_name} · ${p.asset_url}`,
        to: `/applications/${p.id}`,
        icon: Radar,
      })),
      CVEs: (cves.data?.items || []).map((c) => ({
        id: `cve:${c.application_id}:${c.id}`,
        group: "CVEs",
        title: c.id,
        detail: `${applicationName(c.application_id) || "Application"} · ${c.title}`,
        to: `/applications/${c.application_id}?tab=cves&cve=${encodeURIComponent(c.id)}`,
        icon: ShieldAlert,
        keywords: c.description,
      })),
      Commits: (commits.data?.items || []).map((c) => ({
        id: `commit:${c.id}`,
        group: "Commits",
        title: c.message.split("\n")[0],
        detail: `${c.revision.slice(0, 10)} · ${c.author || "Unknown author"}`,
        to: `/commits/${c.id}`,
        icon: GitCommitHorizontal,
        keywords: c.revision,
      })),
      Findings: (findings.data?.items || []).map((f) => ({
        id: `finding:${f.id}`,
        group: "Findings",
        title: f.title,
        detail: f.source_ref || `${f.source} · ${f.id.slice(0, 8)}`,
        to: `/findings/${f.id}`,
        icon: FileText,
      })),
    };
    const order = /^cve-?\d/i.test(q)
      ? ["CVEs", "Findings", "Applications", "Commits", "Pages"]
      : /^[0-9a-f]{5,}$/i.test(q)
        ? ["Commits", "Pages", "Applications", "CVEs", "Findings"]
        : ["Pages", "Applications", "CVEs", "Findings", "Commits"];
    if (!q)
      return [
        ...pages.slice(0, 10),
        ...groups.Applications.slice(0, GROUP_LIMIT),
      ];
    return order.flatMap((name) =>
      groups[name]
        .filter((item) => matches(q, item.title, item.detail, item.keywords))
        .slice(0, GROUP_LIMIT),
    );
  }, [query, applications.data, cves.data, commits.data, findings.data]);
  const current = Math.min(active, Math.max(results.length - 1, 0));
  function go(item: Item | undefined) {
    if (!item) return;
    onClose();
    navigate(item.to);
  }
  return (
    <Modal title="Jump to" onClose={onClose} size="palette">
      <div className="palette-input">
        <Search size={17} aria-hidden="true" />
        <input
          data-autofocus
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={
            results[current] ? `${listId}-${current}` : undefined
          }
          aria-label="Search pages and records"
          placeholder="Search applications, CVE IDs, commits, findings, or pages"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown" || e.key === "ArrowUp") {
              e.preventDefault();
              const delta = e.key === "ArrowDown" ? 1 : -1;
              setActive(
                (current + delta + results.length) %
                  Math.max(results.length, 1),
              );
            } else if (e.key === "Enter") {
              e.preventDefault();
              go(results[current]);
            }
          }}
        />
      </div>
      <ul className="palette-results" role="listbox" id={listId}>
        {results.map((item, i) => (
          <li key={item.id}>
            {(i === 0 || results[i - 1].group !== item.group) && (
              <span className="palette-group" aria-hidden="true">
                {item.group}
              </span>
            )}
            <div
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === current}
              className="palette-item"
              onMouseMove={() => i !== current && setActive(i)}
              onClick={() => go(item)}
            >
              <item.icon size={16} aria-hidden="true" />
              <span className="palette-text">
                <strong>{item.title}</strong>
                {item.detail && <span>{item.detail}</span>}
              </span>
              {i === current && <CornerDownLeft size={14} aria-hidden="true" />}
            </div>
          </li>
        ))}
      </ul>
      {!results.length && (
        <p className="palette-empty">
          {loading ? "Loading records…" : `No matches for “${query}”.`}
        </p>
      )}
      <p className="palette-footer">
        <span>
          <Kbd>↑</Kbd> <Kbd>↓</Kbd> to move · <Kbd>Enter</Kbd> to open ·{" "}
          <Kbd>Esc</Kbd> to close
        </span>
        {loading && <span>Loading records…</span>}
      </p>
    </Modal>
  );
}
