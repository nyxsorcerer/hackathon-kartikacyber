import { useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  ArrowLeft,
  ArrowUpRight,
  Check,
  CircleAlert,
  CircleCheck,
  Copy,
  Inbox,
  Info,
  LoaderCircle,
  Search,
  TriangleAlert,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { readable, safeHref } from "../types";
import { useDocumentTitle } from "../hooks";
export function notify(message: string, url?: string) {
  window.dispatchEvent(
    new CustomEvent("numen:notice", { detail: { message, url } }),
  );
}
export function date(value: string | null | undefined) {
  if (!value) return "Never";
  const d = new Date(value);
  return Number.isNaN(d.getTime())
    ? "Unknown"
    : d.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
}
const relativeUnits: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31536000],
  ["month", 2592000],
  ["week", 604800],
  ["day", 86400],
  ["hour", 3600],
  ["minute", 60],
];
export function relativeTime(value: string | null | undefined) {
  if (!value) return "Never";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "Unknown";
  const seconds = (d.getTime() - Date.now()) / 1000;
  if (Math.abs(seconds) < 45) return "just now";
  const format = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [unit, size] of relativeUnits)
    if (Math.abs(seconds) >= size || unit === "minute")
      return format.format(Math.round(seconds / size), unit);
  return date(value);
}
/** Relative time with the absolute timestamp available on hover. */
export function Time({
  value,
  absolute = false,
  fallback,
}: {
  value: string | null | undefined;
  absolute?: boolean;
  fallback?: string;
}) {
  if (!value) return <>{fallback ?? "Never"}</>;
  return (
    <time dateTime={value} title={date(value)}>
      {absolute
        ? `${date(value)} · ${relativeTime(value)}`
        : relativeTime(value)}
    </time>
  );
}
export function humanize(value: string) {
  const text = value.replaceAll("_", " ").trim();
  return text.charAt(0).toUpperCase() + text.slice(1);
}
/** End a message with punctuation so another sentence can follow it. */
export function sentence(text: string) {
  return /[.!?]$/.test(text.trim()) ? text.trim() : `${text.trim()}.`;
}
/** Extract a readable message from an unknown error payload. */
export function describeError(value: unknown) {
  if (typeof value === "string") return value;
  if (
    typeof value === "object" &&
    value &&
    "message" in value &&
    typeof value.message === "string"
  )
    return value.message;
  return undefined;
}
const tones: Record<string, string[]> = {
  good: [
    "ready",
    "succeeded",
    "fixed",
    "complete",
    "completed",
    "confirmed",
    "detected",
    "monitoring",
    "enabled",
    "healthy",
    "eligible",
    "verified",
    "delivered",
    "current",
    "not affected",
    "signed in",
  ],
  danger: [
    "failed",
    "error",
    "affected",
    "open",
    "security candidate",
    "expired",
    "rejected",
    "unavailable",
    "blocked",
    "likely vulnerability fix",
    "potentially introduced vulnerability",
  ],
  warm: [
    "candidate",
    "ambiguous",
    "partial",
    "stale",
    "cancelling",
    "potential",
    "unchecked",
    "draft",
    "insufficient context",
    "cleanup pending",
  ],
  info: ["queued", "running", "pending login"],
};
export function toneFor(label: string) {
  const key = label.replaceAll("_", " ").toLowerCase();
  return (
    Object.entries(tones).find(([, labels]) => labels.includes(key))?.[0] ||
    "neutral"
  );
}
export function Badge({
  children,
  tone,
}: {
  children: ReactNode;
  tone?: string;
}) {
  const text = typeof children === "string" ? children : undefined;
  return (
    <span className={`badge ${tone || (text ? toneFor(text) : "neutral")}`}>
      <span className="badge-dot" aria-hidden="true" />
      {text ? humanize(text) : children}
    </span>
  );
}
export function PageHeading({
  eyebrow,
  title,
  description,
  actions,
  meta,
  back,
}: {
  eyebrow?: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  meta?: ReactNode;
  back?: { to: string; label: string };
}) {
  useDocumentTitle(title);
  return (
    <header className="page-heading">
      {back && (
        <Link className="back-link" to={back.to}>
          <ArrowLeft size={14} aria-hidden="true" />
          {back.label}
        </Link>
      )}
      <div className="page-heading-row">
        <div className="page-heading-text">
          {eyebrow && <p className="eyebrow">{eyebrow}</p>}
          <h1>{title}</h1>
          {description && <div className="page-description">{description}</div>}
        </div>
        {actions && <div className="heading-actions">{actions}</div>}
      </div>
      {meta && <div className="page-meta">{meta}</div>}
    </header>
  );
}
export function Panel({
  title,
  description,
  actions,
  children,
  className = "",
  padded = false,
}: {
  title?: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  const titleId = useId();
  return (
    <section
      className={`panel ${className}`}
      aria-labelledby={title ? titleId : undefined}
    >
      {(title || actions) && (
        <div className="panel-heading">
          <div className="panel-titles">
            {title && <h2 id={titleId}>{title}</h2>}
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      {padded ? <div className="panel-body">{children}</div> : children}
    </section>
  );
}
export function Empty({
  title,
  description,
  action,
  icon: Icon = Inbox,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  icon?: LucideIcon;
}) {
  return (
    <div className="empty-state">
      <div className="empty-icon" aria-hidden="true">
        <Icon size={20} />
      </div>
      <h3>{title}</h3>
      {description && <p>{description}</p>}
      {action}
    </div>
  );
}
export function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <div className="callout danger" role="alert">
      <CircleAlert size={17} aria-hidden="true" />
      <div className="callout-body">{children}</div>
    </div>
  );
}
const calloutIcons: Record<string, LucideIcon> = {
  info: Info,
  warm: TriangleAlert,
  danger: CircleAlert,
  good: CircleCheck,
};
/** A persistent, non-interrupting status message (not announced as an alert). */
export function Callout({
  tone = "info",
  title,
  children,
  action,
}: {
  tone?: "info" | "warm" | "danger" | "good";
  title?: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  const Icon = calloutIcons[tone];
  return (
    <div className={`callout ${tone}`}>
      <Icon size={17} aria-hidden="true" />
      <div className="callout-body">
        {title && <strong className="callout-title">{title}</strong>}
        {children}
      </div>
      {action && <div className="callout-action">{action}</div>}
    </div>
  );
}
export function DataState({
  loading,
  error,
  retry,
  children,
  hasData = false,
}: {
  loading: boolean;
  error?: string;
  retry: () => void;
  children: ReactNode;
  hasData?: boolean;
}) {
  if (loading && !hasData)
    return (
      <div className="loading-state" role="status">
        <LoaderCircle className="spin" size={18} aria-hidden="true" /> Loading…
      </div>
    );
  const note = error && (
    <ErrorNote>
      {error}{" "}
      <button className="text-button" onClick={retry}>
        Try again
      </button>
    </ErrorNote>
  );
  if (error && !hasData) return note;
  return (
    <>
      {note}
      {children}
    </>
  );
}
export function ActionButton({
  children,
  onAction,
  className = "",
  disabled = false,
  confirm,
  title,
}: {
  children: ReactNode;
  onAction: () => Promise<unknown>;
  className?: string;
  disabled?: boolean;
  /** When set, the first click arms the button and shows this label. */
  confirm?: string;
  title?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [armed, setArmed] = useState(false);
  const [error, setError] = useState<string>();
  useEffect(() => {
    if (!armed) return;
    const timeout = setTimeout(() => setArmed(false), 4000);
    return () => clearTimeout(timeout);
  }, [armed]);
  return (
    <span className="action-control">
      <button
        type="button"
        title={title}
        className={`${className} ${armed ? "armed" : ""}`}
        disabled={disabled || busy}
        onClick={async () => {
          if (confirm && !armed) {
            setArmed(true);
            return;
          }
          setArmed(false);
          setBusy(true);
          setError(undefined);
          try {
            await onAction();
          } catch (e) {
            setError(e instanceof Error ? e.message : "The action failed.");
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy && <LoaderCircle size={15} className="spin" aria-hidden="true" />}
        {armed ? confirm : children}
      </button>
      {armed && (
        <span className="sr-only" role="status">
          Press again to confirm.
        </span>
      )}
      {error && (
        <span className="action-error" role="alert">
          {error}
        </span>
      )}
    </span>
  );
}
export function Modal({
  title,
  description,
  onClose,
  children,
  size = "default",
  headerActions,
}: {
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  size?: "default" | "wide" | "drawer" | "palette";
  headerActions?: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const dialog = ref.current;
    if (dialog && !dialog.open) dialog.showModal();
    // showModal() focuses the first focusable control (the close button);
    // move focus to the field the dialog marks as its starting point.
    dialog?.querySelector<HTMLElement>("[data-autofocus]")?.focus();
    return () => dialog?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className={`modal modal-${size}`}
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        // Drawers and the palette hold no unsaved input, so a backdrop click
        // dismisses them.
        if (
          (size === "drawer" || size === "palette") &&
          e.target === e.currentTarget
        )
          onClose();
      }}
    >
      <div className="modal-heading">
        <div>
          <h2 id={titleId}>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        <div className="modal-heading-actions">
          {headerActions}
          <button
            type="button"
            className="icon-button"
            aria-label="Close dialog"
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </div>
      </div>
      <div className="modal-body">{children}</div>
    </dialog>
  );
}
export function JsonView({ value }: { value: unknown }) {
  return <pre className="json-view">{readable(value)}</pre>;
}
export function Evidence({
  value,
  label = "Evidence",
}: {
  value: unknown;
  label?: string;
}) {
  return (
    <details className="evidence">
      <summary>{label}</summary>
      <JsonView value={value} />
    </details>
  );
}
export function ExternalLink({
  href,
  children,
  className,
}: {
  href: string | null | undefined;
  children: ReactNode;
  className?: string;
}) {
  const safe = safeHref(href);
  return safe ? (
    <a
      className={`external-link ${className || ""}`}
      href={safe}
      target="_blank"
      rel="noreferrer"
    >
      {children}
      <ArrowUpRight size={13} aria-hidden="true" />
    </a>
  ) : (
    <span>{children}</span>
  );
}
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timeout = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timeout);
  }, [copied]);
  return (
    <button
      type="button"
      className="icon-button copy-button"
      aria-label={copied ? "Copied" : label}
      title={copied ? "Copied" : label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
    </button>
  );
}
/** GitHub-flavored Markdown: tables, task lists, strikethrough, footnotes. */
const markdownPlugins = [remarkGfm];
export function Markdown({
  children,
  artifactLink,
  compact = false,
}: {
  children: string;
  /** Inline use without report padding, e.g. inside lists and cards. */
  compact?: boolean;
  artifactLink?: (
    href: string,
  ) => { url: string; open: () => void } | undefined;
}) {
  return (
    <div className={compact ? "markdown compact" : "markdown"}>
      <ReactMarkdown
        remarkPlugins={markdownPlugins}
        components={{
          img: ({ alt }) => <span>{alt || "Report image"}</span>,
          table: ({ children }) => (
            <div className="markdown-table">
              <table>{children}</table>
            </div>
          ),
          a: ({ href, children }) => {
            // Footnote references and anchors stay on the current page.
            if (href?.startsWith("#")) return <a href={href}>{children}</a>;
            const artifact = href ? artifactLink?.(href) : undefined;
            return artifact ? (
              <a
                href={artifact.url}
                onClick={(event) => {
                  event.preventDefault();
                  artifact.open();
                }}
              >
                {children}
              </a>
            ) : (
              <ExternalLink href={href}>{children}</ExternalLink>
            );
          },
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
export function Tabs({
  items,
  active,
  onChange,
  label,
}: {
  items: { id: string; label: string; count?: number }[];
  active: string;
  onChange: (id: string) => void;
  label?: string;
}) {
  const list = useRef<HTMLDivElement>(null);
  return (
    <div
      className="tabs"
      role="tablist"
      aria-label={label}
      ref={list}
      onKeyDown={(e) => {
        const index = items.findIndex((item) => item.id === active);
        const next =
          e.key === "ArrowRight"
            ? (index + 1) % items.length
            : e.key === "ArrowLeft"
              ? (index - 1 + items.length) % items.length
              : e.key === "Home"
                ? 0
                : e.key === "End"
                  ? items.length - 1
                  : -1;
        if (next < 0) return;
        e.preventDefault();
        onChange(items[next].id);
        const tabs =
          list.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
        tabs?.[next]?.focus();
      }}
    >
      {items.map((item) => (
        <button
          key={item.id}
          type="button"
          role="tab"
          aria-selected={active === item.id}
          tabIndex={active === item.id ? 0 : -1}
          onClick={() => onChange(item.id)}
        >
          {item.label}
          {item.count !== undefined && (
            <span className="tab-count">{item.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}
/** A compact single-choice filter. */
export function Segmented({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { value: string; label: string; count?: number }[];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
          {option.count !== undefined && (
            <span className="segment-count">{option.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}
/** Search input with a clear button; `onChange` fires on every keystroke. */
export function SearchField({
  label,
  value,
  onChange,
  placeholder,
  busy = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  busy?: boolean;
}) {
  return (
    <div className="search-field">
      <Search size={16} aria-hidden="true" />
      <input
        type="search"
        aria-label={label}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape" && value) {
            e.preventDefault();
            onChange("");
          }
        }}
      />
      {busy ? (
        <LoaderCircle className="spin" size={15} aria-label="Searching" />
      ) : (
        value && (
          <button
            type="button"
            className="icon-button"
            aria-label="Clear search"
            onClick={() => onChange("")}
          >
            <X size={15} />
          </button>
        )
      )}
    </div>
  );
}
/** A compact labeled select for secondary filters and sort order. */
export function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string; count?: number }[];
}) {
  return (
    <label className="filter-select">
      <span>{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
            {option.count !== undefined ? ` (${option.count})` : ""}
          </option>
        ))}
      </select>
    </label>
  );
}
/** "Showing X of Y" with a reset action when any filter narrows the list. */
export function ResultSummary({
  shown,
  total,
  noun,
  onClear,
  truncated = false,
}: {
  shown: number;
  total: number;
  noun: [string, string];
  onClear?: () => void;
  truncated?: boolean;
}) {
  const word = (n: number) => (n === 1 ? noun[0] : noun[1]);
  return (
    <p className="result-summary" role="status">
      {shown === total
        ? `${total} ${word(total)}`
        : `Showing ${shown} of ${total} ${word(total)}`}
      {truncated && ` · only the first ${total} were loaded`}
      {onClear && shown !== total && (
        <button type="button" className="text-button" onClick={onClear}>
          Clear filters
        </button>
      )}
    </p>
  );
}
/**
 * Renders long lists in steps so pages stay short while search and filters
 * still cover the whole collection. Resets when `resetKey` changes.
 */
export function useShowMore<T>(items: T[], resetKey: string, step = 50) {
  const [limit, setLimit] = useState(step);
  const [key, setKey] = useState(resetKey);
  if (key !== resetKey) {
    setKey(resetKey);
    setLimit(step);
  }
  return {
    shown: items.slice(0, limit),
    footer: items.length > limit && (
      <div className="show-more">
        <span className="muted">
          Showing {limit} of {items.length}
        </span>
        <button
          type="button"
          className="secondary"
          onClick={() => setLimit((n) => n + step)}
        >
          Show {Math.min(step, items.length - limit)} more
        </button>
        <button
          type="button"
          className="text-button"
          onClick={() => setLimit(items.length)}
        >
          Show all
        </button>
      </div>
    ),
  };
}
export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}
export type Severity = "critical" | "high" | "medium" | "low" | "none";
/** CVSS v3/v4 qualitative rating for a Base score. */
export function severityOf(score: number | undefined): Severity {
  if (score === undefined) return "none";
  return score >= 9
    ? "critical"
    : score >= 7
      ? "high"
      : score >= 4
        ? "medium"
        : score > 0
          ? "low"
          : "none";
}
export const severityLabels: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  none: "Unscored",
};
/** Case-insensitive match of every whitespace-separated term in `query`. */
export function matches(
  query: string,
  ...fields: (string | null | undefined)[]
) {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return true;
  const haystack = fields.filter(Boolean).join(" ").toLowerCase();
  return terms.every((term) => haystack.includes(term));
}
export function countBy<T>(items: T[], key: (item: T) => string) {
  const counts: Record<string, number> = {};
  for (const item of items) counts[key(item)] = (counts[key(item)] || 0) + 1;
  return counts;
}
export function Pagination({
  next,
  onNext,
  onFirst,
  showFirst = false,
}: {
  next: string | null | undefined;
  onNext: (cursor: string) => void;
  onFirst: () => void;
  showFirst?: boolean;
}) {
  if (!next && !showFirst) return null;
  return (
    <div className="pagination">
      {showFirst && (
        <button className="secondary" onClick={onFirst}>
          First page
        </button>
      )}
      {next && (
        <button className="secondary" onClick={() => onNext(next)}>
          Next page
        </button>
      )}
    </div>
  );
}
export function DetailGrid({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="detail-grid">
      {items.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
export function JobLink({ id }: { id: string }) {
  return (
    <Link className="inline-link" to={`/jobs/${encodeURIComponent(id)}`}>
      View job <ArrowUpRight size={14} aria-hidden="true" />
    </Link>
  );
}
const DIFF_HIGHLIGHT_LIMIT = 8000;
function diffLineClass(line: string) {
  if (line.startsWith("+++") || line.startsWith("---")) return "diff-file";
  if (line.startsWith("diff ") || line.startsWith("index ")) return "diff-file";
  if (line.startsWith("@@")) return "diff-hunk";
  if (line.startsWith("+")) return "diff-add";
  if (line.startsWith("-")) return "diff-del";
  return "diff-context";
}
/** Unified diff with added, removed, and hunk lines distinguished. */
export function DiffView({
  diff,
  wrap = false,
}: {
  diff: string;
  wrap?: boolean;
}) {
  const lines = diff.replace(/\n$/, "").split("\n");
  if (lines.length > DIFF_HIGHLIGHT_LIMIT)
    return <pre className={`source-code ${wrap ? "wrap" : ""}`}>{diff}</pre>;
  return (
    <pre className={`source-code diff-view ${wrap ? "wrap" : ""}`}>
      <code>
        {lines.map((line, i) => (
          <span key={i} className={diffLineClass(line)}>
            {line || " "}
            {"\n"}
          </span>
        ))}
      </code>
    </pre>
  );
}
