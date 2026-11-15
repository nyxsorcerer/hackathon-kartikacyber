import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { z } from "zod";
import { request } from "./api";
/**
 * Loads a value for `key` and keeps it fresh.
 *
 * `loading` is only true while no data exists for the current key, so
 * refreshes and polling never replace rendered content with a spinner.
 * With `keepPrevious`, data from the previous key stays visible while a new
 * key (search, filter, page) loads; `refreshing` reports that request.
 * A `null` key skips loading.
 */
function useLoader<T>(
  key: string | null,
  load: (key: string, signal: AbortSignal) => Promise<T>,
  pollMs: number,
  keepPrevious: boolean,
) {
  const [snapshot, setSnapshot] = useState<{ key: string; value: T }>();
  const current = snapshot?.key === key;
  const data = current || keepPrevious ? snapshot?.value : undefined;
  const [error, setError] = useState<string>();
  const [pending, setPending] = useState(key !== null);
  const [revision, setRevision] = useState(0);
  const refresh = useCallback(() => setRevision((n) => n + 1), []);
  useEffect(() => {
    if (key === null) return;
    const abort = new AbortController();
    setPending(true);
    load(key, abort.signal)
      .then((value) => {
        if (!abort.signal.aborted) {
          setSnapshot({ key, value });
          setError(undefined);
          setPending(false);
        }
      })
      .catch((err: unknown) => {
        if (!abort.signal.aborted) {
          setError(
            err instanceof Error ? err.message : "Unable to load this page.",
          );
          setPending(false);
        }
      });
    return () => abort.abort();
    // `load` closes over the caller's schema, which is defined statically.
  }, [key, revision]);
  useEffect(() => {
    if (!pollMs || key === null) return;
    const interval = setInterval(refresh, pollMs);
    return () => clearInterval(interval);
  }, [pollMs, key, refresh]);
  return {
    data,
    error,
    loading: pending && data === undefined,
    refreshing: pending,
    refresh,
  };
}
export function useResource<T>(
  path: string | null,
  schema: z.ZodType<T>,
  pollMs = 0,
  keepPrevious = false,
) {
  return useLoader(
    path,
    (key, signal) => request(key, schema, { signal }),
    pollMs,
    keepPrevious,
  );
}
export type Collection<T> = {
  data?: { items: T[]; truncated: boolean };
  error?: string;
  loading: boolean;
  refreshing: boolean;
  refresh: () => void;
};
const PAGE_SIZE = 200;
/**
 * Loads every page of a cursor-paginated list (up to `max` items) so views can
 * search, filter, and sort the whole collection instantly in the browser.
 */
export function useCollection<T>(
  path: string | null,
  schema: z.ZodType<{ items: T[]; next_cursor: string | null }>,
  pollMs = 0,
  max = 1000,
): Collection<T> {
  return useLoader(
    path,
    async (key, signal) => {
      const items: T[] = [];
      let cursor: string | null = null;
      do {
        const query = new URLSearchParams({ limit: String(PAGE_SIZE) });
        if (cursor) query.set("cursor", cursor);
        const page: { items: T[]; next_cursor: string | null } = await request(
          `${key}${key.includes("?") ? "&" : "?"}${query}`,
          schema,
          { signal },
        );
        items.push(...page.items);
        cursor = page.next_cursor;
      } while (cursor && items.length < max);
      return { items, truncated: !!cursor };
    },
    pollMs,
    true,
  );
}
/**
 * Reads and updates several URL query parameters together, so filters survive
 * refresh, back/forward, and can be shared as links. Defaults are omitted from
 * the URL. Updates replace the history entry.
 */
export function useQueryState<K extends string>(defaults: Record<K, string>) {
  const [params, setParams] = useSearchParams();
  const values = Object.fromEntries(
    Object.entries<string>(defaults).map(([key, fallback]) => [
      key,
      params.get(key) ?? fallback,
    ]),
  ) as Record<K, string>;
  const update = useCallback(
    (patch: Partial<Record<K, string | null>>) =>
      setParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          for (const [key, value] of Object.entries(patch) as [
            K,
            string | null | undefined,
          ][]) {
            if (!value || value === defaults[key]) next.delete(key);
            else next.set(key, value);
          }
          return next;
        },
        { replace: true },
      ),
    // Defaults are static per call site.
    [setParams],
  );
  return [values, update] as const;
}
/** Fetches an artifact's text content (skipped when `id` is undefined). */
export function useArtifactText(id: string | undefined) {
  const [state, setState] = useState<{
    id: string;
    text?: string;
    error?: string;
  }>();
  useEffect(() => {
    if (!id) return;
    const controller = new AbortController();
    fetch(`/api/artifacts/${encodeURIComponent(id)}/content`, {
      credentials: "same-origin",
      signal: controller.signal,
    })
      .then((r) => {
        if (!r.ok) throw new Error(`Unable to read artifact (${r.status}).`);
        return r.text();
      })
      .then((text) => setState({ id, text }))
      .catch((e: unknown) => {
        if (!controller.signal.aborted)
          setState({
            id,
            error: e instanceof Error ? e.message : "Artifact unavailable.",
          });
      });
    return () => controller.abort();
  }, [id]);
  return state?.id === id ? state : undefined;
}
export function useDebounced<T>(value: T, ms = 250) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timeout = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(timeout);
  }, [value, ms]);
  return debounced;
}
export function useDocumentTitle(title: string | undefined) {
  useEffect(() => {
    if (title) document.title = `${title} · GarudaNetra`;
  }, [title]);
}
/** Runs `handler` for single-key shortcuts when focus is not in a text field. */
export function useShortcut(
  keys: string[],
  handler: (key: string) => void,
  enabled = true,
) {
  useEffect(() => {
    if (!enabled) return;
    const listener = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || e.defaultPrevented) return;
      const target = e.target;
      if (
        target instanceof HTMLElement &&
        (target.isContentEditable ||
          ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))
      )
        return;
      if (keys.includes(e.key)) {
        e.preventDefault();
        handler(e.key);
      }
    };
    window.addEventListener("keydown", listener);
    return () => window.removeEventListener("keydown", listener);
  }, [keys, handler, enabled]);
}
