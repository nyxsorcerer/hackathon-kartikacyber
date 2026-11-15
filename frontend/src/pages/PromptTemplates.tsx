import { useEffect, useId, useState } from "react";
import { Eye, FileDown, RotateCcw, Save } from "lucide-react";
import { mutate } from "../api";
import { useQueryState, useResource } from "../hooks";
import {
  operationNames,
  promptPreviewSchema,
  promptTemplateSchema,
  promptTemplatesSchema,
} from "../types";
import type { Operation, PromptTemplate } from "../types";
import {
  ActionButton,
  Badge,
  Callout,
  DataState,
  FilterSelect,
  humanize,
  notify,
  Panel,
  Time,
} from "../components/ui";

/** Operations read as their job name; sections by the name an include uses. */
function templateLabel(name: string, kind = "operation") {
  return kind === "operation"
    ? operationNames[name as Operation] || humanize(name)
    : name;
}
// Drafts outlive the editor for the browser session, so leaving Settings or
// switching tabs never discards them.
const draftsKey = "numen:prompt-drafts";
function loadDrafts(): Record<string, string> {
  try {
    const value: unknown = JSON.parse(
      sessionStorage.getItem(draftsKey) || "{}",
    );
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    return Object.fromEntries(
      Object.entries(value).filter(([, v]) => typeof v === "string"),
    ) as Record<string, string>;
  } catch {
    return {};
  }
}
function wordCount(text: string) {
  return text.split(/\s+/).filter(Boolean).length;
}
/**
 * Settings › Prompts: every agent operation's prompt is a template built from
 * shared sections. Drafts survive switching templates and are only sent on Save.
 */
export function PromptTemplates() {
  const resource = useResource("/prompts", promptTemplatesSchema);
  const [query, update] = useQueryState({ prompt: "" });
  const [drafts, setDrafts] = useState(loadDrafts);
  useEffect(() => {
    try {
      if (Object.keys(drafts).length)
        sessionStorage.setItem(draftsKey, JSON.stringify(drafts));
      else sessionStorage.removeItem(draftsKey);
    } catch {
      // Without storage, drafts last while the editor stays open.
    }
  }, [drafts]);
  // Rows just saved, shown until the refreshed list arrives.
  const [saved, setSaved] = useState<Record<string, PromptTemplate>>({});
  useEffect(() => setSaved({}), [resource.data]);
  const items = (resource.data?.items || []).map((t) => saved[t.name] || t);
  const operations = items.filter((t) => t.kind === "operation");
  const sections = items.filter((t) => t.kind === "section");
  const selected =
    items.find((t) => t.name === query.prompt) || operations[0] || items[0];
  const isDirty = (t: PromptTemplate) =>
    drafts[t.name] !== undefined && drafts[t.name] !== t.source;
  const anyDirty = items.some(isDirty);
  useEffect(() => {
    if (!anyDirty) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [anyDirty]);
  const setDraft = (name: string, source: string | undefined) =>
    setDrafts((previous) => {
      const next = { ...previous };
      if (source === undefined) delete next[name];
      else next[name] = source;
      return next;
    });
  const group = (title: string, list: PromptTemplate[]) => (
    <div className="prompt-nav-group">
      <h3>{title}</h3>
      <ul>
        {list.map((t) => (
          <li key={t.name}>
            <button
              type="button"
              aria-current={t.name === selected?.name ? "true" : undefined}
              onClick={() => update({ prompt: t.name })}
            >
              <span className={t.kind === "section" ? "mono" : undefined}>
                {templateLabel(t.name, t.kind)}
              </span>
              {isDirty(t) ? (
                <Badge tone="warm">Unsaved</Badge>
              ) : (
                t.customized && <Badge tone="accent">Customized</Badge>
              )}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
  return (
    <Panel
      title="Prompt templates"
      description="Each operation's prompt is a template built from shared sections. A saved change applies to the next job; running jobs keep the prompt they started with."
    >
      <DataState
        loading={resource.loading}
        error={resource.error}
        retry={resource.refresh}
        hasData={!!resource.data}
      >
        {selected && (
          <div className="prompt-workbench">
            <nav className="prompt-nav" aria-label="Prompt templates">
              {group("Operations", operations)}
              {group("Shared sections", sections)}
            </nav>
            <TemplateEditor
              key={selected.name}
              template={selected}
              draft={drafts[selected.name] ?? selected.source}
              variables={resource.data?.variables || {}}
              onDraft={(source) => setDraft(selected.name, source)}
              onSaved={(row) => {
                setSaved((previous) => ({ ...previous, [row.name]: row }));
                setDraft(row.name, undefined);
                resource.refresh();
              }}
              onOpen={(name) => update({ prompt: name })}
            />
          </div>
        )}
      </DataState>
    </Panel>
  );
}
function TemplateEditor({
  template,
  draft,
  variables,
  onDraft,
  onSaved,
  onOpen,
}: {
  template: PromptTemplate;
  draft: string;
  variables: Record<string, string>;
  onDraft: (source: string | undefined) => void;
  onSaved: (row: PromptTemplate) => void;
  onOpen: (name: string) => void;
}) {
  const sourceId = useId();
  const dirty = draft !== template.source;
  const [showDefault, setShowDefault] = useState(false);
  const targets =
    template.kind === "operation" ? [template.name] : template.used_by;
  const [previewIn, setPreviewIn] = useState(targets[0] || "");
  const [preview, setPreview] = useState<{
    prompt: string;
    of: string;
  }>();
  const related =
    template.kind === "section" ? template.used_by : template.includes;
  return (
    <section className="prompt-editor" aria-labelledby={`${sourceId}-title`}>
      <header className="prompt-editor-head">
        <div>
          <h3 id={`${sourceId}-title`}>
            {templateLabel(template.name, template.kind)}
          </h3>
          <p className="hint">{template.description}</p>
          <p className="prompt-relations">
            {template.kind === "section" ? "Used by" : "Includes"}{" "}
            {related.length ? (
              related.map((name, i) => (
                <span key={name}>
                  {i > 0 && ", "}
                  <button
                    type="button"
                    className="text-button"
                    onClick={() => onOpen(name)}
                  >
                    {template.kind === "section" ? templateLabel(name) : name}
                  </button>
                </span>
              ))
            ) : (
              <span className="muted">
                {template.kind === "section" ? "no operation" : "no sections"}
              </span>
            )}
          </p>
        </div>
        <div className="prompt-state">
          {template.customized ? (
            <>
              <Badge tone="accent">Customized</Badge>
              {template.updated_at && (
                <small>
                  Saved <Time value={template.updated_at} />
                </small>
              )}
            </>
          ) : (
            <Badge tone="neutral">Default</Badge>
          )}
        </div>
      </header>
      {template.default_changed && (
        <Callout
          tone="warm"
          title="The default changed after you customized this template"
          action={
            <button
              type="button"
              className="secondary"
              onClick={() => setShowDefault(true)}
            >
              Compare with default
            </button>
          }
        >
          Review the new default and merge what you need, or reset to it.
        </Callout>
      )}
      <label className="prompt-source-field">
        Template
        <textarea
          className="prompt-source"
          spellCheck={false}
          autoComplete="off"
          value={draft}
          onChange={(e) => onDraft(e.target.value)}
        />
      </label>
      <div className="prompt-source-meta">
        <span>
          {draft.length.toLocaleString()} characters
          {dirty && " · Unsaved changes"}
        </span>
        <span>GarudaNetra appends the run's facts after the prompt.</span>
      </div>
      <div className="form-actions prompt-actions">
        {(template.customized || dirty) && (
          <button
            type="button"
            className="secondary"
            aria-expanded={showDefault}
            onClick={() => setShowDefault((shown) => !shown)}
          >
            {showDefault ? "Hide default" : "Show default"}
          </button>
        )}
        {template.customized && (
          <ActionButton
            className="secondary"
            confirm="Reset to default?"
            title="Discard your version; jobs use the shipped default again."
            onAction={async () => {
              const row = await mutate(
                `/prompts/${encodeURIComponent(template.name)}`,
                promptTemplateSchema,
                {},
                "DELETE",
              );
              onSaved(row);
              notify(
                `${templateLabel(template.name, template.kind)} uses the default again.`,
              );
            }}
          >
            <RotateCcw size={15} aria-hidden="true" />
            Reset to default
          </ActionButton>
        )}
        {dirty && (
          <button
            type="button"
            className="secondary"
            onClick={() => onDraft(undefined)}
          >
            Discard changes
          </button>
        )}
        <ActionButton
          className="primary"
          disabled={!dirty}
          onAction={async () => {
            const row = await mutate(
              `/prompts/${encodeURIComponent(template.name)}`,
              promptTemplateSchema,
              { source: draft },
              "PUT",
            );
            onSaved(row);
            notify(
              row.customized
                ? "Template saved. The next job that uses it renders this version."
                : "Template matches the default again.",
            );
          }}
        >
          <Save size={15} aria-hidden="true" />
          Save template
        </ActionButton>
      </div>
      {showDefault && (
        <div className="prompt-default">
          <div className="prompt-block-head">
            <h4>Shipped default</h4>
            <button
              type="button"
              className="text-button"
              disabled={draft === template.default_source}
              onClick={() => onDraft(template.default_source)}
            >
              <FileDown size={14} aria-hidden="true" />
              Load into editor
            </button>
          </div>
          <pre>{template.default_source}</pre>
        </div>
      )}
      <details className="prompt-help">
        <summary>Template syntax</summary>
        <ul>
          <li>
            <code>{'{% include "attack-path" %}'}</code> inserts a shared
            section by name.
          </li>
          {Object.entries(variables).map(([name, description]) => (
            <li key={name}>
              <code>{`{{ ${name} }}`}</code> {description}
            </li>
          ))}
          <li>
            <code>{"{% if facts.audit_context %}…{% endif %}"}</code> keeps text
            only when the condition holds; <code>{"{# note #}"}</code> is a
            comment jobs never see.
          </li>
        </ul>
      </details>
      <div className="prompt-preview">
        <div className="prompt-block-head">
          <h4>Preview</h4>
          {targets.length > 1 && (
            <FilterSelect
              label="Render in"
              value={previewIn}
              onChange={setPreviewIn}
              options={targets.map((name) => ({
                value: name,
                label: templateLabel(name),
              }))}
            />
          )}
          <ActionButton
            className="secondary"
            disabled={!previewIn}
            title={
              previewIn
                ? "Render the prompt a job would receive, with your unsaved edits"
                : "No operation includes this section"
            }
            onAction={async () => {
              const result = await mutate(
                "/prompts/preview",
                promptPreviewSchema,
                { operation: previewIn, name: template.name, source: draft },
              );
              setPreview({ ...result, of: `${previewIn}\n${draft}` });
            }}
          >
            <Eye size={15} aria-hidden="true" />
            {preview ? "Refresh preview" : "Preview"}
          </ActionButton>
        </div>
        {preview ? (
          <>
            <p className="hint">
              {wordCount(preview.prompt).toLocaleString()} words
              {preview.of !== `${previewIn}\n${draft}` &&
                " · out of date, refresh to include your latest edits"}
            </p>
            <pre className="prompt-rendered">{preview.prompt}</pre>
          </>
        ) : (
          <p className="hint">
            Render the prompt a job would receive, including your unsaved edits.
            Errors that would stop a job appear here before you save.
          </p>
        )}
      </div>
    </section>
  );
}
