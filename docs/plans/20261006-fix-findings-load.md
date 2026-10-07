# Faster Findings reads

The Findings menu waited 25–70 seconds for two rows and received 7.5 MB of unused artifact metadata. A profile attributed 20.1 of 23.4 seconds to loading a 24,126-file/171 MB bundle. Saved version evidence also failed the frontend's string-only schema.

The governing contract is `docs/implementation-contract.md`, with the read strategy in `docs/design/numen-design.md` and retained presentation in `docs/ui-spec/numen-ui-spec.md`.

1. Add focused API and React regression coverage for compact/scoped/paginated reads, latest lab status, readable versions, and evidence-preserving edits. Reproduce the existing failures.
2. Publish completeness in the finding's existing JSON paired with its artifact revision. Preserve that private state on operator edits. Existing or changed revisions derive completeness from metadata and the two parsed declarations. Preview/download/lab paths continue validating actual bytes.
3. Add the optional summary list projection and switch the register, program counts, and quick search to it. Preserve default full responses. Accept strings and structured version records and reuse the existing label formatting behavior.
4. Run focused and affected backend/frontend suites plus lint, types, formatting, and production build. Refresh only services whose active jobs can safely continue. Populate existing revision summaries atomically and measure actual HTTP/browser load and response size on the existing large finding.

Proof is the real API with SQLite for summary/persistence/integrity behavior, React with the API boundary controlled for display/edit behavior, and the running PostgreSQL/browser stack for the measured latency improvement. Assert elimination of artifact reads rather than fragile wall-clock thresholds in automated tests. No model inference, dependency updates, or database schema changes are required.
