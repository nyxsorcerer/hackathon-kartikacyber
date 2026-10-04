# Evidence and primary references

Initial inspection: 2026-10-03. Implementation verification continued on 2026-10-04. Source behavior can change; shipped packages are pinned and account capability checks remain explicit. These references establish integration facts; executed repository checks are recorded in [verification](verification.md).

## Workspace evidence

| Observation | How observed | Effect |
|---|---|---|
| The workspace was empty at the start | Directory listing and `rg --files --hidden` | New application; no existing stack, schema, or UI pattern |
| No Git repository existed | `git status --short --branch` failed with not-a-repository | There is no existing history or PR workflow to preserve |
| No applicable ancestor `AGENTS.md` was found | Checked the workspace and each ancestor | No repository-specific implementation rules discovered |
| Pi is available locally | Installed package metadata and `pi --help` | Installed `@earendil-works/pi-coding-agent` version `1.0.0`; use as a compatibility reference, not a floating production dependency |
| Claude Code is available locally | `claude --help`, `claude --version` | Installed version `2.1.288`; model/effort flags and structured output are available |
| Codex CLI is available locally | `codex --version`, `codex exec --help`, `codex login --help` | Installed version `0.160.0`; noninteractive execution, JSON/schema output, model selection, sandbox modes, and native login flags are available |
| Docker CLI was not on the initial PATH | Later located under Docker.app; engine/Compose checks succeeded | Docker launcher handles its CLI/helper path; actual image/runtime tests now execute against Engine 20.10.22 |

The local CLIs were inspected without logging into providers, reading credential files, or invoking paid agent work.

## Pi

The current project supports provider selection and native connection setup. Local help confirms noninteractive print mode, JSON/RPC modes, model selection, `--thinking`, explicit skills/extensions, and resource-discovery controls. The installed CLI accepts `off`, `minimal`, `low`, `medium`, `high`, `xhigh`, and `max`; this is the CLI vocabulary, not a guarantee that every model accepts every value.

- [Current Pi repository README](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/README.md)
- Local inspected documentation: `/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent/docs/`.

## Claude Code

Programmatic print mode exposes JSON/schema output and controlled tool permissions. Bare mode uses API credentials and does not read subscription OAuth credentials; the adapter must distinguish those connection modes.

- [Run Claude Code programmatically](https://code.claude.com/docs/en/headless)
- Local help supplies `--model`, `--effort`, `--output-format`, `--json-schema`, and `--allowedTools` for the inspected version.

## Codex CLI

Codex was added to the requested agent scope in the user's follow-up. Local version `0.160.0` was inspected without reading authentication files or starting an agent run. Its exec help confirms JSONL events, schema-constrained final output, model selection, ephemeral sessions, and read-only/workspace-write sandbox choices. The application still needs container/proxy and credentialed compatibility checks.

Official OpenAI documentation supplies the execution, authentication, and capability contracts:

- [Non-interactive execution](https://learn.chatgpt.com/docs/non-interactive-mode): `codex exec`, `--json`, `--output-schema`, and final-message output.
- [Configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference): `model_reasoning_effort`, project-instruction limits, and sandbox policy. Effort values depend on the model/client.
- [Authentication](https://learn.chatgpt.com/docs/auth): OpenAI API-key or eligible ChatGPT login; headless device-code login is account/workspace-dependent.
- [App-server model discovery](https://learn.chatgpt.com/docs/app-server): `model/list` returns available models and supported/default reasoning efforts. Paginate and use returned values rather than hardcoding a model list.

Use the shared audit coordinator with the pinned Trail of Bits inputs. Codex support does not imply that a Claude plugin command executes natively in Codex. No live Codex provider, subscription, or Docker workload was verified during this planning update.

## TypeSafe AI Jev

The user supplied TypeSafe AI's announcement. Its documentation defines a typed evaluation API and choice/probability outputs. The planned application uses it for optional commit triage. Report writing, script creation, and code investigation use Pi, Claude Code, or Codex CLI.

- [User-supplied introduction](https://typesafe.ai/blog/introducing-system-one-models-and-jev)
- [API reference](https://docs.typesafe.ai/api): `POST https://api.typesafe.ai/v1/systemone`, bearer authentication, and `state`, `model`, `questions`, and `answers` envelopes.
- [Question primitives](https://docs.typesafe.ai/primitives): Choice supplies a decision and probabilities. The application's exact triage criteria are authored in the architecture.

No accuracy, latency, or cost claim from the vendor is an application acceptance guarantee. No Jev request was made.

## Command Code Pi provider

The specified community plugin provides a Command Code connection, credential setup, model discovery, and model-specific reasoning capability. Pin and test it with the selected Pi version. Its account access and quota reporting are provider-dependent; missing prices or usage are not proof of zero cost.

- [User-supplied provider repository](https://github.com/patlux/pi-commandcode-provider/)

## Trail of Bits audit context building

The installed plugin inspected for this plan is version `2.0.2` at:

`/Users/nyxmare/.codex/plugins/cache/trailofbits/audit-context-building/2.0.2/`

Its README and skill describe orientation, delegated per-function work, and synthesis. Outputs include `audit-context/DOSSIER.md` and supporting function documents. The adapter must preserve source evidence and open questions, then expose the requested `audit-context-building.md` entry document. Context generation is distinct from vulnerability investigation.

- [Upstream skills repository](https://github.com/trailofbits/skills)
- [Inspected SKILL.md](/Users/nyxmare/.codex/plugins/cache/trailofbits/audit-context-building/2.0.2/skills/audit-context-building/SKILL.md)
- Local companion sources: `README.md`, `agents/function-analyzer.md`, `workflows/audit-context.js`, and `resources/ANALYSIS_FORMAT.md` under the skill directory.

The implementation must vendor/pin a portable copy with license and revision metadata. Runtime must not depend on this operator-specific local path. No target codebase was audited for this documentation task.

## GitHub and WordPress

GitHub exposes commit listing and commit details. The collector still needs to identify the tracked reference, fetch complete history/diffs, and preserve its cursor after partial failure.

- [GitHub commit API](https://docs.github.com/en/rest/commits/commits)

WordPress.org distributes plugin source through SVN. Its handbook distinguishes that release history from a development workflow; a WordPress source must therefore work without GitHub and retain its SVN revision/path.

- [WordPress SVN handbook](https://developer.wordpress.org/plugins/wordpress-org/how-to-use-subversion/)

## CVE / CVSS

NVD's official response schema includes versioned CVSS metric structures. NIST also documents updates to existing scores; ingestion must refresh modified records rather than tracking publication alone. Product matching and version applicability are application responsibilities.

- [Official NVD CVE API JSON schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
- [NIST NVD notices, including score corrections](https://www.nist.gov/itl/nvd)
- [NVD CVE/CVSS FAQs](https://nvd.nist.gov/general/FAQ-Sections/CVE-FAQs)

The old [NVD API guide](https://nvd.nist.gov/developers/vulnerabilities) did not expose usable guide text in this inspection. The schema was readable with the web tool; a separate direct fetch returned HTTP 403. Exact current rate limits, query limits, and account behavior are implementation-time connector checks. The plan does not claim a live NVD connector has been verified.

## Discord

Incoming webhooks post notifications. Use a URL link to the dashboard for operator decisions. Custom interactive action controls require application-owned integration support; they are not assumed by this plan. Use confirmation responses and suppress unintended mentions when publishing untrusted commit text.

- [Discord webhook resource](https://docs.discord.com/developers/resources/webhook)

## PostgreSQL and Docker

- [PostgreSQL SELECT / locking clauses](https://www.postgresql.org/docs/current/sql-select.html): supports queue-style row claiming; does not replace leases or external-effect deduplication.
- [Docker Engine security](https://docs.docker.com/engine/security/): Engine control is a privileged trust boundary.
- [Rootless Docker tips](https://docs.docker.com/engine/security/rootless/tips/): documented rootless Docker-in-Docker still needs an outer privileged container.

The ADRs compare runtime choices using those facts. Network isolation, limit enforcement, and workload recovery remain executable acceptance checks in the implementation plan.
