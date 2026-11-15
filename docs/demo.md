# Demo run sheet (A16)

This sheet runs the Asset Monitor demo on a disposable VM, from `make demo-up` to the last Remediation PR. It covers two Applications: the demo Node Application, which goes through five steps, and the demo PHP Application, whose Asset serves injected content.

**Everything the demo watches is a local stand-in.** The Own repository, the React Upstream repository, the npm packages, the advisories and the Asset's pages are all served by the `fixtures` container on the VM. None of them is a real repository, package, advisory or site. **No real exploit code is used:**

- The React stand-in is not React's code. Where the flaw would reach an inherited member, its 19.0.0 answers the marker `asset-monitor-simulated-flaw`. It never loads or calls anything.
- Step 1's path traversal reads only the Lab container's own `/etc/passwd`.
- The Malicious change's payload, if it were run, would only write the marker file `/tmp/.demo-shop-telemetry`. It names `NPM_TOKEN`, `GITHUB_TOKEN` and a `.test` host as strings only, and nothing ever runs it. Labs install dependencies with scripts disabled and refuse a tree that holds it, and its Proof is static.
- The ClickFix loader's clipboard command is `echo asset-monitor-fixture`, and all its hosts are `.test` hosts. Served-content checks never execute JavaScript.

Only the model providers (Anthropic and DeepSeek) are real, plus Discord if you set a webhook. Labs, yara Detection rules and Served-content checks run for real on the VM's Docker Engine.

## Prerequisites

- **A disposable VM** (ADR-0005). Labs build code that attackers could influence through the host's Docker socket, so escaping a Lab means owning the VM. Put only demo-scoped, spend-capped keys on it, and destroy it afterwards.
- **Software:** Docker Engine with Compose 2.24 or later, make and git. Your shell user must be able to run `docker` (the `docker` group).
- **Hardware:** 4 vCPU, 8 GB RAM (16 GB recommended) and 40 GB disk. The images take about 6 GB.
- **Network:** `make build` downloads the base images and the agent images' packages. At run time the VM reaches only the model providers and herdr.dev (Herdr's agent-detection manifests), plus Discord if set. The stand-ins need no outbound access.
- **Reaching the dashboard:** every port is published on 127.0.0.1 only. From the presenting laptop, open a tunnel with `ssh -L 8790:127.0.0.1:8790 <vm>`, then browse to http://localhost:8790. Alert links use that same address.

## Keys and tokens

Export these in the shell that runs `make`. Never write them to `.env` and never commit them. The seed passes them to its container by name and never prints a value.

| Variable | Used for | Needed |
|---|---|---|
| `ASSET_MONITOR_DEMO_VM=1` | Declares that this host is the disposable demo VM. `make demo-up` refuses to start without it. | Yes |
| `ANTHROPIC_API_KEY` | Analysis, patch drafting and Proof bundles, on Claude Code at high effort (Provider account "Anthropic (demo)"). | For Verdicts and Proofs |
| `DEEPSEEK_API_KEY` | Triage on Pi (Provider account "DeepSeek (demo)"). Without it the seed leaves Triage off, and no Analysis starts automatically. | For Triage, so set both keys |
| `DEMO_ANALYSIS_MODEL`, `DEMO_TRIAGE_MODEL` | The model id each Provider account uses. Without them the seed takes the first model in the account's catalogue. Set them to the models you mean to show. | Recommended |
| `DISCORD_WEBHOOK_URL` | A real channel for Alerts. Without it, Alerts go to the stand-in's webhook endpoint and nobody sees them. | Optional |

The GitHub tokens are not yours to set. The seed creates two Provider accounts, "Stand-in GitHub read token" and "Stand-in GitHub write token", which hold placeholders that only the stand-in accepts. The demo project points every GitHub, registry and feed address at the stand-ins, so never add a real GitHub token to it.

**Without model keys,** the seed still completes and prints a `NEEDS MODEL KEYS` line. These parts still work: the pushes and their intake, the Pre-filter, the Advisory check's Findings with their bump Remediation PRs (steps 4 and 5), Served-content changes (php-inject and php-clean), the Demo server's enrollment and its Server change (server-inject), and merge detection (merge-bump, once you approve a bump). What needs Triage or Analysis does not happen: the Findings of steps 1 to 3 (so steps 2 and merge-revert have nothing to merge), step 4's Vulnerability fix and n-day Proof, and the PHP Application's Findings, its server-files Finding among them, and so its Quarantine.

To change keys or models later, export the new values and run `./scripts/demo.sh seed` again. It is idempotent and updates the Provider accounts and default profiles in place.

## The run at a glance

| # | Command or click | The audience sees | Time |
|---|---|---|---|
| 0 | `make demo-up`, sign in | Two seeded Applications with Baselines | First build: allow for 6 GB of downloads; then a few minutes |
| 1 | `make demo-step STEP=1` | Vulnerability introduced, a Finding, a ready patch | Triage under 2 min, Analysis 5 to 30 min, patch drafting up to 20 min |
| | Start Lab, then Approve the patch | Lab Proof verified (Confirmed), draft pull request | Lab 1 to 3 min |
| 2 | `make demo-step STEP=2` | Merge commit imported, Finding Remediated | Under 1 min |
| 3 | `make demo-step STEP=3` | Pre-filter flags, Malicious change, Detection rule, cleanup report | Triage under 2 min, Analysis 5 to 30 min, Detection rule under 1 min |
| | Approve the revert | The Cure's revert pull request | Under 1 min |
| 3b | `make demo-step STEP=merge-revert` | Malicious change Finding Remediated | Under 1 min |
| 4 | `make demo-step STEP=4` | React2Shell Finding, exposed, bump ready; Backfill reaches the fix commit | Under 1 min, then Triage and Analysis of the fix commit |
| | Start Lab, then Approve the bump | n-day Proof verified, bump pull request | Lab 1 to 3 min |
| 5 | `make demo-step STEP=5` | node2shell Finding with a runtime bump | Under 1 min |
| | Approve the runtime bump | The last Remediation PR | Under 1 min |
| (5b) | `make demo-step STEP=merge-bump` (optional) | Bumped Findings Remediated | Under 1 min |
| 6 | `make demo-step STEP=php-inject` | Googlebot-only judol links, ClickFix loader host, 3 Findings | Check under 1 min, then Triage and Analysis |
| 7 | `make demo-step STEP=php-clean` | Every Watched page matches its Baseline, Findings Remediated | Under 1 min |
| 8 | `make demo-step STEP=server-inject` | A dropped PHP file is one Server change on the Demo server, then a server-files Finding | Rescan under 1 min, then Triage and Analysis |
| | Approve Quarantine (password) | The agent moves the file into its Quarantine folder, the Finding Remediated | Under 1 min |

Each step prints `STEP <name> DONE.`, followed by what to click next. Triage, Analysis and Labs then go on in the dashboard. You can run `./scripts/demo.sh status` at any time. It lists each Finding, its Remediation PRs and their pull request links, which Approvals are pending, and the stand-in's pull requests.

Nothing in the scripts approves anything. Every Approval is yours, in the dashboard's password dialog.

## Start

```sh
# In a checkout of this repository on the VM:
export ASSET_MONITOR_DEMO_VM=1 ANTHROPIC_API_KEY=... DEEPSEEK_API_KEY=...
export DEMO_ANALYSIS_MODEL=... DEMO_TRIAGE_MODEL=...   # recommended
make demo-up
cat .numen/bootstrap-password
```

`make demo-up` does the following:

1. It runs `make build`. On a fresh checkout, that first runs `make init`, which creates `.env` and `.numen/bootstrap-password`.
2. `./scripts/demo.sh up` starts the normal stack plus the `fixtures` stand-in, under its own Compose project `asset-monitor-demo`, with its own volumes, on 127.0.0.1:8790, and the two Ingress listeners on 127.0.0.1:8793 (push listener, which no demo step uses) and 127.0.0.1:8794 (agent listener). It also starts `server-standin`, a stand-in server that runs the real On-server agent binary against a small web root, on an internal stand-ins network only.
3. It creates the Operator `admin`.
4. It seeds the demo through the public HTTP API only, with no database edits.

Steps 3 and 4 run as your own user, because only you can read `.numen/bootstrap-password` (mode 0600). This also holds on a Linux VM.

The seed prints `READY ...` lines and then `SEED DONE`. A `NOT READY` line means a key or model was refused (see Troubleshooting).

Sign in at http://localhost:8790 as `admin`, with the password from `cat .numen/bootstrap-password`.

**What the seed set up:**

- **Demo Node shop.** Its Own repository is `asset-monitor-demo/shop`. It locks `react-server-dom-webpack@19.0.0` and its Dockerfile pins `node:20.11.1-alpine`, which is exposed to the stand-in CVE-2026-111497. From `package-lock.json` the seed derived the Upstream repository `asset-monitor-demo/react`, at Locked version 19.0.0. Both repositories have their Baseline at their head, and the Repositories tab shows them.
- **Demo PHP storefront.** It has no Own repository. Its Asset is `http://toko-batik.test:8090/served/`, with two Watched pages: the homepage and `/served/verify`. The seed accepted their first Content fingerprints as the Baseline, for the browser and for Googlebot. That is the dashboard's Accept Baseline, which needs no password: accepting a Baseline is not an Approval.
- **Demo server.** The Demo PHP storefront's On-server agent. The seed added it on the Server files tab, ran the shown enroll command on the stand-in server (with the one-time Enrollment code on standard input), confirmed the fingerprint the agent printed, and accepted its first File manifest as the Baseline. Confirm fingerprint and Accept Baseline are not Approvals and take no password.
- Scheduled polling is off for both Applications. Each change is picked up when the step runs Check now.

## Steps

### Step 1: a Vulnerability introduced

```sh
make demo-step STEP=1
```

- **What the step does:** it pushes the commit "Let customers download their invoices" to the stand-in Own repository, then runs Check now, the same as the Application page's Check now button.
- **The audience sees:**
  - Demo Node shop > Commits shows the new commit. Triage flags it, and Analysis gives **Vulnerability introduced**: `GET /invoices/<name>` joins the name onto `invoices/` with no containment check.
  - A Finding opens on the Findings tab, and an Alert is sent.
  - Analysis drafts the Proof bundle, and patch drafting prepares a patch Remediation PR (status ready).
- **Click, first the Lab:** open the Finding. In the Lab panel, click **Start Lab**. It becomes clickable once the bundle is complete. In the **Approve the Lab** dialog, enter your password and click Approve.
  - The Lab builds the shop at that commit in two phases: dependencies with install scripts disabled, then build and run with no network.
  - The Proof reads the Lab container's own `/etc/passwd`. The Lab run shows verified, and the Finding becomes Confirmed.
- **Click, then the patch:** in the Remediation PRs panel, click **Approve** on the patch. The **Approve the patch Remediation PR** dialog names the diff's SHA-256. Enter your password.
  - A draft pull request opens on the stand-in, on branch `asset-monitor/<sha7>-patch`.
- **Time:** Triage under 2 min, Analysis 5 to 30 min, patch drafting up to 20 min after the Analysis, and the Lab 1 to 3 min.

### Step 2: merging the patch

```sh
make demo-step STEP=2
```

- **What the step does:** it merges the open patch Remediation PR in the stand-in (a squash merge, as the repository's maintainer would do), then runs Check now.
- **The audience sees:** the poller imports the merge commit `<title> (#1)`. The Remediation PR shows merged, and the Finding becomes **Remediated** by it.
- **Before you approve:** until the patch is approved, the step stops with "No patch Remediation PR is open: approve the patch Remediation PR in the dashboard first." Once a patch is approved, the step waits for its pull request to open.
- **Time:** under 1 min. The merge commit then gets its own Triage.

### Step 3: a Malicious change and its Cure

```sh
make demo-step STEP=3
```

- **What the step does:** it pushes "Report anonymous install metrics". The commit adds a `postinstall` hook that runs `scripts/telemetry.js`, an obfuscated `_0x` string-array and base64 loader. Then it runs Check now.
- **The audience sees, from the commit:**
  - Commits: the Pre-filter marks the commit for its dependency manifest, its package scripts, and minified or obfuscated code.
  - The `package.json` change queues an Advisory check, which matches nothing yet.
  - Analysis gives **Malicious change**.
- **The audience sees, on the Finding:**
  - Its static Proof: the indicators from `package.json` and `scripts/telemetry.js`, plus a yara Detection rule. The rule is validated against the change, the parent tree and the Baseline, and the Finding becomes Confirmed by it.
  - The cleanup report names the commit and the secrets to rotate, `NPM_TOKEN` and `GITHUB_TOKEN`.
  - A revert Remediation PR is ready. Together with the Detection rule and the cleanup report, it is the **Cure**.
  - It has no Lab panel, because a Malicious change never runs. The API refuses a Lab for it too.
- **Click:** in the Remediation PRs panel, click **Approve** on the revert, then enter your password. The revert is drafted by application code, not by an agent.
- **Time:** Triage under 2 min, Analysis 5 to 30 min, Detection rule under 1 min.

```sh
make demo-step STEP=merge-revert
```

- **What the step does:** it merges the approved revert, then runs Check now. The Malicious change Finding becomes Remediated.
- **Order matters:** run this before step 4's Lab. A Lab never builds a tree that holds an unmerged Malicious change, so until the revert is merged, every Lab on the Own head is refused.

### Step 4: Backfill reaches the React2Shell fix

```sh
make demo-step STEP=4
```

- **What the step does:**
  1. It publishes the stand-in React2Shell advisory (CVE-2025-55182, GHSA-fv66-9v8q-g76r) in the stand-in feeds.
  2. It runs the Advisory check, the same as Advisories > **Run Advisory check**.
  3. It runs a **Backfill** of 2 commits on the React Upstream repository, the same as Repositories > Backfill. The Backfill reaches the fix commit "Resolve server references through own properties only", below the Baseline "Release 19.0.1".
- **The audience sees, from the Advisory check:**
  - On the Findings tab, CVE-2025-55182 opens, Confirmed by the advisory match. The match reads `react-server-dom-webpack` 19.0.0 from `package-lock.json`, exposed.
  - Its bump Remediation PR is ready. In `package.json` and `package-lock.json`, it moves the vendored `file:vendor/react-server-dom-webpack-19.0.0.tgz` to 19.0.1.
- **The audience sees, from the Backfill:**
  - The Backfill imports the fix commit and Release 19.0.1. Triage and Analysis give **Vulnerability fix**.
  - Its Exposure reads "v19.0.0 does not contain the fix", fixed in v19.0.1, so the Application is exposed.
  - The fix joins the same Finding as the advisory match: one Finding, not two.
  - The Upstream Playbook for an exposed Vulnerability fix drafts the n-day Proof bundle. The bump stays the one already drafted, so no second bump appears.
- **Click, first the Lab:** click **Start Lab**, then confirm in **Approve the Lab** with your password.
  - The Lab builds the Own repository's head with the Locked version 19.0.0 vendored.
  - The Proof sends an action that names an inherited member, and it sees the stand-in's marker.
- **Click, then the bump:** click **Approve** on the bump. Its pull request opens on the Own repository, never on the React stand-in.
- **Time:** the Advisory check and the Backfill take under 1 min. Then Triage takes under 2 min per commit, Analysis 5 to 30 min and the Lab 1 to 3 min.

### Step 5: the Advisory check opens node2shell

```sh
make demo-step STEP=5
```

- **What the step does:** it publishes the stand-in node2shell advisory (CVE-2026-111497), then runs the Advisory check.
- **The audience sees:**
  - A CVE-2026-111497 Finding for `node` 20.11.1, pinned by the Dockerfile, Confirmed and exposed. It is one Finding across the feeds, because their aliases are merged.
  - Its runtime bump is ready: `FROM node:20.11.1-alpine` becomes `FROM node:20.19.5-alpine`.
- **Click:** click **Approve** on the bump and enter your password. This is the **last Remediation PR**, where AC-A16's scenario ends.
- **Time:** under 1 min.

```sh
make demo-step STEP=merge-bump   # optional
```

This merges every approved bump. Each bump's Finding becomes Remediated, and its advisory match is no longer exposed.

### The PHP Application: injected served content

```sh
make demo-step STEP=php-inject
```

- **What the step does:** the Asset stand-in starts serving two injections, and the step runs a Served-content check, the same as Served content > **Check now**.
  - The homepage carries judol links (`slot-gacor.test`, `togel-maxwin.test`), served only to Googlebot.
  - `/served/verify` carries a ClickFix loader tag, a script from `cdn.clickfix-fixture.test`.
- **The audience sees, on the Served content tab:**
  - The homepage's Googlebot row has changed, with the link hosts added, while its browser row still matches its Baseline: the injection is cloaked.
  - Both rows of `/served/verify` have changed, with the script host added.
  - Nothing ran: the check fetches pages and their scripts, and never executes them.
- **The audience sees, with model keys:**
  - Triage and Analysis give Malicious change, and three served-content Findings open. Each one is Confirmed by a validated Detection rule and sends an Alert.
  - They get no Remediation PR, because this Application has no Own repository, and no Lab.
- **Time:** the check takes under 1 min. Then Triage takes under 2 min, Analysis 5 to 30 min and each Detection rule under 1 min.

```sh
make demo-step STEP=php-clean
```

- **What the step does:** the stand-in serves the original pages again, and the step runs a Served-content check.
- **The audience sees:** every row matches its Baseline, and the three Findings become Remediated.
- **No Accept Baseline here:** the Baseline did not change. Accept Baseline is only for a new, legitimate fingerprint, and a Malicious change's fingerprint can never become the Baseline.

### The On-server agent: server-inject

```sh
make demo-step STEP=server-inject
```

- **What the step does:** it writes `wp-content/uploads/cache.php` into the stand-in server's web root, a webshell-like file that is inert (if run, it would only print a marker, and nothing runs it). Then it runs the Demo server's **Check now**, a signed rescan command.
- **The audience sees, on the Server files tab:** one Server change on the Demo server that adds the file, with its bytes held. Nothing ran: the agent only hashes and uploads the bytes, and the dashboard never executes or renders them.
- **The audience sees, with model keys:**
  - Triage and Analysis (on the stored bytes only) give Malicious change, and a server-files Finding opens. Its Alert names the Demo server, never a path.
  - On the Finding, the Quarantine panel lists the file by root, path and SHA-256. **Approve Quarantine** asks for your password. The agent then moves the file into its Quarantine folder, shows its result per file, and its next File manifest Remediates the Finding.
  - **Restore** also asks for your password, and warns that it puts the payload back. If you restore, the next manifest shows the SHA-256 again and the Finding regresses to Confirmed, with an Alert.
- **Time:** the rescan takes under 1 min. Then Triage takes under 2 min and Analysis 5 to 30 min. Quarantine takes under 1 min.

## Troubleshooting

- **An Analysis shows "Waiting for cap".** Automatic Analyses are capped at 10 per Application and 30 per Provider account per day, reset at 00:00 UTC, and rehearsals count towards the caps. `make demo-down` followed by `make demo-up` starts a fresh database, which resets them.
- **An extra Triage or Analysis appears for a merge commit.** Each squash-merged Remediation PR is a new commit on the Own repository, so it is triaged and may be analysed. That is expected, and it is paid. If its Analysis opens an extra Vulnerability fix Finding for the merged patch, Dismiss it.
- **Start Lab is refused (`lab_not_allowed`) at step 4.** The step 3 revert is not merged yet. Approve the revert, run `make demo-step STEP=merge-revert`, and try again.
- **Start Lab is greyed out ("Complete the bundle first").** The Proof bundle is still being drafted. Wait for its job on the Jobs page.
- **`make demo-step STEP=2` (or `merge-revert`, or `merge-bump`) says "No … Remediation PR is open".** Approve that Remediation PR in the dashboard first, then run the step again.
- **A pull request link leads to a missing page on github.com.** The pull requests exist only in the stand-in, so links such as `https://github.com/asset-monitor-demo/shop/pull/1` are not real. Use `./scripts/demo.sh status`, which lists them.
- **The node2shell match lists only the ghsa and osv feeds.** The Advisory check caches NVD's answer for 12 hours, and step 3's check cached it while node2shell was not yet published. It is still one Finding.
- **The seed prints `NOT READY <account>`.** Check the key, and make sure `DEMO_ANALYSIS_MODEL` or `DEMO_TRIAGE_MODEL` names a model in that account's catalogue (Settings > Accounts). Then run `./scripts/demo.sh seed` again.
- **`make demo-up` says "set ASSET_MONITOR_DEMO_VM=1".** Export it on the demo VM only. The script also refuses any Compose project name except `asset-monitor-demo` or `asset-monitor-demo-*`.
- **Every Served-content check, Lab or Detection rule fails with "Workload failed".** Docker may have run out of network address pools: each run creates two networks, and the demo project has nine of its own. On a shared host, remove other projects' unused networks first (for example, take down a finished `asset-monitor-test` journey stack with `./scripts/compose.sh -p asset-monitor-test -f compose.yaml -f compose.test.yaml down`), then `make demo-down` and `make demo-up`.
- **The Demo server is silent: no last seen time moves, or Check now stays pending.** Look at `server-standin` and `ingress-agent` in the logs below. A refused request shows as the agent's last refusal on the Server files tab. A pending command expires after 15 minutes; approve or request it again.
- **The Demo server's requests are refused with `clock_skew`.** The agent's clock and the dashboard's differ by more than 5 minutes. On the VM both run on the host clock, so sync the host clock (for example `timedatectl set-ntp true`) and restart the stack.
- **Logs:**

  ```sh
  ./scripts/compose.sh -p asset-monitor-demo -f compose.yaml -f compose.demo.yaml logs --tail=100 app worker scheduler runner-broker fixtures ingress-agent server-standin
  ```

- **Starting the scenario over:** `make demo-down`, then `make demo-up`. The stand-in repositories are rebuilt with the same commits.
- **Rehearsing without keys:** `make test-demo` runs the whole demo with no model keys under a separate project (`asset-monitor-demo-test`, port 18790), then a dry run with canned agent decisions. Neither touches `asset-monitor-demo`. It takes about 15 to 25 minutes after the build.

## Teardown

1. Run `make demo-down`. It removes only the `asset-monitor-demo` project's containers, networks and volumes.
2. Destroy the VM.
3. Revoke the Anthropic and DeepSeek keys at their providers, and delete the Discord webhook if you made one.

## Deviation from AC-A16

AC-A16 says the scenario runs "from `make up`". On the demo VM it runs from `make demo-up` instead. That target is `make build`, then the normal stack plus the stand-ins under the `asset-monitor-demo` project, then the seed. `make up` stays the Operator's production entry point: it uses the real GitHub, registries and feeds, and never starts the stand-ins.
