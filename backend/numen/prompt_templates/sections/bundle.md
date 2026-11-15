## Finding bundle

For cve_analysis, finding_artifacts, and commit_analysis with a Vulnerability fix or Vulnerability introduced Verdict, write every required bundle file at these exact output-relative paths: {{ required_files | join(", ") }}. Pin the actual vulnerable upstream version, immutable source and dependencies in application.lock.json; do not label a fixed checkout or a synthetic substitute as the vulnerable application.

That lock is read at its top level, not from a nested object: "version" must be the vulnerable release, "source_ref" must be the full immutable revision it was taken from (hexadecimal, or omitted in favour of "local_inputs"), "local_inputs" maps each application file you bundled to why it is there and every one of those paths must exist under vulnerable-app/, and every entry of "images" must be asset-monitor-lab:0.1.0. Anything else you want to record can sit beside those keys.

Labs are Node only in this release: vulnerable-app/ must be a Node application with its package.json, and its package-lock.json whenever the application has one. A bundle for any other stack stays a draft and its Lab is refused, so explain in report.md what the application needs instead.

After the Operator's Approval, the Lab works in two phases. First it fetches the dependencies itself from vulnerable-app/package.json and package-lock.json (npm ci, or npm install without a lockfile) with install scripts disabled, from the npm registry only, and adds the resulting node_modules to vulnerable-app/. Then it builds vulnerable-app/Dockerfile and runs it with no network at all. So the Dockerfile cannot git clone, apt-get, npm install from a registry, or ADD a URL, and no dependency install script ever runs, not even through npm rebuild: the application has to work with dependencies installed exactly that way. RUN is accepted and runs offline.

FROM must name asset-monitor-lab:0.1.0, scratch, or an earlier stage of your own file; any other image is refused. asset-monitor-lab:0.1.0 is Debian bookworm with Python 3.12, Node 24.9.0 and npm, running as root by default, and nothing else. COPY and ADD sources are bundle files inside vulnerable-app/, or carry --from naming one of your own stages. Build mounts and privileged build flags (--mount, --security, --network) are refused. Bundle files arrive owned by root with no execute bit, so CMD names its interpreter (CMD ["node", "server.js"]).

The vulnerable_app fact names the application the Lab builds, which GarudaNetra supplies under vulnerable-app/; a file you bundle there replaces the supplied one:
- own_commit (the own_repository fact is true): the Lab places the Own repository at the Verdict's commit under vulnerable-app/ for you.
- own_head: the Lab places the Own repository at its default-branch head under vulnerable-app/, and GarudaNetra installs the packages fact's packages at the locked_version fact, exactly as the npm registry publishes them, from vulnerable-app/.asset-monitor/.
- minimal, with the packages and locked_version facts: GarudaNetra writes vulnerable-app/package.json, a minimal private application whose dependencies pin those packages at the Locked version, and installs them the same way.

In those cases bundle only the Dockerfile and the files you wrote yourself, such as the code that reaches the vulnerable package, never a copy of the repository or a package.json or package-lock.json of your own, and use COPY . /app/ so the build takes the whole application. When the facts name no packages or Locked version for a minimal app, nothing is supplied: bundle a minimal Node application that pins the vulnerable package version in package.json and package-lock.json, with the code that reaches it. Never present a reduced copy of a real application as the real one. Your outputs are limited to 8 MB.

Keep the bundle itself declarative so the Lab can rebuild it, and put everything the bundle needs under vulnerable-app/ because your workspace is destroyed with the run.

Exactly one application container runs, with no sidecars and no compose, so anything else it needs belongs inside that image and is started before it serves. It serves port 8080 on an internal Lab network with no route to the internet or to any other network, its image's own user, an ordinary capability set, 2 CPUs, 6 GB and 4096 processes, and it inherits no environment.

Lab limits: each Lab image is at most 4 GB, its dependency fetch and build together get 15 minutes, and the run gets 10 minutes that include the application's startup. A Lab over a limit fails and its image is removed.

poc.py runs in a separate container on the same internal Lab network, also with no internet, so an observed proof must come from the application rather than from the network. It is staged read-only and run as `python -I /workspace/inputs/poc.py` with the working directory /workspace, which is a different writable filesystem: one file, standard library plus httpx only, locating any data it needs from Path(__file__).parent rather than the working directory, writing only under /workspace, reading its target from the TARGET_URL environment variable, polling it until it answers because the application may take a while to start, verifying the observed proof and exiting nonzero on failure. Reports and startup instructions must explain prerequisites, impact, reproduction and limitations.

If the vulnerable application cannot meet that contract, say so in report.md with the specific prerequisite it needs instead of shipping a bundle the Lab must refuse. If the supplied evidence cannot support a genuine vulnerable bundle, preserve the report and explain the missing prerequisites instead of inventing files; an incomplete bundle is kept as a draft.

The bundle is a draft: a Lab verifies it after the Operator's Approval, so never claim it reproduces.
