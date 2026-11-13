import io
import json
import re
import os
import secrets
import socket
import tarfile
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import docker
from .contracts import HERDR_HOSTS, PROVIDERS, input_files

LABEL = "org.pruferva.asset-monitor.run"
BUNDLE_PREFIX = "bundle/"
INSTANCE = "org.pruferva.asset-monitor.instance"
GIT_CACHE = "org.pruferva.asset-monitor.cache=git"
VERSION = "0.1.0"

# Fixed Engine exec transports join the running workload's mount namespace.
# Docker archive/copy on Engine20.10 cannot see files in its active tmpfs mounts.
# Exec stdout is a separate private stream, never the container's main log stream.
READ_NATIVE_CACHE = """import os,stat,sys
fd=os.open('/home/job/credential-ingress.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as handle:
    info=os.fstat(handle.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>256*1024:
        sys.exit(1)
    data=handle.read(256*1024+1)
    if len(data)>256*1024:
        sys.exit(1)
    sys.stdout.buffer.write(data)
"""
ACK_NATIVE_CACHE = """import os
fd=os.open('/workspace/credential-ack',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
    os.write(fd,b'ok')
finally:
    os.close(fd)
"""

# The operator's authorization code arrives on exec stdin, never argv/environment, and
# is renamed into place so the login workload cannot observe a partial write.
WRITE_LOGIN_CODE = """import os,sys
data=sys.stdin.buffer.read(4097)
if not data or len(data)>4096:
    sys.exit(1)
temp='/home/job/login-code.%d.tmp'%os.getpid()
fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
    os.write(fd,data)
finally:
    os.close(fd)
os.rename(temp,'/home/job/login-code')
"""


# Lab phase one (A07): this fixed command, never the bundle's, copies the application and fetches
# its dependencies with install scripts disabled. A bundled node_modules is never used.
FETCH_DEPENDENCIES = """set -e
app=/workspace/inputs/bundle/vulnerable-app
[ -d "$app" ] || app=/workspace/inputs/vulnerable-app
cp -R "$app" /opt/lab/app
chmod -R u+w /opt/lab/app
rm -rf /opt/lab/app/node_modules
cd /opt/lab/app
if [ -f package-lock.json ]; then npm ci --ignore-scripts --no-audit --no-fund
else npm install --ignore-scripts --no-audit --no-fund; fi
"""


class RuntimeFailure(Exception):
    def __init__(self, code, message):
        self.code, self.safe_message = code, message
        super().__init__(message)


# A vulnerable application is built, not merely assembled, so executable build steps are accepted.
# The build is offline (ADR-0005), so a bundle may build only on the bundled Lab base, which carries
# pinned Node, or scratch: the Engine would fetch any other base, or a URL source, outside
# --network none, and a fetched base would outlive the run.
LAB_DIRECTIVES = frozenset({"FROM", "RUN", "COPY", "ADD", "WORKDIR", "USER", "ENV", "ARG", "EXPOSE",
                            "CMD", "ENTRYPOINT", "LABEL", "VOLUME", "STOPSIGNAL", "SHELL", "HEALTHCHECK"})
LAB_BASE = re.compile(r"(?:asset-monitor-lab:0\.1\.0|scratch)(?: AS [a-zA-Z][a-zA-Z0-9_-]*)?")


def instructions(text):
    """The Dockerfile's instructions as the Engine reads them (Engine 20.10): a comment line is
    dropped before continuations are joined, so a trailing backslash never continues it, and blank
    or comment lines inside a continuation are skipped. A parser directive could change the escape
    character, so none is accepted. artifacts.dockerfile_instructions in the backend mirrors this."""
    result, current = [], None
    for line in text.removeprefix("\ufeff").split("\n"):
        line = line.rstrip("\r")
        stripped = line.lstrip()
        if stripped.startswith("#"):
            if re.match(r"#\s*(?:escape|syntax)\s*=", stripped, re.I):
                raise ValueError("lab Dockerfile parser directives are not accepted")
            continue
        if not stripped:
            continue
        continued = re.search(r"\\[ \t]*$", line)
        part = line[:continued.start()] if continued else line
        current = part.lstrip() if current is None else current + part
        if not continued:
            result.append(current)
            current = None
    return result if current is None else [*result, current]


def validate_dockerfile(data):
    text = data.decode("utf-8")
    if len(text) > 262144:
        raise ValueError("lab Dockerfile exceeds its size bound")
    bases, stages = [], set()
    for line in instructions(text):
        line = line.strip()
        if not line:
            continue
        instruction, _, value = line.partition(" ")
        instruction, value = instruction.upper(), value.strip()
        if instruction not in LAB_DIRECTIVES:
            raise ValueError("unsupported lab Dockerfile directive")
        if instruction in {"FROM", "COPY", "ADD"} and "$" in value:
            # The Engine expands a variable here, so what is checked would not be what it builds.
            raise ValueError("lab FROM, COPY and ADD cannot use variables")
        if instruction == "FROM":
            if not LAB_BASE.fullmatch(value):
                reference = value.split()[0]
                # An earlier stage of this same build is not an external base.
                if reference not in stages:
                    raise ValueError("lab base must be the bundled lab image, scratch or a build stage")
            else:
                bases.append(value.split()[0])
            if " AS " in value.upper():
                stages.add(value.split()[-1])
        # A build mount or a host path is the one thing a bundle must never reach for. Only the
        # flags that lead the directive are inspected, so an ENV or LABEL may mention one.
        flags = []
        for part in value.split():
            if not part.startswith("--"):
                break
            flags.append(part)
        if any(flag.startswith(("--mount", "--security", "--network")) for flag in flags):
            raise ValueError("lab build mounts and privileged build flags are not accepted")
        if instruction in {"COPY", "ADD"}:
            source = next((f.removeprefix("--from=") for f in flags if f.startswith("--from=")), None)
            if source is not None:
                # With --from the source path belongs to that stage, not to the context.
                if source not in stages:
                    raise ValueError("lab COPY --from must name an earlier build stage")
            else:
                sources = [part for part in value.split() if not part.startswith("--")][:-1]
                if any("://" in part for part in sources):
                    raise ValueError("lab COPY and ADD sources cannot be URLs")
                if any(part.startswith("/") or ".." in part.split("/") for part in sources):
                    raise ValueError("lab COPY source must be within context")
    if not bases and not stages:
        raise ValueError("lab Dockerfile lacks a pinned base")
    return bases


def labelled(text, labels):
    """The Dockerfile with a LABEL after every FROM, so every layer and every build-step container
    of the build carries the run's labels and the run's cleanup finds a failed build's remains."""
    label = "LABEL " + " ".join(f"{json.dumps(k)}={json.dumps(v)}" for k, v in labels.items())
    lines = []
    for line in instructions(text):
        lines.append(line)
        if line.upper().startswith("FROM "):
            lines.append(label)
    return "\n".join(lines) + "\n"


# Workloads reach providers only through the run's credential-free gateway.
PROXY_ENVIRONMENT = {"HTTP_PROXY":"http://gateway:8082","HTTPS_PROXY":"http://gateway:8082","ALL_PROXY":"http://gateway:8082",
                     "NO_PROXY":"gateway,localhost,127.0.0.1","NODE_OPTIONS":"--require=/opt/numen/proxy-preload.cjs",
                     "NODE_USE_ENV_PROXY":"1"}


def npm_registry():
    return os.getenv("NUMEN_NPM_REGISTRY_URL", "https://registry.npmjs.org")


def gateway_config(request, profile, interactive):
    """The gateway's CONNECT allowlist: the provider's own hosts, plus herdr.dev for a run that
    hosts a Herdr session, because Herdr fetches its agent-detection manifests from there. A Lab's
    dependency fetch reaches only the npm registry, whatever its Profile names."""
    if request.kind == "lab":
        return {"provider_hosts": [urlsplit(npm_registry()).hostname]}
    hosts = [] if request.kind == "probe" else PROVIDERS.get(profile["provider_id"], [])
    return {"provider_hosts": hosts + (HERDR_HOSTS if interactive else [])}


class DockerEngine:
    def __init__(self, client=None):
        self.client = client or docker.from_env(timeout=30)
        self.instance = os.getenv("NUMEN_RUNNER_INSTANCE", "numen")
        # herdr runs agents as interactive sessions an operator can watch and steer.
        self.agent_backend = os.getenv("NUMEN_AGENT_BACKEND", "native")
        self.sessions = {}  # run id -> workload container hosting its agent session
        self.session_homes = {}  # private per-run volume, removed only after history retention

    def ping(self):
        return self.client.ping()

    def hosts_session(self, request):
        """Whether the run hosts a Herdr session. Triage is a one-shot call with no tools, never a
        session, so it never reaches herdr.dev."""
        return request.kind == "agent" and self.agent_backend == "herdr" and request.profile.operation != "commit_triage"

    def cleanup(self, run_id):
        self.sessions.pop(run_id, None)
        self.session_homes.pop(run_id, None)
        for container in self.client.containers.list(all=True, filters={"label":[f"{LABEL}={run_id}",f"{INSTANCE}={self.instance}"]}):
            try:
                container.remove(force=True, v=True)
            except docker.errors.NotFound:
                pass
        for volume in self.client.volumes.list(filters={"label":[f"{LABEL}={run_id}",f"{INSTANCE}={self.instance}"]}):
            try:
                volume.remove(force=True)
            except docker.errors.NotFound:
                pass
        for network in self.client.networks.list(filters={"label":[f"{LABEL}={run_id}",f"{INSTANCE}={self.instance}"]}):
            try:
                network.remove()
            except docker.errors.NotFound:
                pass
        try:
            self.client.images.remove("asset-monitor-lab-job:" + run_id, force=True)
        except docker.errors.NotFound:
            pass
        # A Lab build's intermediate layers carry the run label too. Only an image no other one
        # builds on can be removed, and removing it also removes its untagged parents.
        images = self.client.images.list(all=True, filters={"label":[f"{LABEL}={run_id}",f"{INSTANCE}={self.instance}"]})
        parents = {image.attrs.get("Parent") for image in images}
        for image in images:
            if image.id in parents:
                continue
            try:
                self.client.images.remove(image.id, force=True)
            except docker.errors.NotFound:
                pass

    def reconcile(self):
        ids = {c.labels[LABEL] for c in self.client.containers.list(all=True, filters={"label":[LABEL,f"{INSTANCE}={self.instance}"]})}
        ids.update(n.attrs.get("Labels", {}).get(LABEL) for n in self.client.networks.list(filters={"label":[LABEL,f"{INSTANCE}={self.instance}"]}))
        ids.update(v.attrs.get("Labels", {}).get(LABEL) for v in self.client.volumes.list(filters={"label":[LABEL,f"{INSTANCE}={self.instance}"]}))
        ids.update(i.labels.get(LABEL) for i in self.client.images.list(all=True, filters={"label":[LABEL,f"{INSTANCE}={self.instance}"]}))
        for run_id in ids:
            if run_id:
                self.cleanup(run_id)
        # Build runs before ADR-0005 shared git mirrors in a volume that outlived them; nothing mounts it now.
        for volume in self.client.volumes.list(filters={"label":[GIT_CACHE,f"{INSTANCE}={self.instance}"]}):
            try:
                volume.remove(force=True)
            except docker.errors.APIError:
                pass  # Never block readiness on it; the next broker start tries again.

    def spec(self, request, network, labels, application=False):
        b = request.bounds
        spec = {"user":"10001:10001", "read_only":True, "cap_drop":["ALL"], "security_opt":["no-new-privileges:true"],
                "mem_limit":f"{int(b['memory_mb'])}m", "memswap_limit":f"{int(b['memory_mb'])}m",
                "nano_cpus":int(b["cpus"]*1e9), "pids_limit":int(b["pids"]), "network":network.name,
                "tmpfs":{"/workspace":f"rw,nosuid,nodev,size={int(min(b['input_bytes'],64*1024*1024)+b['output_bytes']+32*1024*1024)},uid=10001,gid=10001,mode=0700",
                         "/home/job":"rw,nosuid,nodev,size=33554432,uid=10001,gid=10001,mode=0700",
                         "/tmp":"rw,nosuid,nodev,size=33554432,uid=10001,gid=10001,mode=1777"},
                "labels":labels, "log_config":docker.types.LogConfig(type="json-file",config={"max-size":"16m","max-file":"1"}),
                "ulimits":[docker.types.Ulimit(name="nofile",soft=256,hard=256)], "use_config_proxy":False, "detach":True}
        if application:
            # ponytail: a verified reproduction has to actually run, so the application container is
            # an ordinary one. Everything it can reach is per-run and removed with the run. The PoC
            # that observes it keeps the bounded, nonroot, network-isolated profile above.
            spec.update({"read_only":False, "cap_drop":[], "user":None})
            spec["tmpfs"] = {"/tmp":"rw,nosuid,nodev,size=1073741824"}
            spec["ulimits"] = [docker.types.Ulimit(name="nofile",soft=4096,hard=4096)]
        return spec

    def start_gateway(self, run_id, request, network, labels, config):
        """The run's credential-free gateway, on its own egress bridge and reachable from network as `gateway`."""
        egress = self.client.networks.create("numen-egress-" + run_id, labels=labels)
        proxy_spec = self.spec(request, egress, labels)
        proxy_spec["tmpfs"] = {"/tmp":"rw,nosuid,nodev,size=16777216,uid=10001,gid=10001"}
        proxy = self.client.containers.create("asset-monitor-gateway:" + VERSION, command=["python","-m","numen_runner.gateway"],
                                               environment={"NUMEN_GATEWAY_CONFIG":json.dumps(config)}, **proxy_spec)
        network.connect(proxy, aliases=["gateway"])
        proxy.start()
        return proxy

    def prepare_session_home(self, run_id, image, labels):
        # Native conversation files must survive workload exit/cancellation until the broker
        # has read and redacted them. Only this run's own containers mount this private volume.
        volume = self.client.volumes.create("numen-session-" + run_id, labels=labels)
        stager = self.client.containers.create(
            image, ["chmod", "0700", "/home/job"], network_mode="none", user="10001:10001",
            read_only=True, cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
            labels=labels, volumes={volume.name:{"bind":"/home/job","mode":"rw"}},
            use_config_proxy=False)
        try:
            stager.start()
            if stager.wait(timeout=60).get("StatusCode"):
                raise RuntimeFailure("session_unavailable", "Private session storage could not be prepared.")
        finally:
            stager.remove(force=True)
        return volume

    def run(self, run_id, request, cancelled, event, login_input=None):
        timeout = request.bounds["timeout_seconds"]
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            self.ping()
        except docker.errors.DockerException as exc:
            raise RuntimeFailure("engine_unavailable", "Docker Engine is unavailable.") from exc
        labels = {LABEL:run_id,INSTANCE:self.instance,"org.pruferva.asset-monitor.version":VERSION}
        job_network = self.client.networks.create("numen-job-" + run_id, internal=True, labels=labels)
        profile = request.profile.model_dump()
        kind = request.kind
        environment = {"HOME":"/home/job","PATH":"/opt/numen/node_modules/.bin:/opt/runner/.venv/bin:/usr/local/bin:/usr/bin:/bin"}
        interactive = self.hosts_session(request)
        if kind in {"agent","capabilities","account_login","probe"}:
            config = gateway_config(request, profile, interactive)
            if request.target_policy:
                policy = dict(request.target_policy)
                # An explicit internal asset exception never authorizes application/control subnets.
                blocked = []
                for network in self.client.networks.list():
                    if network.name != job_network.name and network.name.endswith(("_application","_control")):
                        blocked.extend(c["Subnet"] for c in network.attrs.get("IPAM",{}).get("Config",[]) if c.get("Subnet"))
                policy["blocked_cidrs"] = blocked
                config.update({"target_policy":policy,"fetch_token":secrets.token_urlsafe(32)})
                environment.update({"NUMEN_FETCH_URL":"http://gateway:8082/fetch","NUMEN_FETCH_TOKEN":config["fetch_token"]})
            self.start_gateway(run_id, request, job_network, labels, config)
            environment.update(PROXY_ENVIRONMENT)
        image = "asset-monitor-" + (profile["agent"] if kind in {"agent","capabilities","account_login"} else kind) + ":" + VERSION
        lab_image = None
        lab_application = None
        # A Lab's dependency fetch and its PoC read the same immutable inputs.
        input_volume = self.materialize_inputs(run_id, request, labels)
        if kind == "lab":
            lab_image = self.build_lab(run_id, request, cancelled, event, input_volume, labels)
            # The run's own deadline starts once its image is built (ADR-0005: build 15 min, run 10).
            deadline = time.monotonic() + timeout
            # The application joins only the internal job network, beside its PoC: it has no route
            # out and none to the application or control networks (ADR-0005).
            app_spec = self.spec(request, job_network, labels, application=True)
            app_spec["networking_config"] = {job_network.name: self.client.api.create_endpoint_config(aliases=["application"])}
            application = self.client.containers.create(lab_image, **app_spec)
            application.start()
            environment["TARGET_URL"] = "http://application:8080"
            event({"type":"lab_started","message":"Pinned application launched on the isolated job network."})
            # An application that cannot start is a verification failure, not a non-reproduction, so
            # it is watched through its startup rather than sampled the instant after it is started.
            start = time.monotonic() + 10
            while time.monotonic() < start:
                application.reload()
                if application.status in {"exited","dead"}:
                    event({"type":"lab_application_exited","message":"lab_application_exited"})
                    raise RuntimeFailure("lab_application_failed",
                                         "The pinned application stopped before anything could be verified.")
                time.sleep(0.5)
            lab_application = application
        spec = self.spec(request, job_network, labels)
        spec["volumes"] = {input_volume.name:{"bind":"/workspace/inputs","mode":"ro"}}
        if kind == "agent" and profile["agent"] == "codex":
            policy = json.loads((Path(__file__).parents[1] / "seccomp-codex.json").read_text())
            spec["security_opt"].append("seccomp=" + json.dumps(policy, separators=(",", ":")))
        if interactive:
            home = self.prepare_session_home(run_id, image, labels)
            spec["tmpfs"].pop("/home/job", None)
            spec["volumes"][home.name] = {"bind":"/home/job","mode":"rw"}
            self.session_homes[run_id] = (home.name, image, labels)
        container = self.client.containers.create(image, command=["python","-m","numen_runner.workload"],
                                                  environment=environment, stdin_open=True, **spec)
        connection = container.attach_socket(params={"stdin":1,"stream":1})
        container.start()
        data = request.model_dump()
        data["limits"] = request.bounds
        data["lab_image"] = lab_image
        data["inputs"] = []
        data["inputs_materialized"] = True
        data["session"] = interactive
        if data["session"]:
            self.sessions[run_id] = container
        try:
            connection._sock.sendall((json.dumps(data) + "\n").encode())
        finally:
            connection.close()
        image_digest = self.client.images.get(image).id
        manifest_path = Path(__file__).parents[1] / "plugins.lock.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
        resource_path = Path(__file__).parents[1] / "resources.lock.json"
        resources = json.loads(resource_path.read_text()) if resource_path.exists() else {}
        execution = {"image_digest":image_digest,
                     "agent_version":manifest.get("agents",{}).get(profile["agent"],{}).get("version") if kind in {"agent","capabilities","account_login"} else None,
                     "plugin_versions":{p["id"]:p["version"] for p in manifest.get("plugins",[]) if p["id"] in profile.get("enabled_plugins",[])},
                     "skill_revision":resources.get("bundle_sha256") if profile.get("operation") == "audit_context" else None}
        event({"type":"workload_started","message":f"Started {kind} workload with pinned image {image}.","execution":execution})
        reported = set()
        signalled = set()
        polls = 0
        native_credential = None
        next_session = 0
        while True:
            polls += 1
            if lab_application is not None and polls % 20 == 1:
                lab_application.reload()
                if lab_application.status in {"exited","dead"} and "exited" not in signalled:
                    # The PoC's own outcome still stands; the operator learns why it saw nothing.
                    signalled.add("exited")
                    event({"type":"lab_application_exited","message":"lab_application_exited"})
            if cancelled():
                container.kill()
                raise RuntimeFailure("cancelled", "Workload stopped. No validated partial output was retained.")
            if deadline is not None and time.monotonic() > deadline:
                container.kill()
                raise RuntimeFailure("timeout", "Workload exceeded the configured execution deadline.")
            container.reload()
            if interactive and container.status == "running" and time.monotonic() >= next_session:
                next_session = time.monotonic() + 2
                try:
                    snapshot = self.session(run_id, "read")
                except RuntimeFailure:
                    pass  # Startup has no pane yet; the live endpoint keeps its retryable error.
                else:
                    event({"session": snapshot})
            code = login_input() if login_input and container.status == "running" else None
            if code:
                self.deliver_login_code(container, code)
            logs = container.logs(stdout=True, stderr=False)
            if len(logs) > 16*1024*1024:
                container.kill()
                raise RuntimeFailure("output_limit", "Workload exceeded its bounded output log.")
            for line in logs.splitlines():
                if line in reported:
                    continue
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if value.get("credential_ready") and profile.get("auth_type") == "native_oauth" and request.kind in {"account_login","agent","capabilities"}:
                    reported.add(line)
                    native_credential = self.ingest_native_credential(container)
                if "event" in value:
                    reported.add(line)
                    event(value["event"])
            if container.status in {"exited","dead"}:
                break
            time.sleep(0.25)
        state = container.attrs["State"]
        if state.get("OOMKilled"):
            raise RuntimeFailure("memory_limit", "Workload was stopped by its memory limit.")
        final = None
        for line in logs.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if "envelope" in value:
                final = value["envelope"]
            if "failure" in value:
                failure = RuntimeFailure(value["failure"]["code"], value["failure"]["message"])
                failure.credential = native_credential
                raise failure
        if state["ExitCode"] or final is None:
            raise RuntimeFailure("workload_failed", "Workload exited without a validated completion envelope.")
        final["execution"] = execution
        if native_credential is not None:
            final["credential"] = native_credential
            final["credential_updated"] = True
        return final

    def session(self, run_id, *args):
        """Read or steer a run's agent session through the fixed in-workload session command."""
        container = self.sessions.get(run_id)
        if container is None:
            raise RuntimeFailure("no_session", "This run has no interactive agent session.")
        reader = None
        try:
            container.reload()
            if container.status != "running":
                if args != ("read",) or run_id not in self.session_homes:
                    raise RuntimeFailure("session_unavailable", "The agent session has ended.")
                volume, image, labels = self.session_homes[run_id]
                # Main stdout stays silent: raw history uses exec's private stream and never
                # enters Docker logs before the broker redacts it.
                reader = self.client.containers.create(image,
                    ["python", "-c", "import time; time.sleep(300)"],
                    network_mode="none", user="10001:10001", read_only=True,
                    cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
                    mem_limit="1g", pids_limit=16, labels=labels,
                    volumes={volume:{"bind":"/home/job","mode":"ro"}}, use_config_proxy=False)
                reader.start()
                container = reader
                args = ("archive",)
            done = container.exec_run(["python","-m","numen_runner.session",*args], user="10001:10001",
                                      stdout=True, stderr=False, privileged=False)
        except docker.errors.DockerException:
            raise RuntimeFailure("session_unavailable", "The agent session is not reachable.") from None
        finally:
            if reader is not None:
                reader.remove(force=True)
        if done.exit_code:
            raise RuntimeFailure("session_unavailable", "The agent session is not ready or has ended.")
        if args and args[0] == "send" and not done.output.strip():
            return {}  # Steering succeeds without a response body from the session command.
        try:
            state = json.loads(done.output)
            if not isinstance(state, dict) or (args[0] != "send" and not isinstance(state.get("screen"), str)):
                raise ValueError("invalid session response")
            return state
        except (ValueError, TypeError):
            raise RuntimeFailure("session_unavailable", "The agent session returned invalid state.") from None

    def ingest_native_credential(self, container):
        # Neither credentials nor caller-controlled values enter argv/environment/errors.
        try:
            received = container.exec_run(["python","-c",READ_NATIVE_CACHE], user="10001:10001",
                                          stdout=True, stderr=False, privileged=False)
        except docker.errors.DockerException:
            raise RuntimeFailure("credential_ingress_failed", "Protected native cache read failed.") from None
        if received.exit_code or len(received.output) > 256*1024:
            raise RuntimeFailure("credential_ingress_failed", "Native credential cache failed bounded file validation.")
        try:
            credential = json.loads(received.output)
            if not isinstance(credential, dict):
                raise ValueError("credential envelope must be an object")
        except (ValueError, TypeError):
            raise RuntimeFailure("credential_ingress_failed", "Native credential cache failed JSON validation.") from None
        try:
            acknowledged = container.exec_run(["python","-c",ACK_NATIVE_CACHE], user="10001:10001",
                                               stdout=False, stderr=False, privileged=False)
            if acknowledged.exit_code:
                raise RuntimeError("acknowledgement failed")
        except (docker.errors.DockerException, RuntimeError):
            failure = RuntimeFailure("credential_ingress_failed", "Protected native cache acknowledgement failed.")
            # Preserve a rotated cache already securely received even if acknowledgement fails.
            failure.credential = credential
            raise failure from None
        return credential

    def deliver_login_code(self, container, code):
        api = self.client.api
        try:
            exec_id = api.exec_create(container.id, ["python","-c",WRITE_LOGIN_CODE], stdin=True, stdout=False,
                                      stderr=False, user="10001:10001", privileged=False)["Id"]
            stream = api.exec_start(exec_id, socket=True)
            try:
                raw = getattr(stream, "_sock", stream)
                raw.sendall(code.encode())
                raw.shutdown(socket.SHUT_WR)
                deadline = time.monotonic() + 10
                while api.exec_inspect(exec_id)["Running"]:
                    if time.monotonic() > deadline:
                        raise RuntimeError("login input write timed out")
                    time.sleep(.05)
            finally:
                stream.close()
            if api.exec_inspect(exec_id)["ExitCode"]:
                raise RuntimeError("login input write failed")
        except (docker.errors.DockerException, OSError, RuntimeError):
            raise RuntimeFailure("login_input_failed", "Authorization code delivery to the login workload failed.") from None

    def materialize_inputs(self, run_id, request, labels):
        volume = self.client.volumes.create("numen-inputs-" + run_id, labels=labels)
        # This fixed trusted stager executes no input. Engine archive ingress writes regular files;
        # subsequent workloads mount the bounded immutable volume read-only.
        stager = self.client.containers.create("asset-monitor-probe:" + VERSION, ["sleep","60"], network_mode="none",
            user="10001:10001", read_only=True, cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
            mem_limit="128m", pids_limit=16, nano_cpus=250000000, labels=labels,
            volumes={volume.name:{"bind":"/staged","mode":"rw"}}, use_config_proxy=False)
        try:
            stager.start()
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode="w") as archive:
                inputs = [item.model_dump() for item in request.inputs]
                for path, content in input_files(inputs, int(request.bounds["input_bytes"])):
                    info = tarfile.TarInfo(path)
                    info.size, info.mode, info.uid, info.gid = len(content), 0o444, 0, 0
                    archive.addfile(info, io.BytesIO(content))
            payload.seek(0)
            if not stager.put_archive("/staged", payload.getvalue()):
                raise RuntimeFailure("input_ingress_failed", "Immutable input staging failed.")
        finally:
            stager.remove(force=True)
        return volume

    def fetch_dependencies(self, run_id, request, cancelled, deadline, inputs, labels):
        """Lab phase one (A07): the Node app's dependencies, fetched with install scripts disabled and
        no credential, through a gateway that reaches only the npm registry. Returns node_modules
        as a tar file, or None when the app has none."""
        bounds = request.bounds
        network = self.client.networks.create("asset-monitor-lab-fetch-" + run_id, internal=True, labels=labels)
        proxy = self.start_gateway(run_id, request, network, labels, gateway_config(request, request.profile.model_dump(), False))
        # /opt/lab is owned by the job user in the Lab base, and Docker gives the empty volume that ownership.
        app = self.client.volumes.create("asset-monitor-lab-app-" + run_id, labels=labels)
        spec = self.spec(request, network, labels)
        spec["volumes"] = {inputs.name:{"bind":"/workspace/inputs","mode":"ro"}, app.name:{"bind":"/opt/lab","mode":"rw"}}
        environment = {"HOME":"/home/job","PATH":"/usr/local/bin:/usr/bin:/bin","HTTP_PROXY":"http://gateway:8082",
                       "HTTPS_PROXY":"http://gateway:8082","NO_PROXY":"gateway,localhost,127.0.0.1",
                       "npm_config_registry":npm_registry(),"npm_config_cache":"/opt/lab/cache","npm_config_update_notifier":"false"}
        fetch = self.client.containers.create("asset-monitor-lab:" + VERSION, ["sh","-c",FETCH_DEPENDENCIES], environment=environment, **spec)
        try:
            fetch.start()
            while True:
                if cancelled():
                    fetch.kill()
                    raise RuntimeFailure("cancelled", "Lab build stopped before verification.")
                if time.monotonic() > deadline:
                    fetch.kill()
                    raise RuntimeFailure("timeout", f"The Lab build exceeded its {int(bounds['build_seconds'])} s limit and was removed.")
                fetch.reload()
                if fetch.status in {"exited","dead"}:
                    break
                time.sleep(0.25)
            if fetch.attrs["State"]["ExitCode"]:
                raise RuntimeFailure("lab_dependencies_failed", "The Lab could not fetch its dependencies with install scripts disabled.")
            try:
                stream, _ = fetch.get_archive("/opt/lab/app/node_modules")
            except docker.errors.NotFound:
                return None
            modules, size = tempfile.TemporaryFile(), 0
            for chunk in stream:
                size += len(chunk)
                if size > bounds["image_bytes"]:
                    modules.close()
                    raise RuntimeFailure("lab_image_too_large", f"The Lab image is larger than its {bounds['image_bytes'] / 1024**3:.3g} GB limit and was removed.")
                modules.write(chunk)
            modules.seek(0)
            return modules
        finally:
            fetch.remove(force=True)
            proxy.remove(force=True)
            app.remove(force=True)

    def build_lab(self, run_id, request, cancelled, event, inputs, labels):
        bounds = request.bounds
        staged = input_files([f.model_dump() for f in request.inputs], int(bounds["input_bytes"]))
        # A bundle larger than the individual-input path can carry arrives as one archive.
        files = {path.removeprefix(BUNDLE_PREFIX): data for path, data in staged}
        if not {"poc.py","report.md","vulnerable-app/Dockerfile"}.issubset(files):
            raise RuntimeFailure("lab_incomplete", "Lab requires poc.py, report.md, and vulnerable-app/Dockerfile.")
        if "vulnerable-app/package.json" not in files:
            raise RuntimeFailure("lab_stack_unsupported", "Labs run only Node applications in this release: the Proof bundle needs vulnerable-app/package.json.")
        try:
            bases = validate_dockerfile(files["vulnerable-app/Dockerfile"])
        except ValueError as exc:
            raise RuntimeFailure("unsafe_lab_bundle", "Lab Dockerfile must build on asset-monitor-lab:0.1.0, scratch or its own stages, from bundle files only, with supported directives.") from exc
        files["vulnerable-app/Dockerfile"] = labelled(files["vulnerable-app/Dockerfile"].decode(), {LABEL:run_id,INSTANCE:self.instance}).encode()
        # The build deadline covers phase one as well (ADR-0005: 15 minutes).
        deadline, done = time.monotonic() + bounds["build_seconds"], threading.Event()
        event({"type":"lab_dependencies","message":"Fetching the Lab's dependencies with install scripts disabled."})
        modules = self.fetch_dependencies(run_id, request, cancelled, deadline, inputs, labels)
        # The context is the bundle's application, its own node_modules dropped, plus the fetched one.
        context = tempfile.TemporaryFile()
        with tarfile.open(fileobj=context,mode="w") as archive:
            for path,data in files.items():
                name = path.removeprefix("vulnerable-app/")
                if name == path or name.split("/")[0] == "node_modules":
                    continue
                info = tarfile.TarInfo(name)
                info.size,info.mode = len(data),0o644
                archive.addfile(info,io.BytesIO(data))
            if modules:
                with modules, tarfile.open(fileobj=modules, mode="r|") as fetched:
                    for member in fetched:
                        parts = member.name.split("/")
                        # npm writes files, directories and its .bin symlinks; nothing else is carried.
                        if parts[0] != "node_modules" or ".." in parts or not (member.isreg() or member.isdir() or member.issym()):
                            raise RuntimeFailure("lab_dependencies_failed", "The Lab's fetched dependencies held an unsupported entry.")
                        archive.addfile(member, fetched.extractfile(member) if member.isreg() else None)
        context.seek(0)
        tag = "asset-monitor-lab-job:" + run_id
        event({"type":"lab_build","message":"Building the pinned lab image from its bundle."})
        # The build stream yields only between chunks, so a silent RUN step is stopped here: at the
        # deadline or on cancel, the run's build-step containers are killed, which ends the build.
        def watchdog():
            while not done.wait(1):
                if cancelled() or time.monotonic() > deadline:
                    for container in self.client.containers.list(filters={"label":[f"{LABEL}={run_id}",f"{INSTANCE}={self.instance}"]}):
                        try:
                            container.kill()
                        except docker.errors.APIError:
                            pass  # It ended on its own.
        threading.Thread(target=watchdog, daemon=True).start()
        failed = False
        try:
            # Offline (ADR-0005): no build step reaches any network.
            stream = self.client.api.build(fileobj=context,custom_context=True,tag=tag,rm=True,forcerm=True,pull=False,
                                           network_mode="none", timeout=int(bounds["build_seconds"]) + 60,
                                           container_limits={"memory":int(bounds["memory_mb"])*1024*1024,"memswap":int(bounds["memory_mb"])*1024*1024,"cpushares":512},
                                           decode=True,use_config_proxy=False)
            for chunk in stream:
                failed = failed or "error" in chunk
        finally:
            done.set()
            context.close()
        if cancelled():
            raise RuntimeFailure("cancelled", "Lab build stopped before verification.")
        if time.monotonic() > deadline:
            raise RuntimeFailure("timeout", f"The Lab build exceeded its {int(bounds['build_seconds'])} s limit and was removed.")
        if failed:
            raise RuntimeFailure("lab_build_failed", "Lab build failed. The build is offline: its prerequisites must come from the Lab base, the bundle or its fetched dependencies.")
        image = self.client.images.get(tag)
        if image.attrs["Size"] > bounds["image_bytes"]:
            raise RuntimeFailure("lab_image_too_large", f"The Lab image is larger than its {bounds['image_bytes'] / 1024**3:.3g} GB limit and was removed.")
        event({"type":"lab_built","message":f"Built immutable lab image {image.id}; bases: {', '.join(bases)}."})
        return image.id
