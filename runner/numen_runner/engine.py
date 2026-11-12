import hashlib
import io
import json
import re
import os
import secrets
import socket
import tarfile
import time
from pathlib import Path

import docker
import requests
from .contracts import BUILD_HOSTS, PROVIDERS, collect_outputs, input_files

LABEL = "org.pruferva.asset-monitor.run"
BUNDLE_PREFIX = "bundle/"
INSTANCE = "org.pruferva.asset-monitor.instance"
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


# Mirror once, then fetch; the lock makes concurrent build runs take turns on the mirror.
SEED_REPOSITORY = """set -eu
mirror="/workspace/$KEY.git"
exec 9>/workspace/.lock
flock 9
if [ -d "$mirror" ]; then
  git -C "$mirror" fetch --prune --quiet origin
else
  rm -rf "$mirror.partial"
  git clone --mirror --quiet "$URL" "$mirror.partial"
  mv "$mirror.partial" "$mirror"
fi
flock -u 9
git clone --quiet "$mirror" /target/repo
git -C /target/repo remote set-url origin "$URL"
git -C /target/repo -c advice.detachedHead=false checkout --quiet --detach "$REF"
"""
# A build daemon reports a rejected build in its own log, which the operator cannot see. A match
# reports its event type only; the daemon's own log text is driven by the agent and never leaves
# it. The one exception is the image Docker refused to pull, kept only as a well-formed reference.
IMAGE_REFUSED = re.compile(rb"pull access denied for ([a-z0-9][a-z0-9._/:@-]{0,199})")
BUILD_SIGNALS = (
    (b"denied: requested access to the resource is denied", "build_rejected_image"),
    (b"creating mount source path", "build_rejected_mount"),
    (b"no space left on device", "build_rejected_disk"),
)


class RuntimeFailure(Exception):
    def __init__(self, code, message):
        self.code, self.safe_message = code, message
        super().__init__(message)


# A vulnerable application is built, not merely assembled: dependencies are installed and a
# database is initialised, so executable build steps are accepted. What a bundle still may not do
# is reach the host or float its base, because a reproduction has to stay reproducible.
LAB_DIRECTIVES = frozenset({"FROM", "RUN", "COPY", "ADD", "WORKDIR", "USER", "ENV", "ARG", "EXPOSE",
                            "CMD", "ENTRYPOINT", "LABEL", "VOLUME", "STOPSIGNAL", "SHELL", "HEALTHCHECK"})
LAB_BASE = re.compile(
    r"(?:asset-monitor-lab:0\.1\.0|scratch|[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64})"
    r"(?: AS [a-zA-Z][a-zA-Z0-9_-]*)?"
)


def validate_dockerfile(data):
    text = data.decode("utf-8")
    if len(text) > 262144:
        raise ValueError("lab Dockerfile exceeds its size bound")
    # Continuations are ordinary in a real build, so they are joined before the directives are read.
    joined = re.sub(r"\\[ \t]*\r?\n", " ", text)
    bases, stages = [], set()
    for line in joined.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        instruction, _, value = line.partition(" ")
        instruction, value = instruction.upper(), value.strip()
        if instruction not in LAB_DIRECTIVES:
            raise ValueError("unsupported lab Dockerfile directive")
        if instruction == "FROM":
            if not LAB_BASE.fullmatch(value):
                reference = value.split()[0]
                # An earlier stage of this same build is not an external base.
                if reference not in stages:
                    raise ValueError("lab base must be bundled, scratch, a build stage or digest pinned")
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
                # With --from the source path belongs to that stage or image, not to the context.
                if source not in stages and not LAB_BASE.fullmatch(source):
                    raise ValueError("lab COPY --from must name a build stage or a digest-pinned image")
            else:
                parts = [part for part in value.split() if not part.startswith("--")]
                local = [part for part in parts[:-1] if not re.match(r"[a-z][a-z0-9+.-]*://", part)]
                if any(part.startswith("/") or ".." in part.split("/") for part in local):
                    raise ValueError("lab COPY source must be within context")
    if not bases and not stages:
        raise ValueError("lab Dockerfile lacks a pinned base")
    return bases


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
        for image in self.client.images.list(filters={"label":[f"{LABEL}={run_id}",f"{INSTANCE}={self.instance}"]}):
            try:
                self.client.images.remove(image.id, force=True)
            except docker.errors.NotFound:
                pass

    def reconcile(self):
        ids = {c.labels[LABEL] for c in self.client.containers.list(all=True, filters={"label":[LABEL,f"{INSTANCE}={self.instance}"]})}
        ids.update(n.attrs.get("Labels", {}).get(LABEL) for n in self.client.networks.list(filters={"label":[LABEL,f"{INSTANCE}={self.instance}"]}))
        ids.update(v.attrs.get("Labels", {}).get(LABEL) for v in self.client.volumes.list(filters={"label":[LABEL,f"{INSTANCE}={self.instance}"]}))
        ids.update(i.labels.get(LABEL) for i in self.client.images.list(filters={"label":[LABEL,f"{INSTANCE}={self.instance}"]}))
        for run_id in ids:
            if run_id:
                self.cleanup(run_id)

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
        if request.build:
            # A checkout with history and installed dependencies does not fit a memory-backed
            # workspace, and dependency installers exceed the analysis file/process budget.
            spec["tmpfs"].pop("/workspace")
            spec["tmpfs"]["/home/job"] = "rw,nosuid,nodev,size=1073741824,uid=10001,gid=10001,mode=0700"
            spec["tmpfs"]["/tmp"] = "rw,nosuid,nodev,size=1073741824,uid=10001,gid=10001,mode=1777"
            spec["ulimits"] = [docker.types.Ulimit(name="nofile",soft=4096,hard=4096)]
        return spec

    def stopping(self, cancelled, deadline):
        if cancelled():
            raise RuntimeFailure("cancelled", "Workload stopped. No validated partial output was retained.")
        if deadline is not None and time.monotonic() > deadline:
            raise RuntimeFailure("timeout", "Workload exceeded the configured execution deadline.")

    def prepare_workspace(self, run_id, image, labels):
        """A build run's workspace is a volume shared with its daemon, so its ownership cannot be
        left to whichever container mounts it first: the workload's own image seeds it, which needs
        neither root nor any capability. share/ is world-writable because containers the daemon
        starts cannot map back to the workload's user and could otherwise never write to a bind
        mount of their own build directory."""
        volume = self.client.volumes.create("numen-workspace-" + run_id, labels=labels)
        stager = self.client.containers.create(
            image, ["sh","-c","mkdir -p /workspace/share && chmod 0777 /workspace/share"],
            network_mode="none", user="10001:10001", read_only=True, cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"], mem_limit="128m", pids_limit=16,
            nano_cpus=250000000, labels=labels, volumes={volume.name:{"bind":"/workspace","mode":"rw"}},
            use_config_proxy=False)
        try:
            stager.start()
            if stager.wait(timeout=60).get("StatusCode"):
                raise RuntimeFailure("workspace_ingress_failed", "Build workspace preparation failed.")
        except (docker.errors.DockerException, requests.exceptions.RequestException) as exc:
            raise RuntimeFailure("workspace_ingress_failed", "Build workspace preparation failed.") from exc
        finally:
            stager.remove(force=True)
        return volume

    def prepare_session_home(self, run_id, image, labels):
        # Native conversation files must survive workload exit/cancellation until the broker
        # has read and redacted them. This private volume is never shared with a build daemon.
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

    def start_build_daemon(self, run_id, request, job_network, labels, workspace, stopping=lambda: None):
        """A per-run rootless Docker daemon the agent drives; the host Engine socket is never shared.

        The workspace is mounted at the same path it has in the workload, because a bind mount's
        source resolves in the daemon's filesystem and not in the client's.
        """
        egress = self.client.networks.create("numen-build-" + run_id, labels=labels)
        b = request.bounds
        try:
            self.client.images.get("asset-monitor-dind:" + VERSION)
        except docker.errors.DockerException as exc:
            raise RuntimeFailure("build_image_unavailable",
                                 f"asset-monitor-dind:{VERSION} is not built; build the images profile first.") from exc
        daemon = self.client.containers.create(
            "asset-monitor-dind:" + VERSION, command=["--host=tcp://0.0.0.0:2375"],
            # ponytail: privileged is what nested containers actually need on Engine 20.10 without
            # cgroup delegation; the rootless image still runs its daemon unprivileged inside.
            privileged=True, environment={"DOCKER_TLS_CERTDIR":""}, network=egress.name,
            volumes={workspace.name:{"bind":"/workspace","mode":"rw"}},
            # A build run therefore reserves two containers' budgets, which the broker's concurrency
            # bound should account for. Its anonymous image store is removed with the container.
            mem_limit=f"{int(b['memory_mb'])}m", memswap_limit=f"{int(b['memory_mb'])}m",
            pids_limit=int(b["pids"]), nano_cpus=int(b["cpus"]*1e9), labels=labels, detach=True,
            log_config=docker.types.LogConfig(type="json-file",config={"max-size":"16m","max-file":"1"}),
            use_config_proxy=False)
        job_network.connect(daemon, aliases=["docker"])
        daemon.start()
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            stopping()
            daemon.reload()
            if daemon.status in {"exited","dead"}:
                raise RuntimeFailure("build_daemon_failed", "The private build daemon stopped before it was ready.")
            if b"API listen on [::]:2375" in daemon.logs(stdout=False, stderr=True, tail=200):
                return daemon
            time.sleep(0.5)
        raise RuntimeFailure("build_daemon_failed", "The private build daemon did not become ready.")

    def require_build_disk(self, image, labels):
        """A build run installs and builds a whole application, and every concurrent run's daemon
        stores its images on the same Docker disk. Refuse to start one on a nearly full disk, where
        it would only fail later on "No space left on device"."""
        minimum = float(os.getenv("NUMEN_BUILD_MIN_FREE_GB", "10"))
        try:
            report = self.client.containers.run(
                image, ["df", "-Pk", "/"], network_mode="none", user="10001:10001", read_only=True,
                cap_drop=["ALL"], security_opt=["no-new-privileges:true"], mem_limit="64m",
                pids_limit=16, labels=labels, remove=True, use_config_proxy=False)
            free = int(report.decode().strip().splitlines()[-1].split()[3]) / 1024 / 1024
        except (docker.errors.DockerException, ValueError, IndexError):
            return None  # The check is advisory; an unreadable report never blocks a run.
        if free < minimum:
            raise RuntimeFailure("build_disk_low",
                                 f"The Docker host has {free:.1f} GB of free disk; a build run needs at least {minimum:.0f} GB. "
                                 "Remove unused images (make prune) or enlarge the Docker disk, then retry.")
        return free

    def repository_cache(self):
        """The mirror store build runs share. It outlives runs, so it carries no run label and
        cleanup never removes it; only Numen's seeding step ever mounts it writable."""
        name = "numen-git-cache-" + self.instance
        try:
            return self.client.volumes.get(name)
        except docker.errors.NotFound:
            return self.client.volumes.create(name, labels={INSTANCE: self.instance, "org.pruferva.asset-monitor.cache": "git"})

    def seed_repository(self, request, image, network, labels, workspace, environment, event, stopping):
        """Clone the program's repository, with every branch, tag and its full history, into
        /workspace/repo before the agent starts, so the agent never has to clone it again.

        A shared mirror is created once and then only fetched, under a lock so concurrent runs
        take turns. The step runs Numen's fixed commands through the run's own egress gateway;
        the agent's container never mounts the mirror, so no run can alter what later runs get.
        A failure is reported and the run continues: the agent can still clone it itself.
        """
        repository = request.repository
        cache = self.repository_cache()
        spec = self.spec(request, network, labels)
        spec["volumes"] = {
            # The workload image owns /workspace, so the mirror volume is first created owned by
            # the workload user instead of root.
            cache.name: {"bind": "/workspace", "mode": "rw"},
            workspace.name: {"bind": "/target", "mode": "rw"},
        }
        proxy = {key: value for key, value in environment.items() if key.endswith(("_PROXY", "_proxy"))}
        proxy.update({key.lower(): value for key, value in proxy.items()})
        seeder = self.client.containers.create(
            image,
            ["sh", "-c", SEED_REPOSITORY],
            environment={**environment, **proxy, "URL": repository.url, "REF": repository.ref,
                         "KEY": hashlib.sha256(repository.url.encode()).hexdigest()[:24],
                         "GIT_TERMINAL_PROMPT": "0"},
            **spec)
        started = time.monotonic()
        try:
            seeder.start()
            while True:
                stopping()
                seeder.reload()
                if seeder.status in {"exited", "dead"}:
                    break
                if time.monotonic() - started > 1800:
                    seeder.kill()
                    break
                time.sleep(1)
            code = seeder.attrs["State"].get("ExitCode")
            detail = seeder.logs(stdout=True, stderr=True, tail=5).decode(errors="replace").strip()
        finally:
            seeder.remove(force=True)
        if code == 0:
            event({"type": "repository_ready",
                   "message": f"Full history of {repository.url} at /workspace/repo, checked out at {repository.ref}.",
                   "seconds": round(time.monotonic() - started)})
            return True
        event({"type": "repository_unavailable",
               "message": "The repository could not be prepared; the agent can still clone it.",
               "detail": detail[-500:]})
        return False

    def harvest_outputs(self, request, workspace, labels):
        """Collect a disk-backed workspace's outputs directly from its volume.

        A bundle carrying a real application cannot travel through the container log, which Docker
        rotates at its size bound, so it would arrive truncated rather than refused.
        """
        harvester = self.client.containers.create(
            "asset-monitor-probe:" + VERSION, ["sleep","300"], network_mode="none", user="10001:10001",
            read_only=True, cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
            mem_limit="256m", pids_limit=16, nano_cpus=500000000, labels=labels,
            volumes={workspace.name:{"bind":"/workspace","mode":"ro"}}, use_config_proxy=False)
        try:
            harvester.start()
            stream, _ = harvester.get_archive("/workspace/outputs", encode_stream=False)
            payload = io.BytesIO()
            for chunk in stream:
                payload.write(chunk)
            payload.seek(0)
            return collect_outputs(payload, int(request.bounds["output_bytes"]))
        except docker.errors.NotFound:
            return []  # A run that wrote nothing is not a failure here.
        except (docker.errors.DockerException, requests.exceptions.RequestException) as exc:
            raise RuntimeFailure("output_harvest_failed", "Validated output could not be collected.") from exc
        except ValueError as exc:
            raise RuntimeFailure("output_limit", "Workload produced more output than its limit allows.") from exc
        finally:
            harvester.remove(force=True)

    def load_lab_base(self, daemon, event, stopping=lambda: None):
        """The daemon starts with an empty image store and only public registry access, so the
        bundled lab base is streamed in. The lab verifier rebuilds a bundle offline, so a base the
        agent cannot obtain here is a base its bundle must not use."""
        try:
            image = self.client.images.get("asset-monitor-lab:" + VERSION)
        except docker.errors.DockerException:
            event({"type":"build_base_unavailable",
                   "message":f"asset-monitor-lab:{VERSION} is not built, so the build daemon has no offline lab base."})
            return False
        api = self.client.api
        try:
            # An exec does not inherit the rootless daemon's own socket, so it is addressed over TCP.
            exec_id = api.exec_create(daemon.id, ["docker","load"], stdin=True, stdout=False, stderr=False,
                                      environment=["DOCKER_HOST=tcp://127.0.0.1:2375"])["Id"]
            stream = api.exec_start(exec_id, socket=True)
            try:
                raw = getattr(stream, "_sock", stream)
                for chunk in image.save(named="asset-monitor-lab:" + VERSION):
                    raw.sendall(chunk)
                raw.shutdown(socket.SHUT_WR)
                deadline = time.monotonic() + 600
                while api.exec_inspect(exec_id)["Running"]:
                    stopping()
                    if time.monotonic() > deadline:
                        raise RuntimeError("lab base load timed out")
                    time.sleep(0.25)
                # A missing exit code is not a success.
                if api.exec_inspect(exec_id)["ExitCode"] != 0:
                    raise RuntimeError("lab base load failed")
            finally:
                stream.close()
        except (docker.errors.DockerException, OSError, RuntimeError) as exc:
            raise RuntimeFailure("build_base_load_failed",
                                 "The bundled lab base could not be loaded into the build daemon.") from exc
        event({"type":"build_base_loaded", "message":f"Loaded asset-monitor-lab:{VERSION} into the build daemon."})
        return True

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
        if kind in {"agent","capabilities","account_login","probe"}:
            config = {"provider_hosts":(PROVIDERS.get(profile["provider_id"], []) if kind != "probe" else [])
                                       + (BUILD_HOSTS if request.build else [])}
            if request.build:
                config["tunnel"] = {"bytes":4 * 1024 * 1024 * 1024, "seconds":10800}
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
            egress = self.client.networks.create("numen-egress-" + run_id, labels=labels)
            proxy_spec = self.spec(request, egress, labels)
            proxy_spec["tmpfs"] = {"/tmp":"rw,nosuid,nodev,size=16777216,uid=10001,gid=10001"}
            proxy = self.client.containers.create("numen-gateway:" + VERSION, command=["python","-m","numen_runner.gateway"],
                                                   environment={"NUMEN_GATEWAY_CONFIG":json.dumps(config)}, **proxy_spec)
            job_network.connect(proxy, aliases=["gateway"])
            proxy.start()
            environment.update({"HTTP_PROXY":"http://gateway:8082","HTTPS_PROXY":"http://gateway:8082","ALL_PROXY":"http://gateway:8082","NO_PROXY":"gateway,localhost,127.0.0.1",
                                "NODE_OPTIONS":"--require=/opt/numen/proxy-preload.cjs","NODE_USE_ENV_PROXY":"1"})
        image = "numen-" + (profile["agent"] if kind in {"agent","capabilities","account_login"} else kind) + ":" + VERSION
        lab_image = None
        build_daemon = None
        lab_application = None
        workspace = None
        data_base_loaded = False
        if kind == "lab":
            # The application installs and updates, so its own bridge reaches the internet. Docker
            # keeps bridges apart, so it cannot reach the application or control networks.
            lab_egress = self.client.networks.create("asset-monitor-lab-" + run_id, labels=labels)
            lab_image = self.build_lab(run_id, request, cancelled, event, lab_egress)
            app_spec = self.spec(request, lab_egress, labels, application=True)
            app_spec["tmpfs"].pop("/workspace", None)
            application = self.client.containers.create(lab_image, **app_spec)
            job_network.connect(application, aliases=["application"])
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
        input_volume = self.materialize_inputs(run_id, request, labels)
        spec = self.spec(request, job_network, labels)
        spec["volumes"] = {input_volume.name:{"bind":"/workspace/inputs","mode":"ro"}}
        if request.build:
            # The agent's own workspace is disk backed so a full checkout and its dependencies fit.
            # ponytail: volume and daemon storage are bounded only by the run's lifetime; add a
            # quota-backed driver if a build run ever fills the Engine's disk.
            def stopping():
                self.stopping(cancelled, deadline)
            stopping()
            self.require_build_disk(image, labels)
            workspace = self.prepare_workspace(run_id, image, labels)
            daemon = build_daemon = self.start_build_daemon(
                run_id, request, job_network, labels, workspace, stopping)
            spec["volumes"][workspace.name] = {"bind":"/workspace","mode":"rw"}
            environment["DOCKER_HOST"] = "tcp://docker:2375"
            # Ports a nested container publishes are reachable on the daemon, so the agent exercises
            # the same TARGET_URL contract the lab run uses.
            environment["TARGET_URL"] = "http://docker:8080"
            # The daemon is addressed directly; the credential-free proxy never carries its API.
            environment["NO_PROXY"] = ",".join(filter(None, [environment.get("NO_PROXY"), "docker"]))
            event({"type":"build_daemon_started","message":"Private build daemon ready at tcp://docker:2375.",
                   "daemon_image":self.client.images.get("asset-monitor-dind:" + VERSION).id, "daemon_id":daemon.id})
            data_base_loaded = self.load_lab_base(daemon, event, stopping)
            if request.repository is not None:
                self.seed_repository(request, image, job_network, labels, workspace, environment, event, stopping)
        if kind == "agent" and profile["agent"] == "codex":
            policy = json.loads((Path(__file__).parents[1] / "seccomp-codex.json").read_text())
            spec["security_opt"].append("seccomp=" + json.dumps(policy, separators=(",", ":")))
        interactive = kind == "agent" and self.agent_backend == "herdr"
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
        data["lab_base_loaded"] = data_base_loaded
        data["outputs_harvested"] = workspace is not None
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
            if build_daemon is not None and polls % 20 == 1:
                # The whole log is scanned, not a tail: a one-line rejection scrolls out of a window
                # between samples. Its size is already capped by the daemon's own log configuration.
                recorded = build_daemon.logs(stdout=False, stderr=True)
                for signature, signal in BUILD_SIGNALS:
                    if signature in recorded and signature not in signalled:
                        signalled.add(signature)
                        refused = IMAGE_REFUSED.search(recorded) if signal == "build_rejected_image" else None
                        event({"type":signal,"message":signal,
                               **({"image":refused.group(1).decode()} if refused else {})})
                build_daemon.reload()
                if build_daemon.status in {"exited","dead"} and "lost" not in signalled:
                    # The agent keeps running and would otherwise report only that it could not build.
                    signalled.add("lost")
                    event({"type":"build_daemon_lost","message":"build_daemon_lost"})
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
        if workspace is not None:
            final["outputs"] = self.harvest_outputs(request, workspace, labels)
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

    def build_lab(self, run_id, request, cancelled, event, network=None):
        staged = input_files([f.model_dump() for f in request.inputs], int(request.bounds["input_bytes"]))
        # A bundle larger than the individual-input path can carry arrives as one archive.
        files = {path.removeprefix(BUNDLE_PREFIX): data for path, data in staged}
        if not {"poc.py","report.md","vulnerable-app/Dockerfile"}.issubset(files):
            raise RuntimeFailure("lab_incomplete", "Lab requires poc.py, report.md, and vulnerable-app/Dockerfile.")
        try:
            bases = validate_dockerfile(files["vulnerable-app/Dockerfile"])
        except ValueError as exc:
            raise RuntimeFailure("unsafe_lab_bundle", "Lab Dockerfile must use approved pinned bases, local COPY, and supported directives.") from exc
        context = io.BytesIO()
        with tarfile.open(fileobj=context,mode="w") as archive:
            for path,data in files.items():
                if not path.startswith("vulnerable-app/"):
                    continue
                info = tarfile.TarInfo(path.removeprefix("vulnerable-app/"))
                info.size,info.mode = len(data),0o644
                archive.addfile(info,io.BytesIO(data))
        context.seek(0)
        tag = "asset-monitor-lab-job:" + run_id
        # A bundle's base is validated to be either the bundled lab image or an approved repository
        # pinned by digest. The build itself stays offline, so an absent immutable base is fetched
        # first; otherwise only bases that happen to sit in the local store could ever verify.
        for base in bases:
            if base in ("asset-monitor-lab:" + VERSION, "scratch"):
                continue
            try:
                self.client.images.get(base)
                continue
            except docker.errors.DockerException:
                pass
            event({"type":"lab_base_fetch","message":"Fetching the bundle's digest-pinned base before the offline build."})
            repository, _, digest = base.partition("@")
            try:
                self.client.images.pull(repository, tag=digest)
                self.client.images.get(base)
            except (docker.errors.DockerException, requests.exceptions.RequestException) as exc:
                raise RuntimeFailure("lab_base_unavailable",
                                     "The bundle's digest-pinned base image could not be fetched.") from exc
        event({"type":"lab_build","message":"Building the pinned lab image from its bundle."})
        # A vulnerable application is built as its own project: its build steps execute, with the
        # network its dependencies need, on a per-run bridge that reaches no Numen network.
        stream = self.client.api.build(fileobj=context,custom_context=True,tag=tag,rm=True,forcerm=True,pull=False,
                                       network_mode=network.name if network is not None else "none",
                                       timeout=int(request.bounds["timeout_seconds"]),
                                       container_limits={"memory":int(request.bounds["memory_mb"])*1024*1024,"memswap":int(request.bounds["memory_mb"])*1024*1024,"cpushares":512},
                                       labels={LABEL:run_id,INSTANCE:self.instance},decode=True,use_config_proxy=False)
        deadline = time.monotonic() + request.bounds["timeout_seconds"]
        try:
            for chunk in stream:
                if cancelled() or time.monotonic() > deadline:
                    raise RuntimeFailure("cancelled" if cancelled() else "timeout", "Lab build stopped before verification.")
                if "error" in chunk:
                    raise RuntimeFailure("lab_build_failed", "Lab build failed. Bundle prerequisites must be available offline in the pinned base or context.")
        finally:
            stream.close()
        image = self.client.images.get(tag)
        event({"type":"lab_built","message":f"Built immutable lab image {image.id}; bases: {', '.join(bases)}."})
        return image.id
