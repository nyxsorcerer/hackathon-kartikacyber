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
from .contracts import BUILD_HOSTS, PROVIDERS, decode_file, input_files

LABEL = "org.pruferva.numen.run"
INSTANCE = "org.pruferva.numen.instance"
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


class RuntimeFailure(Exception):
    def __init__(self, code, message):
        self.code, self.safe_message = code, message
        super().__init__(message)


def validate_dockerfile(data):
    text = data.decode("utf-8")
    if len(text) > 65536 or "\\\n" in text:
        raise ValueError("lab Dockerfile too large or continued directives unsupported")
    bases = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        instruction, _, value = line.partition(" ")
        instruction = instruction.upper()
        if instruction not in {"FROM", "COPY", "WORKDIR", "USER", "ENV", "EXPOSE", "CMD", "ENTRYPOINT", "LABEL"}:
            raise ValueError("unsupported lab Dockerfile directive")
        if instruction == "USER" and value not in {"10001", "10001:10001"}:
            raise ValueError("lab builds must remain nonroot")
        if instruction == "FROM":
            if not re.fullmatch(r"(?:numen-lab:0\.1\.0|(?:docker\.io/)?(?:library/)?(?:python|node|php|nginx)@sha256:[0-9a-f]{64})(?: AS [a-zA-Z][a-zA-Z0-9_-]*)?", value):
                raise ValueError("lab base must be bundled or approved and digest pinned")
            bases.append(value.split()[0])
        if instruction in {"RUN", "COPY"} and value.startswith("--"):
            raise ValueError("lab build flags/mounts are not accepted")
        if instruction == "COPY" and any(part.startswith("/") or ".." in part.split("/") for part in value.split()[:-1]):
            raise ValueError("lab COPY source must be within context")
    if not bases:
        raise ValueError("lab Dockerfile lacks a pinned base")
    return bases


class DockerEngine:
    def __init__(self, client=None):
        self.client = client or docker.from_env(timeout=30)
        self.instance = os.getenv("NUMEN_RUNNER_INSTANCE", "numen")

    def ping(self):
        return self.client.ping()

    def cleanup(self, run_id):
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

    def spec(self, request, network, labels):
        b = request.bounds
        spec = {"user":"10001:10001", "read_only":True, "cap_drop":["ALL"], "security_opt":["no-new-privileges:true"],
                "mem_limit":f"{int(b['memory_mb'])}m", "memswap_limit":f"{int(b['memory_mb'])}m",
                "nano_cpus":int(b["cpus"]*1e9), "pids_limit":int(b["pids"]), "network":network.name,
                "tmpfs":{"/workspace":f"rw,nosuid,nodev,size={int(b['input_bytes']+b['output_bytes']+32*1024*1024)},uid=10001,gid=10001,mode=0700",
                         "/home/job":"rw,nosuid,nodev,size=33554432,uid=10001,gid=10001,mode=0700",
                         "/tmp":"rw,nosuid,nodev,size=33554432,uid=10001,gid=10001,mode=1777"},
                "labels":labels, "log_config":docker.types.LogConfig(type="json-file",config={"max-size":"16m","max-file":"1"}),
                "ulimits":[docker.types.Ulimit(name="nofile",soft=256,hard=256)], "use_config_proxy":False, "detach":True}
        if request.build:
            # A checkout with history and installed dependencies does not fit a memory-backed
            # workspace, and dependency installers exceed the analysis file/process budget.
            spec["tmpfs"].pop("/workspace")
            spec["tmpfs"]["/home/job"] = "rw,nosuid,nodev,size=1073741824,uid=10001,gid=10001,mode=0700"
            spec["tmpfs"]["/tmp"] = "rw,nosuid,nodev,size=1073741824,uid=10001,gid=10001,mode=1777"
            spec["ulimits"] = [docker.types.Ulimit(name="nofile",soft=4096,hard=4096)]
        return spec

    def start_build_daemon(self, run_id, request, job_network, labels):
        """A per-run rootless Docker daemon the agent drives; the host Engine socket is never shared."""
        egress = self.client.networks.create("numen-build-" + run_id, labels=labels)
        b = request.bounds
        daemon = self.client.containers.create(
            "numen-dind:" + VERSION, command=["--host=tcp://0.0.0.0:2375"],
            # ponytail: privileged is what nested containers actually need on Engine 20.10 without
            # cgroup delegation; the rootless image still runs its daemon unprivileged inside.
            privileged=True, environment={"DOCKER_TLS_CERTDIR":""}, network=egress.name,
            mem_limit=f"{int(b['memory_mb'])}m", nano_cpus=int(b["cpus"]*1e9), labels=labels, detach=True,
            log_config=docker.types.LogConfig(type="json-file",config={"max-size":"16m","max-file":"1"}),
            use_config_proxy=False)
        job_network.connect(daemon, aliases=["docker"])
        daemon.start()
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            daemon.reload()
            if daemon.status in {"exited","dead"}:
                raise RuntimeFailure("build_daemon_failed", "The private build daemon stopped before it was ready.")
            if b"API listen on [::]:2375" in daemon.logs(stdout=False, stderr=True):
                return daemon
            time.sleep(0.5)
        raise RuntimeFailure("build_daemon_failed", "The private build daemon did not become ready.")

    def run(self, run_id, request, cancelled, event, login_input=None):
        timeout = request.bounds["timeout_seconds"]
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            self.ping()
        except docker.errors.DockerException as exc:
            raise RuntimeFailure("engine_unavailable", "Docker Engine is unavailable.") from exc
        labels = {LABEL:run_id,INSTANCE:self.instance,"org.pruferva.numen.version":VERSION}
        job_network = self.client.networks.create("numen-job-" + run_id, internal=True, labels=labels)
        profile = request.profile.model_dump()
        kind = request.kind
        environment = {"HOME":"/home/job","PATH":"/opt/numen/node_modules/.bin:/opt/runner/.venv/bin:/usr/local/bin:/usr/bin:/bin"}
        if kind in {"agent","capabilities","account_login","probe"}:
            config = {"provider_hosts":(PROVIDERS.get(profile["provider_id"], []) if kind != "probe" else [])
                                       + (BUILD_HOSTS if request.build else [])}
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
        if kind == "lab":
            lab_image = self.build_lab(run_id, request, cancelled, event)
            app_spec = self.spec(request, job_network, labels)
            app_spec["tmpfs"].pop("/workspace", None)
            application = self.client.containers.create(lab_image, **app_spec)
            job_network.disconnect(application)
            job_network.connect(application, aliases=["application"])
            application.start()
            environment["TARGET_URL"] = "http://application:8080"
            event({"type":"lab_started","message":"Pinned application launched on the isolated job network."})
        input_volume = self.materialize_inputs(run_id, request, labels)
        spec = self.spec(request, job_network, labels)
        spec["volumes"] = {input_volume.name:{"bind":"/workspace/inputs","mode":"ro"}}
        if request.build:
            daemon = self.start_build_daemon(run_id, request, job_network, labels)
            environment["DOCKER_HOST"] = "tcp://docker:2375"
            # The agent's own workspace is disk backed so a full checkout and its dependencies fit.
            # Image ownership of /workspace seeds the fresh volume, keeping the workload nonroot.
            # ponytail: volume and daemon storage are bounded only by the run's lifetime; add a
            # quota-backed driver if a build run ever fills the Engine's disk.
            workspace = self.client.volumes.create("numen-workspace-" + run_id, labels=labels)
            spec["volumes"][workspace.name] = {"bind":"/workspace","mode":"rw"}
            event({"type":"build_daemon_started","message":"Private build daemon ready at tcp://docker:2375.",
                   "daemon_image":self.client.images.get("numen-dind:" + VERSION).id, "daemon_id":daemon.id})
        if kind == "agent" and profile["agent"] == "codex":
            policy = json.loads((Path(__file__).parents[1] / "seccomp-codex.json").read_text())
            spec["security_opt"].append("seccomp=" + json.dumps(policy, separators=(",", ":")))
        container = self.client.containers.create(image, command=["python","-m","numen_runner.workload"],
                                                  environment=environment, stdin_open=True, **spec)
        connection = container.attach_socket(params={"stdin":1,"stream":1})
        container.start()
        data = request.model_dump()
        data["limits"] = request.bounds
        data["lab_image"] = lab_image
        data["inputs"] = []
        data["inputs_materialized"] = True
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
        native_credential = None
        while True:
            if cancelled():
                container.kill()
                raise RuntimeFailure("cancelled", "Workload stopped. No validated partial output was retained.")
            if deadline is not None and time.monotonic() > deadline:
                container.kill()
                raise RuntimeFailure("timeout", "Workload exceeded the configured execution deadline.")
            container.reload()
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
        stager = self.client.containers.create("numen-probe:" + VERSION, ["sleep","60"], network_mode="none",
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

    def build_lab(self, run_id, request, cancelled, event):
        files = {f.path:decode_file(f.model_dump(),int(request.bounds["input_bytes"])) for f in request.inputs}
        if not {"poc.py","report.md","vulnerable-app/Dockerfile"}.issubset(files):
            raise RuntimeFailure("lab_incomplete", "Lab requires poc.py, report.md, and vulnerable-app/Dockerfile.")
        try:
            bases = validate_dockerfile(files["vulnerable-app/Dockerfile"])
        except ValueError as exc:
            raise RuntimeFailure("unsafe_lab_bundle", "Lab Dockerfile must use approved pinned bases, local COPY, and supported directives.") from exc
        # Force nonroot execution for every build stage even when an approved base defaults to root.
        lines = files["vulnerable-app/Dockerfile"].decode().splitlines()
        lines = [line + ("\nUSER 10001:10001" if line.strip().upper().startswith("FROM ") else "") for line in lines]
        files["vulnerable-app/Dockerfile"] = ("\n".join(lines) + "\n").encode()
        context = io.BytesIO()
        with tarfile.open(fileobj=context,mode="w") as archive:
            for path,data in files.items():
                if not path.startswith("vulnerable-app/"):
                    continue
                info = tarfile.TarInfo(path.removeprefix("vulnerable-app/"))
                info.size,info.mode = len(data),0o644
                archive.addfile(info,io.BytesIO(data))
        context.seek(0)
        tag = "numen-lab-job:" + run_id
        event({"type":"lab_build","message":"Building bounded lab context with network disabled and pinned base images."})
        # Declarative materialization only: executable build directives are rejected above.
        # Application code executes later in the bounded nonroot runtime, never in the daemon builder.
        stream = self.client.api.build(fileobj=context,custom_context=True,tag=tag,rm=True,forcerm=True,pull=False,
                                       network_mode="none",timeout=int(request.bounds["timeout_seconds"]),
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
