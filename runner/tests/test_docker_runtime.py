"""Explicit Engine tests. Run in runner-test with socket and NUMEN_DOCKER_TESTS=1."""
import base64
import io
import json
import os
import tarfile
import threading
import uuid
import pytest
from numen_runner.contracts import PROVIDERS, RunRequest
from numen_runner.engine import DockerEngine, RuntimeFailure, LABEL, INSTANCE, VERSION

pytestmark = pytest.mark.skipif(os.getenv("NUMEN_DOCKER_TESTS") != "1", reason="explicit Docker Engine verification only")

@pytest.fixture
def engine():
    value = DockerEngine()
    value.ping()
    return value


def request(script, **limits):
    return RunRequest(attempt_token=str(uuid.uuid4()), kind="probe", inputs=[{"path":"recipe.py","content_base64":base64.b64encode(script.encode()).decode()}], limits={"timeout_seconds":30, **limits})


def execute(engine, job, run_id=None, event=lambda _:None):
    run_id = run_id or str(uuid.uuid4())
    try:
        return engine.run(run_id,job,lambda:False,event)
    finally:
        engine.cleanup(run_id)
        assert not engine.client.containers.list(all=True,filters={"label":f"{LABEL}={run_id}"})
        assert not engine.client.networks.list(filters={"label":f"{LABEL}={run_id}"})
        assert not engine.client.volumes.list(filters={"label":f"{LABEL}={run_id}"})
        # ADR-0005: every Lab's images, a failed build's intermediate layers included, go with its run.
        assert not engine.client.images.list(all=True,filters={"label":f"{LABEL}={run_id}"})


def lab(inputs, **limits):
    """A small Lab run: its bounds stay low so it does not contend with other work on the Engine."""
    return RunRequest(attempt_token=str(uuid.uuid4()), kind="lab", inputs=inputs,
                      limits={"timeout_seconds":60,"memory_mb":512,"cpus":1,"pids":256,**limits})


def tgz(files, prefix=""):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for path, data in files.items():
            data = data if isinstance(data, bytes) else data.encode()
            info = tarfile.TarInfo(prefix + path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return payload.getvalue()


def node_bundle(app_files, bundle_files):
    """One `bundle` archive input, as the backend submits a Proof bundle; app_files are vulnerable-app/."""
    files = {**{"vulnerable-app/" + p: d for p, d in app_files.items()}, **bundle_files}
    return [{"path":"bundle","content_base64":base64.b64encode(tgz(files)).decode(),"archive":True}]


def node_lab(server, poc, steps=""):
    """A tiny Node application with no dependencies, the only first-release Lab stack."""
    return node_bundle({"Dockerfile":f'FROM asset-monitor-lab:0.1.0\nWORKDIR /app\nCOPY . /app/\n{steps}CMD ["node","/app/server.js"]\n',
                        "package.json":'{"name":"lab-fixture","version":"1.0.0","private":true}\n', "server.js":server},
                       {"poc.py":poc, "report.md":"Runtime Lab fixture."})


SERVE = 'require("http").createServer((q,r)=>r.end(BODY)).listen(8080);\n'


def test_agent_source_archive_is_staged_as_read_only_files(engine):
    run_id = str(uuid.uuid4())
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for path in ("index.php", "concrete/src/Kernel.php"):
            info = tarfile.TarInfo(path)
            info.size = len(path)
            archive.addfile(info, io.BytesIO(path.encode()))
    job = RunRequest(attempt_token=run_id, kind="agent",
                     profile={"agent": "pi", "provider_id": "deepseek", "operation": "cve_analysis", "model_id": "m", "credential": {"api_key": "k"}},
                     inputs=[{"path": "source", "content_base64": base64.b64encode(payload.getvalue()).decode(), "archive": True}])
    labels = {LABEL: run_id, INSTANCE: engine.instance}
    try:
        volume = engine.materialize_inputs(run_id, job, labels)
        # The trailing echo terminates cat's unterminated line, which the log stream may drop at exit.
        listing = engine.client.containers.run("asset-monitor-probe:0.1.0", ["sh", "-c", "find /inputs -type f | sort; cat /inputs/source/concrete/src/Kernel.php; echo"],
                                               volumes={volume.name: {"bind": "/inputs", "mode": "ro"}}, network_mode="none",
                                               user="10001:10001", labels=labels, remove=True)
        assert listing.decode().split() == ["/inputs/source/concrete/src/Kernel.php", "/inputs/source/index.php", "concrete/src/Kernel.php"]
    finally:
        engine.cleanup(run_id)


def test_probe_is_nonroot_has_no_socket_secret_or_direct_egress(engine):
    script = '''import os,socket,json
s=socket.socket();s.settimeout(1)
try:
 s.connect(("8.8.8.8",443));direct=True
except OSError: direct=False
print(json.dumps({"uid":os.getuid(),"docker_socket":os.path.exists("/var/run/docker.sock"),"provider_key":bool(os.getenv("OPENAI_API_KEY")),"direct_egress":direct}))
'''
    result = execute(engine,request(script))["result"]
    assert result == {"uid":10001,"docker_socket":False,"provider_key":False,"direct_egress":False}


def test_validated_artifacts_recovered_before_ephemeral_filesystem_cleanup(engine):
    result = execute(engine,request('import json; from pathlib import Path; Path("/workspace/outputs/evidence.txt").write_text("observed");print(json.dumps({"status":"unknown"}))'))
    assert result["result"]["status"] == "unknown"
    assert base64.b64decode(result["outputs"][0]["content_base64"]) == b"observed"


def test_timeout_kills_and_removes_workload(engine):
    with pytest.raises(RuntimeFailure) as error:
        execute(engine,request("import time; time.sleep(30)",timeout_seconds=2))
    assert error.value.code == "timeout"


def test_cancel_kills_running_container(engine):
    run_id = str(uuid.uuid4())
    cancelled = threading.Event()
    started = threading.Event()
    failures = []
    def work():
        try:
            engine.run(run_id,request("import time;time.sleep(30)"),cancelled.is_set,lambda _:started.set())
        except RuntimeFailure as exc:
            failures.append(exc.code)
        finally:
            engine.cleanup(run_id)
    thread = threading.Thread(target=work)
    thread.start()
    assert started.wait(10)
    cancelled.set()
    thread.join(10)
    assert not thread.is_alive() and failures == ["cancelled"]
    assert not engine.client.containers.list(all=True,filters={"label":f"{LABEL}={run_id}"})


def test_output_limit_and_symlink_are_truthful_failures(engine):
    for script in ['from pathlib import Path;import json;Path("/workspace/outputs/huge").write_bytes(b"x"*1024);print("{}")', 'from pathlib import Path;Path("/workspace/outputs/secret").symlink_to("/etc/passwd");print("{}")']:
        with pytest.raises(RuntimeFailure) as error:
            execute(engine,request(script,output_bytes=256))
        assert error.value.code == "workload_failed"


@pytest.mark.parametrize("agent,version", [("pi","1.0.0"),("claude","2.1.288"),("codex","0.160.0")])
def test_actual_native_cli_version(engine,agent,version):
    output = engine.client.containers.run("asset-monitor-"+agent+":0.1.0",[agent,"--version"],network_mode="none",user="10001:10001",cap_drop=["ALL"],security_opt=["no-new-privileges:true"],remove=True)
    assert version in output.decode()


def test_lab_base_runs_node(engine):
    output = engine.client.containers.run("asset-monitor-lab:0.1.0",["node","--version"],network_mode="none",user="10001:10001",remove=True)
    assert output.decode().strip() == "v24.9.0"


def test_lab_dependency_install_scripts_never_run(engine):
    """AC-A07: a Lab build cannot run a dependency install script. A vendored dependency's preinstall,
    install and postinstall each write a marker into its own directory; phase one installs it with
    scripts disabled, and the bundle's own `RUN npm rebuild` skips them too. The fixture is a
    `file:` tarball with a lockfile, so npm never needs a registry."""
    import hashlib
    scripts = {s: f"touch {s}-ran" for s in ("preinstall", "install", "postinstall")}
    marker = tgz({"package.json": json.dumps({"name":"marker","version":"1.0.0","main":"index.js","bin":{"marker":"index.js"},"scripts":scripts}),
                  "index.js": '#!/usr/bin/env node\nmodule.exports="marker-1.0.0";\n'}, "package/")
    spec = "file:vendor/marker-1.0.0.tgz"
    lock = {"name":"lab-fixture","version":"1.0.0","lockfileVersion":3,"requires":True,"packages":{
        "":{"name":"lab-fixture","version":"1.0.0","dependencies":{"marker":spec}},
        "node_modules/marker":{"version":"1.0.0","resolved":spec,"hasInstallScript":True,"bin":{"marker":"index.js"},
                               "integrity":"sha512-"+base64.b64encode(hashlib.sha512(marker).digest()).decode()}}}
    server = '''const fs=require("fs"),dir="/app/node_modules/marker/";
const seen={installed:require("marker"),bin:fs.lstatSync("/app/node_modules/.bin/marker").isSymbolicLink(),
 ran:["preinstall","install","postinstall"].filter(s=>fs.existsSync(dir+s+"-ran"))};
''' + SERVE.replace("BODY","JSON.stringify(seen)")
    poc = '''import json,os,sys,time,urllib.request
for _ in range(50):
    try:seen=json.loads(urllib.request.urlopen(os.environ["TARGET_URL"],timeout=1).read());break
    except OSError:time.sleep(.2)
else:sys.exit("the application never answered")
print(json.dumps(seen))
sys.exit(seen!={"installed":"marker-1.0.0","bin":True,"ran":[]})
'''
    app = {"Dockerfile":'FROM asset-monitor-lab:0.1.0\nWORKDIR /app\nCOPY . /app/\nRUN npm rebuild\nCMD ["node","/app/server.js"]\n',
           "package.json":json.dumps({"name":"lab-fixture","version":"1.0.0","private":True,"dependencies":{"marker":spec}}),
           "package-lock.json":json.dumps(lock), "vendor/marker-1.0.0.tgz":marker, "server.js":server}
    events = []
    result = execute(engine,lab(node_bundle(app,{"poc.py":poc,"report.md":"Install scripts never run."})),event=events.append)["result"]
    assert result["verified"] is True and result["pinned_image"].startswith("sha256:"), result["log"]
    assert json.loads(result["log"].strip().splitlines()[-1]) == {"installed":"marker-1.0.0","bin":True,"ran":[]}
    assert [e["type"] for e in events if e["type"].startswith("lab_")] == ["lab_dependencies","lab_build","lab_built","lab_started"]


def own_repository(server):
    """The input lab_run sends for an Own-repository Proof: the repository at the Verdict's commit
    under vulnerable-app/ (package.json, a lockfile with one vendored `file:` dependency, server.js)
    and the bundle's Dockerfile, PoC and report over it."""
    import hashlib
    greet = tgz({"package.json":'{"name":"greet","version":"1.0.0"}',"index.js":'module.exports="hello from greet";\n'},"package/")
    spec = "file:vendor/greet-1.0.0.tgz"
    lock = {"name":"shop","version":"1.0.0","lockfileVersion":3,"requires":True,"packages":{
        "":{"name":"shop","version":"1.0.0","dependencies":{"greet":spec}},
        "node_modules/greet":{"version":"1.0.0","resolved":spec,"integrity":"sha512-"+base64.b64encode(hashlib.sha512(greet).digest()).decode()}}}
    repository = {"package.json":json.dumps({"name":"shop","version":"1.0.0","dependencies":{"greet":spec}}),
                  "package-lock.json":json.dumps(lock),"vendor/greet-1.0.0.tgz":greet,"public/index.txt":"index","server.js":server}
    poc = '''import os,sys,time,urllib.request
base=os.environ["TARGET_URL"]
for _ in range(50):
    try:urllib.request.urlopen(base,timeout=1).read();break
    except OSError:time.sleep(.2)
else:sys.exit("the application never answered")
try:body=urllib.request.urlopen(base+"/?file=../package.json",timeout=2).read()
except OSError as e:print("traversal refused:",e);sys.exit(1)
print("read outside public/:",body.decode());sys.exit(b'"shop"' not in body)
'''
    return node_bundle(repository, {"vulnerable-app/Dockerfile":'FROM asset-monitor-lab:0.1.0\nWORKDIR /app\nCOPY . /app/\nCMD ["node","server.js"]\n',
                                    "poc.py":poc,"report.md":"Path traversal in ?file."})


# The Own repository's server.js at the Verdict's commit, and after its fix.
TRAVERSAL = '''const fs=require("fs"),path=require("path"),greet=require("greet");
require("http").createServer((q,r)=>{const f=new URL(q.url,"http://x").searchParams.get("file");
 try{r.end(f?fs.readFileSync("/app/public/"+NAME):greet)}catch(e){r.statusCode=404;r.end()}}).listen(8080);
'''


def test_own_repository_node_vulnerability_reproduces(engine):
    result = execute(engine,lab(own_repository(TRAVERSAL.replace("NAME","f"))))["result"]
    assert result["verified"] is True and result["status"] == "verified", result["log"]
    assert "read outside public/:" in result["log"] and '"shop"' in result["log"]


def test_own_repository_at_the_fixed_revision_is_not_reproduced(engine):
    result = execute(engine,lab(own_repository(TRAVERSAL.replace("NAME","path.basename(f)"))))["result"]
    assert (result["status"], result["verified"], result["exit_code"]) == ("not_reproduced", False, 1)
    assert "traversal refused: HTTP Error 404" in result["log"]


def test_lab_has_no_outbound_network(engine):
    """AC-A07 and ADR-0005: neither the application nor its PoC reaches another network, here a
    listener on a bridge named like the application network, or resolves a name. No packet is
    aimed at a public host: the listener is private and host.docker.internal is the Engine's own."""
    run_id = str(uuid.uuid4())
    labels = {LABEL:run_id, INSTANCE:engine.instance}
    outside = engine.client.networks.create(f"asset-monitor-lab-proof-{run_id}_application", labels=labels)
    listen = "import socket\ns=socket.create_server(('0.0.0.0',9000))\nwhile True:s.accept()[0].close()\n"
    listener = engine.client.containers.run("asset-monitor-probe:0.1.0",["python","-c",listen],network=outside.name,labels=labels,detach=True)
    connect = "import socket,sys,time\nfor _ in range(50):\n try:socket.create_connection((sys.argv[1],9000),1).close();break\n except OSError:time.sleep(.1)\nelse:sys.exit(1)\n"
    try:
        listener.reload()
        ip = listener.attrs["NetworkSettings"]["Networks"][outside.name]["IPAddress"]
        # The listener is live: a container on its own bridge reaches it.
        engine.client.containers.run("asset-monitor-probe:0.1.0",["python","-c",connect,ip],network=outside.name,labels=labels,remove=True)
        server = ('const net=require("net"),dns=require("dns"),seen={};\n'
                  'net.connect({host:"IP",port:9000}).setTimeout(3000,function(){seen.tcp="timeout";this.destroy()})'
                  '.on("connect",function(){seen.tcp="connected";this.destroy()}).on("error",e=>{seen.tcp=e.code});\n'
                  'dns.lookup("host.docker.internal",e=>{seen.dns=e?e.code:"resolved"});\n'
                  + SERVE.replace("BODY","JSON.stringify(seen)")).replace("IP",ip)
        poc = '''import json,os,socket,sys,time,urllib.request
for _ in range(100):
    try:
        app=json.loads(urllib.request.urlopen(os.environ["TARGET_URL"],timeout=1).read())
        if {"tcp","dns"}<=set(app):break
    except OSError:pass
    time.sleep(.2)
else:sys.exit("the application never reported")
def tcp():
    try:socket.create_connection(("IP",9000),3).close();return "connected"
    except OSError as e:return type(e).__name__
def dns():
    try:socket.getaddrinfo("host.docker.internal",80);return "resolved"
    except OSError:return "blocked"
seen={"application":app,"poc":{"tcp":tcp(),"dns":dns()}}
print(json.dumps(seen))
sys.exit(any(v in ("connected","resolved") for side in seen.values() for v in side.values()))
'''.replace("IP",ip)
        result = execute(engine,lab(node_lab(server,poc)),run_id)["result"]
        assert result["verified"] is True, result["log"]
        seen = json.loads(result["log"].strip().splitlines()[-1])
        assert seen["application"]["dns"] != "resolved" and seen["poc"] == {"tcp":seen["poc"]["tcp"],"dns":"blocked"}
        assert "connected" not in (seen["application"]["tcp"], seen["poc"]["tcp"]), seen
    finally:
        engine.cleanup(run_id)


LIMITS = {
    # The 8 MiB layer takes the image past a limit of its base plus 1 MiB.
    "image_bytes": ("RUN head -c 8388608 /dev/zero > /blob\n", 'print("built")', "lab_image_too_large"),
    # A silent step: the build stream yields nothing until the step ends.
    "build_seconds": ("RUN sleep 120\n", 'print("built")', "timeout"),
    # The run's deadline starts after the build and covers the application's 10 s startup watch,
    # so 15 s leaves the PoC asleep when it is stopped.
    "timeout_seconds": ("", "import time\ntime.sleep(120)", "timeout"),
}


@pytest.mark.parametrize("limit", LIMITS)
def test_lab_over_a_limit_fails_and_leaves_no_image(engine, limit):
    import time
    step, poc, code = LIMITS[limit]
    value = {"image_bytes": engine.client.images.get("asset-monitor-lab:0.1.0").attrs["Size"] + 1024**2,
             "build_seconds": 5, "timeout_seconds": 15}[limit]
    owned = lambda: {i.id for i in engine.client.images.list(all=True,filters={"label":"org.pruferva.asset-monitor.image=true"})}
    before, started = owned(), time.monotonic()
    with pytest.raises(RuntimeFailure) as error:
        execute(engine,lab(node_lab(SERVE.replace("BODY",'"up"'),poc,step),**{limit:value}))
    assert error.value.code == code, error.value.safe_message
    assert time.monotonic() - started < 60
    assert owned() == before


def test_memory_and_pid_limits_are_observed(engine):
    with pytest.raises(RuntimeFailure) as error:
        execute(engine,request('buffer=bytearray(1024*1024*1024); print("{}")',memory_mb=64))
    assert error.value.code in {"memory_limit","workload_failed"}
    script='''import subprocess,json
children=[]; exhausted=False
try:
 for _ in range(64):
  try: children.append(subprocess.Popen(["sleep","20"]))
  except OSError: exhausted=True;break
finally:
 for child in children:child.terminate();child.wait()
print(json.dumps({"spawned":len(children),"exhausted":exhausted}))
'''
    result=execute(engine,request(script,pids=16))["result"]
    assert result["exhausted"] and result["spawned"] < 16


def test_reconciliation_removes_abandoned_workloads(engine):
    run_id=str(uuid.uuid4())
    network=engine.client.networks.create('numen-abandoned-'+run_id,internal=True,labels={LABEL:run_id,INSTANCE:engine.instance})
    engine.client.containers.run('asset-monitor-probe:0.1.0',['sleep','60'],network=network.name,labels={LABEL:run_id,INSTANCE:engine.instance},detach=True)
    # The git mirror volume build runs shared before ADR-0005 carries no run label.
    cache=engine.client.volumes.create('numen-git-cache-test-'+run_id,labels={INSTANCE:engine.instance,'org.pruferva.asset-monitor.cache':'git'})
    engine.reconcile()
    assert not engine.client.containers.list(all=True,filters={"label":f"{LABEL}={run_id}"})
    assert not engine.client.networks.list(filters={"label":f"{LABEL}={run_id}"})
    assert cache.name not in {v.name for v in engine.client.volumes.list()}


def test_codex_narrow_seccomp_preserves_native_read_and_write_policies(engine):
    from pathlib import Path
    policy=json.loads((Path(__file__).parents[1]/'seccomp-codex.json').read_text())
    run_id=str(uuid.uuid4())
    network=engine.client.networks.create('asset-monitor-codex-proof-'+run_id,internal=True,labels={LABEL:run_id,INSTANCE:engine.instance})
    spec=engine.spec(request(''),network,{LABEL:run_id,INSTANCE:engine.instance})
    spec.pop('detach')
    spec['security_opt'].append('seccomp='+json.dumps(policy,separators=(',',':')))
    script='''import subprocess,json
from pathlib import Path
ro=subprocess.run(['codex','sandbox','-P',':read-only','-C','/workspace','--','python','-c','from pathlib import Path;Path("/workspace/denied").write_text("x")'],capture_output=True)
rw=subprocess.run(['codex','sandbox','-P',':workspace','-C','/workspace','--','python','-c','from pathlib import Path;Path("/workspace/allowed").write_text("x")'],capture_output=True)
print(json.dumps({"read_only_denied":ro.returncode!=0 and not Path('/workspace/denied').exists(),"workspace_write":rw.returncode==0 and Path('/workspace/allowed').read_text()=='x'}))
'''
    try:
        output=engine.client.containers.run('asset-monitor-codex:0.1.0',['python','-c',script],remove=True,**spec)
        assert json.loads(output)=={"read_only_denied":True,"workspace_write":True}
    finally:
        engine.cleanup(run_id)


def test_provider_proxy_allowlist_and_scoped_fetch_gateway(engine):
    run_id=str(uuid.uuid4())
    labels={LABEL:run_id,INSTANCE:engine.instance}
    inside=engine.client.networks.create('numen-proof-private-'+run_id,internal=True,labels=labels)
    outside=engine.client.networks.create('numen-proof-egress-'+run_id,labels=labels)
    fixture_code='''from http.server import BaseHTTPRequestHandler,HTTPServer
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path=='/redirect':self.send_response(302);self.send_header('Location','http://127.0.0.1:8080/');self.end_headers()
  else:self.send_response(200);self.end_headers();self.wfile.write(b'observed-target')
HTTPServer(('0.0.0.0',8080),H).serve_forever()
'''
    target=engine.client.containers.create('asset-monitor-probe:0.1.0',['python','-c',fixture_code],**engine.spec(request(''),outside,labels))
    target.start()
    target.reload()
    ip=target.attrs['NetworkSettings']['Networks'][outside.name]['IPAddress']
    url='http://'+ip+':8080'
    config={"provider_hosts":["api.openai.com"],"fetch_token":"capability-for-test","target_policy":{"origins":[url],"allowed_private_cidrs":[ip+'/32'],"max_requests":4}}
    gateway=engine.client.containers.create('asset-monitor-gateway:0.1.0',['python','-m','numen_runner.gateway'],environment={"NUMEN_GATEWAY_CONFIG":json.dumps(config)},**engine.spec(request(''),outside,labels))
    inside.connect(gateway,aliases=['gateway'])
    gateway.start()
    script='''import http.client,json,time
url=URL
for n in range(20):
 try:
  c=http.client.HTTPConnection('gateway',8082,timeout=1);c.request('GET','/health');c.getresponse().read();break
 except OSError:time.sleep(.2)
def call(path,token='capability-for-test'):
 c=http.client.HTTPConnection('gateway',8082,timeout=10);c.request('POST','/fetch',json.dumps({'url':path}),{'Content-Type':'application/json','X-Fetch-Token':token});r=c.getresponse();data=r.read();return r.status,data.decode()
allowed,body=call(url+'/')
wrong,_=call(url+'/','wrong')
redirect,_=call(url+'/redirect')
scope,_=call('http://127.0.0.1:8080/')
c=http.client.HTTPConnection('gateway',8082,timeout=10);c.set_tunnel('not-a-provider.example',443)
try:c.connect();deny=False
except OSError:deny=True
c=http.client.HTTPConnection('gateway',8082,timeout=10);c.set_tunnel('api.openai.com',443)
try:c.connect();provider=True;c.close()
except OSError:provider=False
print(json.dumps({'allowed':allowed,'body':json.loads(body),'wrong':wrong,'redirect':redirect,'scope':scope,'provider_allowed':provider,'provider_denied':deny}))
'''.replace('URL',repr(url))
    spec=engine.spec(request(''),inside,labels)
    spec.pop('detach')
    try:
        output=engine.client.containers.run('asset-monitor-probe:0.1.0',['python','-c',script],remove=True,**spec)
        result=json.loads(output)
        assert result['allowed']==200 and base64.b64decode(result['body']['content_base64'])==b'observed-target'
        assert result['wrong']==result['redirect']==result['scope']==403
        assert result['provider_allowed'] and result['provider_denied']
    finally:
        engine.cleanup(run_id)


def test_immutable_inputs_and_false_poc_result_are_preserved(engine):
    result=execute(engine,request('import json;from pathlib import Path\ntry:Path("/workspace/inputs/recipe.py").write_text("altered");blocked=False\nexcept OSError:blocked=True\nprint(json.dumps({"immutable":blocked}))'))
    assert result['result']['immutable']
    assert result['execution']['image_digest'].startswith('sha256:')
    files=node_lab('setTimeout(()=>{},30000);\n','import sys;print("observed failure to reproduce");sys.exit(3)')
    result=execute(engine,lab(files,timeout_seconds=30))['result']
    assert result['verified'] is False and result['status']=='not_reproduced' and result['exit_code']==3
    assert 'observed failure to reproduce' in result['log']


def test_codex_native_tools_cannot_read_private_auth_cache(engine):
    from pathlib import Path
    policy=json.loads((Path(__file__).parents[1]/'seccomp-codex.json').read_text())
    run_id=str(uuid.uuid4())
    network=engine.client.networks.create('asset-monitor-codex-private-'+run_id,internal=True,labels={LABEL:run_id,INSTANCE:engine.instance})
    spec=engine.spec(request(''),network,{LABEL:run_id,INSTANCE:engine.instance})
    spec.pop('detach')
    spec['security_opt'].append('seccomp='+json.dumps(policy,separators=(',',':')))
    script='''import subprocess,json
from pathlib import Path
Path('/home/job/secret').write_text('private-value')
args=['codex','sandbox','-P','numen','-c','permissions.numen.extends=":workspace"','-c','permissions.numen.filesystem./home/job="deny"','-C','/workspace','--','python','-c','from pathlib import Path;Path("/workspace/allowed").write_text("artifact");Path("/home/job/secret").read_text()']
result=subprocess.run(args,capture_output=True)
print(json.dumps({'denied':result.returncode!=0 and b'Permission denied' in result.stderr,'artifact':Path('/workspace/allowed').read_text()}))
'''
    try:
        output=engine.client.containers.run('asset-monitor-codex:0.1.0',['python','-c',script],remove=True,**spec)
        assert json.loads(output)=={'denied':True,'artifact':'artifact'}
    finally:
        engine.cleanup(run_id)


def test_native_codex_catalog_does_not_claim_access_without_account(engine):
    run_id=str(uuid.uuid4())
    labels={LABEL:run_id,INSTANCE:engine.instance}
    network=engine.client.networks.create('asset-monitor-codex-noauth-'+run_id,internal=True,labels=labels)
    spec=engine.spec(request(''),network,labels)
    spec.pop('detach')
    script='''import os,json
from numen_runner.workload import rpc_models
try:
 rpc_models({**os.environ,'CODEX_HOME':'/home/job/.codex'},20,native=True);ready=True
except ValueError:ready=False
print(json.dumps({'ready':ready}))
'''
    try:
        output=engine.client.containers.run('asset-monitor-codex:0.1.0',['python','-c',script],remove=True,**spec)
        assert json.loads(output)=={'ready':False}
    finally:
        engine.cleanup(run_id)


def test_pi_fixed_dependency_and_bundled_entrypoint_are_verified(engine):
    script='''import {expand} from '/opt/numen/node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion/dist/esm/index.js';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const root='/opt/numen/node_modules/@earendil-works/pi-coding-agent';
const version=JSON.parse(readFileSync(root+'/node_modules/brace-expansion/package.json')).version;
const bundle=readFileSync(root+'/dist/bundle/chunks/chunk-33XOIQ5N.js');
const deep=expand('{'.repeat(2000)+'a,b'+'}'.repeat(2000));
const depthBound=deep.some(x=>x.includes('a,b')) && JSON.stringify(expand('{a,{b,c}}',{maxDepth:0}))===JSON.stringify(['a','{b,c}']);
console.log(JSON.stringify({version,normal:expand('a{b,c}d'),numbers:expand('{1..3}'),depthBound,bundleHash:createHash('sha256').update(bundle).digest('hex')}));
'''
    output=engine.client.containers.run('asset-monitor-pi:0.1.0',['node','--input-type=module','-e',script],network_mode='none',user='10001:10001',remove=True,mem_limit='256m',nano_cpus=1000000000,pids_limit=32)
    result=json.loads(output)
    assert result['version']=='5.0.12' and result['normal']==['abd','acd'] and result['numbers']==['1','2','3']
    assert result['depthBound'] and result['bundleHash']=='140daad3badc613549342760f22fade24121fb332cdbead61fa6719479df85f0'


def test_completed_lab_stays_nonterminal_until_application_cleanup_is_confirmed(engine, tmp_path):
    import time
    from fastapi.testclient import TestClient
    from numen_runner.broker import create_app
    class TemporaryCleanupFailure:
        available = True
        def reconcile(self):
            engine.reconcile()
        def run(self,*args):
            value=engine.run(*args)
            self.available=False
            return value
        def cleanup(self,run_id):
            if not self.available:
                raise RuntimeError('transient cleanup failure')
            engine.cleanup(run_id)
    wrapper=TemporaryCleanupFailure()
    token='protected-engine-lifecycle-token'
    headers={'X-Broker-Token':token}
    files=node_lab(SERVE.replace('BODY','"observed"'),
        'import os,time,urllib.request\nfor _ in range(30):\n try:\n  assert urllib.request.urlopen(os.environ["TARGET_URL"],timeout=1).read()==b"observed";break\n except OSError:time.sleep(.1)\nelse:raise RuntimeError("lab unavailable")\n')
    body=lab(files,timeout_seconds=30).model_dump()
    run_id=None
    try:
        with TestClient(create_app(token,tmp_path,engine=wrapper,reconcile_interval=.05)) as client:
            run_id=client.post('/internal/runs',headers=headers,json=body).json()['run_id']
            # Phase one, the build and the application's 10 s startup watch come first: about 20 s
            # on a loaded Docker Desktop, so 20 s was a race.
            deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                state=client.get('/internal/runs/'+run_id,headers=headers).json()
                if state.get('error',{}).get('code')=='cleanup_pending':
                    break
                time.sleep(.05)
            assert state['status']=='cancelling'
            assert engine.client.containers.list(filters={'label':f'{LABEL}={run_id}','status':'running'})
            assert client.post('/internal/runs',headers=headers,json={'attempt_token':'replacement','kind':'probe'}).status_code==503
            wrapper.available=True
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                state=client.get('/internal/runs/'+run_id,headers=headers).json()
                if state['status']=='succeeded':
                    break
                time.sleep(.05)
            assert state['status']=='succeeded' and state['result']['verified']
            assert not engine.client.containers.list(all=True,filters={'label':f'{LABEL}={run_id}'})
            assert not engine.client.volumes.list(filters={'label':f'{LABEL}={run_id}'})
    finally:
        wrapper.available=True
        if run_id:
            engine.cleanup(run_id)


def test_analysis_container_has_no_docker_daemon_no_registry_and_only_provider_and_herdr_egress(engine, monkeypatch):
    """An Analysis builds nothing. DockerEngine.run sets up a real Analysis run in a Herdr session,
    with only its workload command swapped for a probe (so no agent or provider is involved): the
    workload has no daemon, socket or registry, and its only way out is the credential-free gateway,
    which allows its provider's hosts plus herdr.dev."""
    from docker.models.containers import ContainerCollection
    run_id = str(uuid.uuid4())
    job = RunRequest(attempt_token=run_id, kind="agent", limits={"timeout_seconds":120},
                     profile={"agent":"pi","provider_id":"deepseek","model_id":"m","operation":"commit_analysis",
                              "credential":{"api_key":"fixture-key-no-real-access"}})
    script = """import http.client,json,os,shutil,socket,time
for _ in range(50):
 try:
  c=http.client.HTTPConnection('gateway',8082,timeout=2);c.request('GET','/health');c.getresponse().read();break
 except OSError:time.sleep(.2)
def connect(host):
 c=http.client.HTTPConnection('gateway',8082,timeout=10);c.request('CONNECT',host+':443');return c.getresponse().status
def resolves(host):
 try:socket.getaddrinfo(host,2375);return True
 except OSError:return False
s=socket.socket();s.settimeout(3)
try:s.connect(('8.8.8.8',443));direct=True
except OSError:direct=False
print(json.dumps({'envelope':{'outputs':[],'result':{'docker_binary':shutil.which('docker'),
 'docker_socket':os.path.exists('/var/run/docker.sock'),'docker_host':'DOCKER_HOST' in os.environ,
 'daemon_resolves':resolves('docker'),'direct_egress':direct,
 'registries':{h:connect(h) for h in ('registry.npmjs.org','github.com','pypi.org')}}}}))
"""
    create = ContainerCollection.create
    def probe(self, image, command=None, **kwargs):
        if command == ["python","-m","numen_runner.workload"]:
            command = ["python","-c",script]
        return create(self, image, command, **kwargs)
    monkeypatch.setattr(ContainerCollection, "create", probe)
    monkeypatch.setattr(engine, "agent_backend", "herdr")
    try:
        observed = engine.run(run_id, job, lambda: False, lambda _: None)["result"]
        assert observed == {"docker_binary": None, "docker_socket": False, "docker_host": False, "daemon_resolves": False,
                            "direct_egress": False, "registries": {"registry.npmjs.org": 403, "github.com": 403, "pypi.org": 403}}
        containers = {c.image.tags[0]: c for c in engine.client.containers.list(all=True, filters={"label":f"{LABEL}={run_id}"})}
        assert set(containers) == {"asset-monitor-gateway:" + VERSION, "asset-monitor-pi:" + VERSION}
        gateway, agent = containers["asset-monitor-gateway:" + VERSION], containers["asset-monitor-pi:" + VERSION]
        config = dict(e.split("=", 1) for e in gateway.attrs["Config"]["Env"])["NUMEN_GATEWAY_CONFIG"]
        assert json.loads(config) == {"provider_hosts": PROVIDERS["deepseek"] + ["herdr.dev"]}
        assert not agent.attrs["HostConfig"]["Privileged"] and agent.attrs["HostConfig"]["CapDrop"] == ["ALL"]
        assert list(agent.attrs["NetworkSettings"]["Networks"]) == ["numen-job-" + run_id]
        # Only its read-only inputs and its private session home: no socket, no cache, no daemon.
        assert {(m["Destination"], m["RW"]) for m in agent.attrs["Mounts"]} == {("/workspace/inputs", False), ("/home/job", True)}
        assert not any(e.startswith("DOCKER_") for e in agent.attrs["Config"]["Env"])
    finally:
        engine.cleanup(run_id)
        assert not engine.client.containers.list(all=True, filters={"label":f"{LABEL}={run_id}"})
        assert not engine.client.networks.list(filters={"label":f"{LABEL}={run_id}"})
        assert not engine.client.volumes.list(filters={"label":f"{LABEL}={run_id}"})
