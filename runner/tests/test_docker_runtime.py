"""Explicit Engine tests. Run in runner-test with socket and NUMEN_DOCKER_TESTS=1."""
import base64
import io
import json
import os
import tarfile
import threading
import uuid
import pytest
from numen_runner.contracts import RunRequest
from numen_runner.engine import DockerEngine, RuntimeFailure, LABEL, INSTANCE, VERSION

pytestmark = pytest.mark.skipif(os.getenv("NUMEN_DOCKER_TESTS") != "1", reason="explicit Docker Engine verification only")

@pytest.fixture
def engine():
    value = DockerEngine()
    value.ping()
    return value


def request(script, **limits):
    return RunRequest(attempt_token=str(uuid.uuid4()), kind="probe", inputs=[{"path":"recipe.py","content_base64":base64.b64encode(script.encode()).decode()}], limits={"timeout_seconds":30, **limits})


def execute(engine, job):
    run_id = str(uuid.uuid4())
    try:
        return engine.run(run_id,job,lambda:False,lambda _:None)
    finally:
        engine.cleanup(run_id)
        assert not engine.client.containers.list(all=True,filters={"label":f"{LABEL}={run_id}"})
        assert not engine.client.networks.list(filters={"label":f"{LABEL}={run_id}"})


def test_agent_source_archive_is_staged_as_read_only_files(engine):
    run_id = str(uuid.uuid4())
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for path in ("index.php", "concrete/src/Kernel.php"):
            info = tarfile.TarInfo(path)
            info.size = len(path)
            archive.addfile(info, io.BytesIO(path.encode()))
    job = RunRequest(attempt_token=run_id, kind="agent",
                     profile={"operation": "cve_analysis", "model_id": "m", "credential": {"api_key": "k"}},
                     inputs=[{"path": "source", "content_base64": base64.b64encode(payload.getvalue()).decode(), "archive": True}])
    labels = {LABEL: run_id, INSTANCE: engine.instance}
    try:
        volume = engine.materialize_inputs(run_id, job, labels)
        # The trailing echo terminates cat's unterminated line, which the log stream may drop at exit.
        listing = engine.client.containers.run("numen-probe:0.1.0", ["sh", "-c", "find /inputs -type f | sort; cat /inputs/source/concrete/src/Kernel.php; echo"],
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
    output = engine.client.containers.run("numen-"+agent+":0.1.0",[agent,"--version"],network_mode="none",user="10001:10001",cap_drop=["ALL"],security_opt=["no-new-privileges:true"],remove=True)
    assert version in output.decode()


def test_lab_build_and_poc_actual_verification(engine):
    files = {
      "vulnerable-app/Dockerfile":'FROM numen-lab:0.1.0\nWORKDIR /app\nCOPY app.py /app/app.py\nCMD ["python","/app/app.py"]\n',
      "vulnerable-app/app.py":'from http.server import BaseHTTPRequestHandler,HTTPServer\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.end_headers();self.wfile.write(b"fixture-vulnerable-version-1")\nHTTPServer(("0.0.0.0",8080),H).serve_forever()\n',
      "poc.py":'import os,time,urllib.request\nfor n in range(20):\n try:\n  data=urllib.request.urlopen(os.environ["TARGET_URL"],timeout=1).read();assert b"fixture-vulnerable-version-1" in data;print("reproduced fixture version 1");break\n except OSError: time.sleep(.2)\nelse: raise RuntimeError("lab unavailable")\n',
      "report.md":"Fixture version 1; isolated verification only."
    }
    job = RunRequest(attempt_token=str(uuid.uuid4()),kind="lab",inputs=[{"path":path,"content_base64":base64.b64encode(data.encode()).decode()} for path,data in files.items()],limits={"timeout_seconds":60})
    result = execute(engine,job)["result"]
    assert result["verified"] and result["exit_code"] == 0 and result["pinned_image"].startswith("sha256:")
    assert "reproduced fixture version 1" in result["log"]


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
    engine.client.containers.run('numen-probe:0.1.0',['sleep','60'],network=network.name,labels={LABEL:run_id,INSTANCE:engine.instance},detach=True)
    engine.reconcile()
    assert not engine.client.containers.list(all=True,filters={"label":f"{LABEL}={run_id}"})
    assert not engine.client.networks.list(filters={"label":f"{LABEL}={run_id}"})


def test_codex_narrow_seccomp_preserves_native_read_and_write_policies(engine):
    from pathlib import Path
    policy=json.loads((Path(__file__).parents[1]/'seccomp-codex.json').read_text())
    run_id=str(uuid.uuid4())
    network=engine.client.networks.create('numen-codex-proof-'+run_id,internal=True,labels={LABEL:run_id,INSTANCE:engine.instance})
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
        output=engine.client.containers.run('numen-codex:0.1.0',['python','-c',script],remove=True,**spec)
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
    target=engine.client.containers.create('numen-probe:0.1.0',['python','-c',fixture_code],**engine.spec(request(''),outside,labels))
    target.start()
    target.reload()
    ip=target.attrs['NetworkSettings']['Networks'][outside.name]['IPAddress']
    url='http://'+ip+':8080'
    config={"provider_hosts":["api.openai.com"],"fetch_token":"capability-for-test","target_policy":{"origins":[url],"allowed_private_cidrs":[ip+'/32'],"max_requests":4}}
    gateway=engine.client.containers.create('numen-gateway:0.1.0',['python','-m','numen_runner.gateway'],environment={"NUMEN_GATEWAY_CONFIG":json.dumps(config)},**engine.spec(request(''),outside,labels))
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
        output=engine.client.containers.run('numen-probe:0.1.0',['python','-c',script],remove=True,**spec)
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
    files={'vulnerable-app/Dockerfile':'FROM numen-lab:0.1.0\nCMD ["sleep","30"]\n','poc.py':'import sys;print("observed failure to reproduce");sys.exit(3)','report.md':'Fixture not reproduced.'}
    job=RunRequest(attempt_token=str(uuid.uuid4()),kind='lab',inputs=[{'path':p,'content_base64':base64.b64encode(d.encode()).decode()}for p,d in files.items()],limits={'timeout_seconds':30})
    result=execute(engine,job)['result']
    assert result['verified'] is False and result['status']=='not_reproduced' and result['exit_code']==3
    assert 'observed failure to reproduce' in result['log']


def test_codex_native_tools_cannot_read_private_auth_cache(engine):
    from pathlib import Path
    policy=json.loads((Path(__file__).parents[1]/'seccomp-codex.json').read_text())
    run_id=str(uuid.uuid4())
    network=engine.client.networks.create('numen-codex-private-'+run_id,internal=True,labels={LABEL:run_id,INSTANCE:engine.instance})
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
        output=engine.client.containers.run('numen-codex:0.1.0',['python','-c',script],remove=True,**spec)
        assert json.loads(output)=={'denied':True,'artifact':'artifact'}
    finally:
        engine.cleanup(run_id)


def test_native_codex_catalog_does_not_claim_access_without_account(engine):
    run_id=str(uuid.uuid4())
    labels={LABEL:run_id,INSTANCE:engine.instance}
    network=engine.client.networks.create('numen-codex-noauth-'+run_id,internal=True,labels=labels)
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
        output=engine.client.containers.run('numen-codex:0.1.0',['python','-c',script],remove=True,**spec)
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
    output=engine.client.containers.run('numen-pi:0.1.0',['node','--input-type=module','-e',script],network_mode='none',user='10001:10001',remove=True,mem_limit='256m',nano_cpus=1000000000,pids_limit=32)
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
    files={
        'vulnerable-app/Dockerfile':'FROM numen-lab:0.1.0\nCOPY app.py /app.py\nCMD ["python","/app.py"]\n',
        'vulnerable-app/app.py':'from http.server import BaseHTTPRequestHandler,HTTPServer\nclass H(BaseHTTPRequestHandler):\n def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b"observed")\nHTTPServer(("0.0.0.0",8080),H).serve_forever()\n',
        'poc.py':'import os,time,urllib.request\nfor _ in range(30):\n try:\n  assert urllib.request.urlopen(os.environ["TARGET_URL"],timeout=1).read()==b"observed";break\n except OSError:time.sleep(.1)\nelse:raise RuntimeError("lab unavailable")\n',
        'report.md':'Lifecycle verification fixture.'}
    body=RunRequest(attempt_token=str(uuid.uuid4()),kind='lab',inputs=[{'path':p,'content_base64':base64.b64encode(d.encode()).decode()}for p,d in files.items()],limits={'timeout_seconds':30}).model_dump()
    run_id=None
    try:
        with TestClient(create_app(token,tmp_path,engine=wrapper,reconcile_interval=.05)) as client:
            run_id=client.post('/internal/runs',headers=headers,json=body).json()['run_id']
            deadline=time.monotonic()+20
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


def test_build_run_gets_a_private_daemon_and_a_writable_nonroot_workspace(engine):
    run_id = str(uuid.uuid4())
    job = RunRequest(attempt_token=run_id, kind="agent", build=True,
                     profile={"operation":"cve_analysis","model_id":"m","credential":{"api_key":"k"}})
    labels = {LABEL:run_id, INSTANCE:engine.instance}
    try:
        network = engine.client.networks.create("numen-job-" + run_id, internal=True, labels=labels)
        engine.start_build_daemon(run_id, job, network, labels)
        spec = engine.spec(job, network, labels)
        # The workspace is disk backed for a build run, and the workload itself stays unprivileged.
        assert "/workspace" not in spec["tmpfs"] and spec["read_only"] and spec["user"] == "10001:10001"
        assert spec["cap_drop"] == ["ALL"] and "no-new-privileges:true" in spec["security_opt"]
        workspace = engine.client.volumes.create("numen-workspace-" + run_id, labels=labels)
        observed = engine.client.containers.run(
            "numen-codex:" + VERSION,
            ["sh","-c","id -u; git --version >/dev/null && echo git-ok; test -e /var/run/docker.sock && echo SOCKET || echo no-host-socket; "
                       "touch /workspace/writable && echo workspace-writable; docker run --rm alpine:3.20 echo nested-ok"],
            environment={"DOCKER_HOST":"tcp://docker:2375"}, network=network.name,
            volumes={workspace.name:{"bind":"/workspace","mode":"rw"}}, user="10001:10001",
            labels=labels, remove=True)
        assert observed.decode().split() == ["10001","git-ok","no-host-socket","workspace-writable","nested-ok"]
    finally:
        engine.cleanup(run_id)
        assert not engine.client.containers.list(all=True,filters={"label":f"{LABEL}={run_id}"})
        assert not engine.client.volumes.list(filters={"label":f"{LABEL}={run_id}"})
        assert not engine.client.networks.list(filters={"label":f"{LABEL}={run_id}"})


def test_build_agent_run_wires_the_daemon_and_workspace_before_the_provider_step(engine):
    run_id = str(uuid.uuid4())
    job = RunRequest(attempt_token=run_id, kind="agent", build=True, limits={"timeout_seconds":120},
                     profile={"agent":"codex","provider_id":"openai","model_id":"m",
                              "operation":"cve_analysis","credential":{"api_key":"fixture-key-no-real-access"}})
    events = []
    try:
        # The run cannot reach a provider with a fixture credential; its capability wiring still must hold.
        with pytest.raises(RuntimeFailure):
            engine.run(run_id, job, lambda: False, events.append)
        assert any(e["type"] == "build_daemon_started" for e in events), events
        workload = next(c for c in engine.client.containers.list(all=True, filters={"label":f"{LABEL}={run_id}"})
                        if c.image.tags and c.image.tags[0].startswith("numen-codex"))
        assert "DOCKER_HOST=tcp://docker:2375" in workload.attrs["Config"]["Env"]
        workspace = [m for m in workload.attrs["Mounts"] if m["Destination"] == "/workspace"]
        assert workspace and workspace[0]["Type"] == "volume" and workspace[0]["RW"]
        assert workload.attrs["HostConfig"]["ReadonlyRootfs"] and workload.attrs["HostConfig"]["CapDrop"] == ["ALL"]
        assert not any(m["Source"] == "/var/run/docker.sock" for m in workload.attrs["Mounts"])
    finally:
        engine.cleanup(run_id)
        assert not engine.client.volumes.list(filters={"label":f"{LABEL}={run_id}"})
