"""Pi integration proofs use the pinned image with no external network or real accounts."""

import io
import json
import os
import tarfile
import uuid
from pathlib import Path

import pytest

from numen_runner import workload
from numen_runner.adapters import agent_argv, parse_agent, pi_event
from numen_runner.contracts import RunRequest

ROOT = Path(__file__).parents[1]
DOCKER = pytest.mark.skipif(
    os.getenv("NUMEN_DOCKER_TESTS") != "1", reason="explicit pinned Pi image verification"
)


def image_script(script, files=None, env=None):
    import docker

    client = docker.from_env()
    container = client.containers.create(
        "numen-pi:0.1.0",
        ["node", "/opt/numen/numen-pi-proof.mjs"],
        working_dir="/opt/numen",
        network_mode="none",
        user="10001:10001",
        environment={
            "PI_CODING_AGENT_DIR": "/home/job/.pi/agent",
            "PI_OFFLINE": "1",
            "PI_TELEMETRY": "0",
            **(env or {}),
        },
        tmpfs={
            "/workspace": "size=64m,uid=10001,gid=10001",
            "/home/job": "size=32m,uid=10001,gid=10001",
        },
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        mem_limit="1g",
        pids_limit=128,
        labels={"numen.pi-proof": str(uuid.uuid4())},
    )
    try:
        archive = io.BytesIO()
        content = {"numen-pi-proof.mjs": script.encode(), **(files or {})}
        source_root = Path(os.getenv("NUMEN_PI_SOURCE_ROOT", str(ROOT / "node")))
        for name in ("pi-capabilities.mjs", "pi-commandcode-login.mjs", "pi-tools.ts"):
            if (source_root / name).is_file():
                content[name] = (source_root / name).read_bytes()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            for path, data in content.items():
                item = tarfile.TarInfo(path)
                item.size, item.mode, item.uid, item.gid = len(data), 0o600, 10001, 10001
                tar.addfile(item, io.BytesIO(data))
        container.put_archive("/opt/numen", archive.getvalue())
        container.start()
        result = container.wait(timeout=30)
        stdout = container.logs(stdout=True, stderr=False).decode()
        stderr = container.logs(stdout=False, stderr=True).decode()
        assert result["StatusCode"] == 0, stderr[-1500:]
        return json.loads(stdout.strip().splitlines()[-1])
    finally:
        container.remove(force=True)
        client.close()


@pytest.mark.parametrize(
    "provider,variable",
    [
        ("deepseek", "DEEPSEEK_API_KEY"),
        ("commandcode", "COMMAND_CODE_API_KEY"),
        ("openai", "OPENAI_API_KEY"),
        ("claude", "ANTHROPIC_API_KEY"),
    ],
)
def test_pi_api_key_mapping_and_argv_use_selected_provider_only(provider, variable):
    profile = {
        "agent": "pi",
        "provider_id": provider,
        "auth_type": "api_key",
        "credential": {"api_key": "synthetic-pi-key-no-access"},
        "model_id": "selected-model",
        "reasoning_effort": "high",
        "operation": "commit_analysis",
    }
    env = {}
    workload.setup_auth(profile, env)
    assert env == {variable: "synthetic-pi-key-no-access"}
    argv = agent_argv(profile)
    assert argv[argv.index("--provider") + 1] == ("anthropic" if provider == "claude" else provider)
    assert argv[argv.index("--thinking") + 1] == "high"
    assert "synthetic-pi-key-no-access" not in " ".join(argv)
    assert "--no-builtin-tools" in argv and "--no-context-files" in argv
    assert any("pi-commandcode-provider" in part for part in argv) is (provider == "commandcode")


def test_pi_native_oauth_and_disabled_commandcode_plugin_are_rejected():
    for profile in [
        {
            "agent": "pi",
            "provider_id": "openai",
            "auth_type": "native_oauth",
            "credential": {"auth_json": {"tokens": {"access_token": "fixture"}}},
        },
        {
            "agent": "pi",
            "provider_id": "commandcode",
            "auth_type": "api_key",
            "credential": {"api_key": "fixture"},
            "enabled_plugins": [],
        },
    ]:
        with pytest.raises(ValueError):
            RunRequest(attempt_token="pi-denied", kind="capabilities", profile=profile)


@DOCKER
@pytest.mark.parametrize(
    "provider,variable,model_id",
    [
        ("openai", "OPENAI_API_KEY", "gpt-5"),
        ("deepseek", "DEEPSEEK_API_KEY", "deepseek-flash"),
        ("claude", "ANTHROPIC_API_KEY", "claude-opus-4-7"),
    ],
)
def test_pinned_pi_catalog_preserves_supported_and_actual_default_effort(
    provider, variable, model_id
):
    script = f"""
import {{mkdir}} from 'node:fs/promises';
import {{spawnSync}} from 'node:child_process';
import {{ModelRuntime,createAgentSession,DefaultResourceLoader,SessionManager,SettingsManager}} from '@earendil-works/pi-coding-agent';
import {{getSupportedThinkingLevels}} from '@earendil-works/pi-ai/compat';
await mkdir('/workspace/inputs',{{recursive:true}});await mkdir('/workspace/outputs',{{recursive:true}});await mkdir(process.env.PI_CODING_AGENT_DIR,{{recursive:true}});
const rt=await ModelRuntime.create({{authPath:process.env.PI_CODING_AGENT_DIR+'/auth.json',modelsPath:null}});
const model=rt.getModel({json.dumps("anthropic" if provider == "claude" else provider)},{json.dumps(model_id)});
const settings=SettingsManager.create('/workspace',process.env.PI_CODING_AGENT_DIR);
const resources=new DefaultResourceLoader({{cwd:'/workspace',agentDir:process.env.PI_CODING_AGENT_DIR,settingsManager:settings,noExtensions:true,noSkills:true,noPromptTemplates:true,noThemes:true,noContextFiles:true}});await resources.reload();
const {{session}}=await createAgentSession({{cwd:'/workspace',agentDir:process.env.PI_CODING_AGENT_DIR,modelRuntime:rt,model,settingsManager:settings,resourceLoader:resources,sessionManager:SessionManager.inMemory(),tools:[]}});
const child=spawnSync('node',['/opt/numen/pi-capabilities.mjs',{json.dumps(provider)}],{{env:process.env,encoding:'utf8'}});if(child.status)throw new Error('capability helper failed');
const found=JSON.parse(child.stdout.trim().split('\\n').at(-1)).models.find(m=>m.id==={json.dumps(model_id)});
console.log(JSON.stringify({{catalog:found,expected:getSupportedThinkingLevels(model).filter(e=>e!=='off'),actual_default:session.thinkingLevel}}));await session.dispose();
"""
    observed = image_script(script, env={variable: "synthetic-pi-key-no-access"})
    assert observed["catalog"]["reasoning_efforts"] == observed["expected"]
    assert observed["catalog"]["default_effort"] == observed["actual_default"]


@DOCKER
def test_pi_bounded_tools_validate_and_deny_private_input_writes():
    script = """
import register from '/opt/numen/pi-tools.ts';
import {mkdir,writeFile,readFile,symlink} from 'node:fs/promises';
import {validateToolCall} from '@earendil-works/pi-ai/compat';
await mkdir('/workspace/inputs',{recursive:true});await mkdir('/workspace/outputs',{recursive:true});
await writeFile('/workspace/inputs/source.txt','source evidence');await writeFile('/home/job/private.txt','fixture private marker');
let tools=[];register({registerTool:t=>tools.push(t)});
async function call(name,args){const tool=tools.find(t=>t.name===name);return tool.execute('1',validateToolCall(tools,{id:'1',name,arguments:args}));}
const denied=[];for(const [name,args] of [['numen_read',{path:'/home/job/private.txt'}],['numen_write',{path:'inputs/source.txt',content:'mutated'}],['numen_read',{path:'inputs/../../home/job/private.txt'}],['target_fetch',{url:'https://example.invalid',method:'POST'}],['numen_shell',{command:'id'}]]){try{await call(name,args);denied.push(false);}catch{denied.push(true);}}
await symlink('/home/job/private.txt','/workspace/inputs/escape.txt');try{await call('numen_read',{path:'inputs/escape.txt'});denied.push(false);}catch{denied.push(true);}
const read=await call('numen_read',{path:'inputs/source.txt'});await call('numen_write',{path:'outputs/report.md',content:'# Artifact'});
console.log(JSON.stringify({denied,read:read.content[0].text,source:await readFile('/workspace/inputs/source.txt','utf8'),artifact:await readFile('/workspace/outputs/report.md','utf8'),tools:tools.map(t=>t.name)}));
"""
    observed = image_script(script)
    assert all(observed["denied"])
    assert observed["read"] == observed["source"] == "source evidence"
    assert observed["artifact"] == "# Artifact"
    # numen_shell is registered but refuses without a build capability, and only build runs enable it.
    assert set(observed["tools"]) == {"numen_read", "numen_list", "numen_write", "target_fetch", "numen_shell"}


@DOCKER
def test_pi_denied_symlink_write_makes_no_outside_directories():
    script = """
import register from '/opt/numen/pi-tools.ts';import {mkdir,symlink,stat} from 'node:fs/promises';
await mkdir('/workspace/outputs',{recursive:true});await mkdir('/home/job/private',{recursive:true});await symlink('/home/job/private','/workspace/outputs/redirect');
let tools=[];register({registerTool:t=>tools.push(t)});let denied=false;
try{await tools.find(t=>t.name==='numen_write').execute('1',{path:'outputs/redirect/new/artifact.md',content:'x'});}catch{denied=true;}
let outside=false;try{await stat('/home/job/private/new');outside=true;}catch{}
console.log(JSON.stringify({denied,outside}));
"""
    observed = image_script(script)
    assert observed == {"denied": True, "outside": False}


@DOCKER
@pytest.mark.parametrize("allowed", [True, False, None])
def test_commandcode_catalog_requires_the_selected_key_to_authenticate(allowed):
    script = f"""
import {{mkdir}} from 'node:fs/promises';
await mkdir('/workspace/inputs',{{recursive:true}});await mkdir('/workspace/outputs',{{recursive:true}});await mkdir(process.env.PI_CODING_AGENT_DIR,{{recursive:true}});
const calls=[];globalThis.fetch=async(url,options={{}})=>{{
 const path=new URL(String(url)).pathname;
 calls.push({{path,credential_matches:new Headers(options.headers).get('authorization')==='Bearer '+process.env.COMMAND_CODE_API_KEY}});
 if(path==='/provider/v1/models')return new Response(JSON.stringify({{object:'list',data:[{{id:'gpt-5',name:'GPT fixture',context_length:128000}}]}}),{{status:200,headers:{{'content-type':'application/json'}}}});
 if(path==='/alpha/whoami')return new Response(JSON.stringify({json.dumps({"user": {"userName": "fixture-account"}} if allowed is not None else {"unexpected": "malformed identity"})}),{{status:{401 if allowed is False else 200},headers:{{'content-type':'application/json'}}}});
 throw new Error('Unexpected endpoint in offline fixture');
}};
const outputs=[];console.log=(value)=>outputs.push(JSON.parse(value));let exit=null;process.exit=code=>{{exit=code;throw new Error('helper exited')}};
process.argv[2]='commandcode';try{{await import('/opt/numen/pi-capabilities.mjs?commandcode-proof')}}catch(error){{if(exit===null)throw error;}}
process.stdout.write(JSON.stringify({{calls,catalog:outputs.at(-1),exit}})+'\\n');
"""
    observed = image_script(
        script, env={"COMMAND_CODE_API_KEY": "synthetic-commandcode-key-no-access"}
    )
    authenticated = [call for call in observed["calls"] if call["path"] == "/alpha/whoami"]
    assert authenticated and authenticated[0]["credential_matches"]
    if allowed:
        assert observed["exit"] is None and observed["catalog"]["status"] == "ready"
        assert observed["catalog"]["models"][0]["id"] == "gpt-5"
    else:
        assert observed["exit"] not in (None, 0)
        assert observed["catalog"].get("status") != "ready"


@pytest.mark.parametrize("finish", ["length", "toolUse", "unknown", "error", "aborted", None])
def test_pi_incomplete_length_result_cannot_be_published_as_success(finish):
    stream = "\n".join(
        json.dumps(event)
        for event in [
            {
                "type": "message_end",
                "message": {
                    "role": "assistant",
                    "stopReason": finish,
                    "content": [{"type": "text", "text": json.dumps({"decision": "candidate"})}],
                },
            },
            {"type": "agent_end"},
        ]
    )
    # Valid JSON does not negate the native finish reason's incomplete-turn signal.
    with pytest.raises(ValueError):
        parse_agent("pi", stream, "/unused")


@DOCKER
@pytest.mark.parametrize("operation", ["commit_triage", "commit_analysis"])
def test_pinned_pi_cli_runs_bounded_extension_and_returns_native_json_protocol(operation):
    profile = {
        "agent": "pi",
        "provider_id": "openai",
        "auth_type": "api_key",
        "model_id": "numen-fixture",
        "reasoning_effort": "high",
        "operation": operation,
    }
    args = [*agent_argv(profile), "--extension", "/opt/numen/pi-offline-fixture.ts"]
    extension = """
import {AssistantMessageEventStream} from '@earendil-works/pi-ai/compat';
import {writeFileSync} from 'node:fs';
export default function(api){
 let turns=0;
 api.on('before_agent_start',event=>{writeFileSync('/workspace/outputs/contract-trace.json',JSON.stringify({active:api.getActiveTools(),ambient:event.systemPrompt.includes('UNTRUSTED_AMBIENT_MARKER')}));});
 api.registerProvider('openai',{baseUrl:'https://offline.invalid',apiKey:'$OPENAI_API_KEY',api:'numen-offline-fixture',
 models:[{id:'numen-fixture',name:'Offline fixture',reasoning:true,input:['text'],cost:{input:0,output:0,cacheRead:0,cacheWrite:0},contextWindow:32000,maxTokens:2048}],
 streamSimple(model,context,options){
  const events=new AssistantMessageEventStream();const first=turns++===0;const writing=api.getActiveTools().includes('numen_write');
  const msg={role:'assistant',api:model.api,provider:model.provider,model:model.id,content:[],usage:{input:1,output:1,cacheRead:0,cacheWrite:0,totalTokens:2,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}},stopReason:first&&writing?'toolUse':'stop',timestamp:Date.now()};
  queueMicrotask(()=>{
   events.push({type:'start',partial:msg});
   if(first&&writing){msg.content.push({type:'toolCall',id:'fixture-write',name:'numen_write',arguments:{path:'outputs/report.md',content:'# Observed offline artifact'}});}
   else{msg.content.push({type:'text',text:JSON.stringify({provider:model.provider,requested_effort:options?.reasoning,credential_matches:options?.apiKey===process.env.OPENAI_API_KEY,turns})});}
   events.push({type:'done',reason:msg.stopReason,message:msg});events.end(msg);
  });return events;
 }});
}
"""
    script = f"""
import {{mkdir,writeFile,readFile}} from 'node:fs/promises';import {{spawnSync}} from 'node:child_process';
await mkdir('/workspace/inputs',{{recursive:true}});await mkdir('/workspace/outputs',{{recursive:true}});await mkdir(process.env.PI_CODING_AGENT_DIR,{{recursive:true}});
await writeFile('/workspace/AGENTS.md','UNTRUSTED_AMBIENT_MARKER');
const child=spawnSync({json.dumps(args[0])},{json.dumps(args[1:])},{{cwd:'/workspace',env:process.env,input:'Run the offline fixture and return JSON.',encoding:'utf8',timeout:15000}});
const trace=JSON.parse(await readFile('/workspace/outputs/contract-trace.json','utf8'));let artifact=null;try{{artifact=await readFile('/workspace/outputs/report.md','utf8')}}catch{{}}
console.log(JSON.stringify({{exit:child.status,stdout:child.stdout,stderr:child.stderr.slice(-1000),trace,artifact}}));
"""
    observed = image_script(
        script,
        files={"pi-offline-fixture.ts": extension.encode()},
        env={"OPENAI_API_KEY": "synthetic-pi-key-no-access"},
    )
    assert observed["exit"] == 0, observed["stderr"]
    parsed = parse_agent("pi", observed["stdout"], "/unused")
    assert parsed["provider"] == "openai"
    assert parsed["requested_effort"] == "high" and parsed["credential_matches"] is True
    assert observed["trace"]["ambient"] is False
    assert "bash" not in observed["trace"]["active"]
    if operation == "commit_triage":
        assert set(observed["trace"]["active"]) == {"numen_read", "numen_list"}
        assert observed["artifact"] is None and parsed["turns"] == 1
    else:
        assert set(observed["trace"]["active"]) == {
            "numen_read",
            "numen_list",
            "numen_write",
            "target_fetch",
        }
        assert observed["artifact"] == "# Observed offline artifact" and parsed["turns"] == 2


@DOCKER
@pytest.mark.parametrize(
    "model_id,effort,path",
    [
        ("deepseek/deepseek-v4-pro", "high", "/provider/v1/chat/completions"),
        ("claude-opus-4-7", "max", "/provider/v1/messages"),
    ],
)
def test_pinned_pi_cli_runs_commandcode_plugin_against_its_provider_api(model_id, effort, path):
    profile = {
        "agent": "pi",
        "provider_id": "commandcode",
        "auth_type": "api_key",
        "model_id": model_id,
        "reasoning_effort": effort,
        "operation": "commit_triage",
    }
    args = agent_argv(profile)
    # The pinned plugin honors its documented endpoint overrides; a loopback fake replaces the
    # Command Code API so the real CLI, plugin catalog and both provider transports run offline.
    script = f"""
import {{mkdir}} from 'node:fs/promises';import {{createServer}} from 'node:http';import {{spawn}} from 'node:child_process';
await mkdir('/workspace/inputs',{{recursive:true}});await mkdir('/workspace/outputs',{{recursive:true}});await mkdir(process.env.PI_CODING_AGENT_DIR,{{recursive:true}});
const answer=JSON.stringify({{decision:'candidate',reason:'offline Command Code fixture'}});const requests=[];
const sse=(res,events)=>{{res.writeHead(200,{{'content-type':'text/event-stream'}});for(const [name,data] of events)res.write((name?'event: '+name+'\\n':'')+'data: '+(typeof data==='string'?data:JSON.stringify(data))+'\\n\\n');res.end();}};
const server=createServer(async(req,res)=>{{
 const url=new URL(req.url,'http://fixture');
 if(req.method==='GET'&&url.pathname==='/provider/v1/models'){{res.writeHead(200,{{'content-type':'application/json'}});res.end(JSON.stringify({{object:'list',data:[
  {{id:'deepseek/deepseek-v4-pro',name:'DeepSeek V4 Pro',context_length:128000}},{{id:'claude-opus-4-7',name:'Claude Opus 4.7',context_length:200000}}]}}));return;}}
 let bytes='';for await(const chunk of req)bytes+=chunk;const body=JSON.parse(bytes);
 requests.push({{path:url.pathname,credential_matches:(req.headers.authorization||req.headers['x-api-key']||'').endsWith(process.env.COMMAND_CODE_API_KEY),
  model:body.model,reasoning_effort:body.reasoning_effort??null,output_effort:body.output_config?.effort??null,
  tools:(body.tools||[]).map(t=>t.function?.name??t.name).sort()}});
 const usage={{prompt_tokens:1,completion_tokens:1,total_tokens:2}};
 if(url.pathname==='/provider/v1/chat/completions')return sse(res,[
  [null,{{id:'c',object:'chat.completion.chunk',created:0,model:body.model,choices:[{{index:0,delta:{{role:'assistant',content:answer}},finish_reason:null}}]}}],
  [null,{{id:'c',object:'chat.completion.chunk',created:0,model:body.model,choices:[{{index:0,delta:{{}},finish_reason:'stop'}}],usage}}],[null,'[DONE]']]);
 if(url.pathname==='/provider/v1/messages')return sse(res,[
  ['message_start',{{type:'message_start',message:{{id:'m',type:'message',role:'assistant',model:body.model,content:[],stop_reason:null,stop_sequence:null,usage:{{input_tokens:1,output_tokens:0}}}}}}],
  ['content_block_start',{{type:'content_block_start',index:0,content_block:{{type:'text',text:''}}}}],
  ['content_block_delta',{{type:'content_block_delta',index:0,delta:{{type:'text_delta',text:answer}}}}],
  ['content_block_stop',{{type:'content_block_stop',index:0}}],
  ['message_delta',{{type:'message_delta',delta:{{stop_reason:'end_turn',stop_sequence:null}},usage:{{output_tokens:1}}}}],
  ['message_stop',{{type:'message_stop'}}]]);
 res.writeHead(404);res.end();
}});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const base='http://127.0.0.1:'+server.address().port+'/provider/v1';
const child=spawn({json.dumps(args[0])},{json.dumps(args[1:])},{{cwd:'/workspace',env:{{...process.env,COMMANDCODE_API_BASE:base,COMMANDCODE_MODELS_URL:base+'/models'}}}});
let stdout='',stderr='';child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.end('Triage the offline fixture and return JSON.');
const exit=await new Promise(resolve=>{{const timer=setTimeout(()=>child.kill('SIGKILL'),20000);child.on('close',code=>{{clearTimeout(timer);resolve(code);}});}});
server.close();console.log(JSON.stringify({{exit,stdout,stderr:stderr.slice(-1000),requests}}));
"""
    observed = image_script(script, env={"COMMAND_CODE_API_KEY": "synthetic-commandcode-key-no-access"})
    assert observed["exit"] == 0, observed["stderr"]
    assert parse_agent("pi", observed["stdout"], "/unused") == {
        "decision": "candidate", "reason": "offline Command Code fixture"
    }
    assert "synthetic-commandcode-key-no-access" not in observed["stdout"]
    request = observed["requests"][0]
    assert request["path"] == path and request["credential_matches"]
    assert request["model"] == model_id
    assert effort in (request["reasoning_effort"], request["output_effort"])
    assert request["tools"] == ["numen_list", "numen_read"]


@DOCKER
@pytest.mark.parametrize("valid", [True, False])
def test_pinned_commandcode_login_uses_plugin_flow_and_stores_only_validated_key(valid):
    key = "user_synthetic-valid-key" if valid else "user_synthetic-rejected-key"
    script = f"""
import {{mkdir,readFile}} from 'node:fs/promises';import {{Readable}} from 'node:stream';
await mkdir('/workspace',{{recursive:true}});await mkdir(process.env.PI_CODING_AGENT_DIR,{{recursive:true}});
const whoami=[];
globalThis.fetch=async(input,init={{}})=>{{const url=new URL(String(input?.url??input));
 if(url.pathname==='/provider/v1/models')return new Response(JSON.stringify({{object:'list',data:[{{id:'cc-model',name:'CC',context_length:128000}}]}}),{{status:200,headers:{{'content-type':'application/json'}}}});
 if(url.pathname==='/alpha/whoami'){{const ok=new Headers(init.headers).get('authorization')==='Bearer user_synthetic-valid-key';whoami.push({{host:url.host,ok}});
  return new Response(JSON.stringify(ok?{{user:{{userName:'fixture'}}}}:{{}}),{{status:ok?200:401,headers:{{'content-type':'application/json'}}}});}}
 throw new Error('Unexpected endpoint in offline fixture');}};
Object.defineProperty(process,'stdin',{{value:Readable.from([{json.dumps(key)}+'\\n'])}});
const printed=[];const log=console.log;console.log=value=>printed.push(String(value));
let exit=null,error=null;process.exit=code=>{{exit=code;throw new Error('login exited')}};
try{{await import('/opt/numen/pi-commandcode-login.mjs')}}catch(e){{if(exit===null)error=e.message}}
let auth=null;try{{auth=JSON.parse(await readFile(process.env.PI_CODING_AGENT_DIR+'/auth.json','utf8'))}}catch{{}}
log(JSON.stringify({{printed,exit,error,whoami,auth}}));
"""
    observed = image_script(script)
    assert len(observed["printed"]) == 1 and key not in observed["printed"][0]
    assert observed["printed"][0].startswith(
        "https://commandcode.ai/studio/auth/cli?callback=http%3A%2F%2Flocalhost%3A5959%2Fcallback&state="
    )
    assert observed["whoami"] == [{"host": "api.commandcode.ai", "ok": valid}]
    if valid:
        assert observed["exit"] == 0 and observed["error"] is None
        entry = observed["auth"]["commandcode"]
        assert entry["type"] == "oauth" and entry["access"] == entry["refresh"] == key
    else:
        assert observed["exit"] is None and "Invalid Command Code API key" in observed["error"]
        assert "commandcode" not in (observed["auth"] or {})


def test_pi_normal_stop_has_positive_completion_proof():
    stream = "\n".join(
        json.dumps(event)
        for event in [
            {
                "type": "message_end",
                "message": {
                    "role": "assistant",
                    "stopReason": "stop",
                    "content": [{"type": "text", "text": json.dumps({"summary": "complete"})}],
                },
            },
            {"type": "agent_end"},
        ]
    )
    assert parse_agent("pi", stream, "/unused") == {"summary": "complete"}


@DOCKER
def test_pi_target_tool_uses_only_the_capability_gateway_and_read_methods():
    script = """
import register from '/opt/numen/pi-tools.ts';import{mkdir}from'node:fs/promises';import{createServer}from'node:http';import{validateToolCall}from'@earendil-works/pi-ai/compat';
await mkdir('/workspace/outputs',{recursive:true});let tools=[];register({registerTool:t=>tools.push(t)});const tool=tools.find(t=>t.name==='target_fetch');const calls=[];
const server=createServer(async(req,res)=>{let bytes='';for await(const chunk of req)bytes+=chunk;const input=JSON.parse(bytes);calls.push({path:req.url,transport:req.method,token_matches:req.headers['x-fetch-token']==='fixture-capability',method:input.method});
if(input.url!=='https://registered.example/version'){res.writeHead(403);res.end('denied');return;}res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({status:200,url:input.url,content_base64:Buffer.from('version=1').toString('base64'),sha256:'fixture-hash'}));});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));process.env.NUMEN_FETCH_URL='http://127.0.0.1:'+server.address().port+'/fetch';process.env.NUMEN_FETCH_TOKEN='fixture-capability';
async function call(args){return tool.execute('1',validateToolCall(tools,{id:'1',name:tool.name,arguments:args}));}
let result,head,scope_denied=false,method_denied=false,missing_denied=false;
try{result=JSON.parse((await call({url:'https://registered.example/version'})).content[0].text);head=await call({url:'https://registered.example/version',method:'HEAD'});try{await call({url:'https://unregistered.example/'});}catch{scope_denied=true;}try{await call({url:'https://registered.example/version',method:'POST'});}catch{method_denied=true;}delete process.env.NUMEN_FETCH_URL;try{await call({url:'https://registered.example/version'});}catch{missing_denied=true;}}
finally{await new Promise(resolve=>server.close(resolve));}
console.log(JSON.stringify({result,calls,scope_denied,method_denied,missing_denied}));
"""
    observed = image_script(script)
    assert observed["scope_denied"] and observed["method_denied"] and observed["missing_denied"]
    assert observed["result"]["status"] == 200
    assert len(observed["calls"]) == 3
    assert all(
        call["transport"] == "POST" and call["path"] == "/fetch" and call["token_matches"]
        for call in observed["calls"]
    )
    assert [call["method"] for call in observed["calls"]] == ["GET", "HEAD", "GET"]


@DOCKER
def test_pi_tool_file_limits_reject_overlimit_reads_and_writes():
    script = """
import register from '/opt/numen/pi-tools.ts';import{mkdir,writeFile,stat}from'node:fs/promises';
await mkdir('/workspace/inputs',{recursive:true});await mkdir('/workspace/outputs',{recursive:true});await writeFile('/workspace/inputs/large.txt',Buffer.alloc(1048577));
let tools=[];register({registerTool:t=>tools.push(t)});let read_denied=false,write_denied=false,created=false;
try{await tools.find(t=>t.name==='numen_read').execute('1',{path:'inputs/large.txt'});}catch{read_denied=true;}
try{await tools.find(t=>t.name==='numen_write').execute('1',{path:'outputs/large.txt',content:'x'.repeat(1048577)});}catch{write_denied=true;}
try{await stat('/workspace/outputs/large.txt');created=true;}catch{}console.log(JSON.stringify({read_denied,write_denied,created}));
"""
    assert image_script(script) == {"read_denied": True, "write_denied": True, "created": False}


def pi_line(event):
    return json.dumps(event, separators=(",", ":")) + "\n"  # Pi writes compact JSON.


def test_pi_event_filter_skips_repeated_tool_output_and_survives_chunking(tmp_path, monkeypatch):
    blob = "x" * (1024 * 1024)
    final = {"type": "message_end", "message": {
        "content": [{"type": "text", "text": json.dumps({"ok": True})}], "role": "assistant", "stopReason": "stop"}}
    reads = [pi_line({"type": "tool_execution_end", "result": blob}),
             pi_line({"type": "message_end", "message": {"role": "toolResult", "content": blob}}),
             pi_line({"type": "turn_end", "toolResults": [blob]})]
    stream = "".join(reads * 10 + [pi_line(final), pi_line({"type": "agent_end", "messages": [blob] * 10})]).encode()
    lines, peak = workload.EventLines(pi_event), 0
    for start in range(0, len(stream), 7919):  # Odd chunks split prefixes and lines.
        lines.feed(stream[start:start + 7919])
        peak = max(peak, lines.size)
    assert parse_agent("pi", lines.finish().decode(), None) == {"ok": True} and peak < 64 * 1024
    # About 40 MiB of events: over the 16 MiB bound unless repeated tool output is skipped.
    monkeypatch.setattr(workload, "WORK", tmp_path)
    (tmp_path / "events").write_bytes(stream)
    argv = [workload.sys.executable, "-c", "import sys;sys.stdout.buffer.write(open('events','rb').read())"]
    code, out, _ = workload.run_process(argv, {}, events=pi_event)
    assert code == 0 and parse_agent("pi", out, None) == {"ok": True}
    with pytest.raises(ValueError, match="output exceeded byte limit"):
        workload.run_process(argv, {})


@DOCKER
def test_pinned_pi_long_reading_run_stays_within_the_output_bound():
    extension = """
import {AssistantMessageEventStream} from '@earendil-works/pi-ai/compat';
export default function(api){
 let turns=0;
 api.registerProvider('openai',{baseUrl:'https://offline.invalid',apiKey:'$OPENAI_API_KEY',api:'numen-offline-fixture',
 models:[{id:'numen-fixture',name:'Offline fixture',reasoning:true,input:['text'],cost:{input:0,output:0,cacheRead:0,cacheWrite:0},contextWindow:100000000,maxTokens:2048}],
 streamSimple(model,context,options){
  const events=new AssistantMessageEventStream();const reading=turns++<20;
  const msg={content:[],role:'assistant',api:model.api,provider:model.provider,model:model.id,usage:{input:1,output:1,cacheRead:0,cacheWrite:0,totalTokens:2,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}},stopReason:reading?'toolUse':'stop',timestamp:Date.now()};
  queueMicrotask(()=>{
   events.push({type:'start',partial:msg});
   if(reading){msg.content.push({type:'toolCall',id:'read-'+turns,name:'numen_read',arguments:{path:'inputs/source/big.js'}});}
   else{msg.content.push({type:'text',text:JSON.stringify({reads:turns-1})});}
   events.push({type:'done',reason:msg.stopReason,message:msg});events.end(msg);
  });return events;
 }});
}
"""
    runner = """
import json,os,sys
sys.path.insert(0,'/opt/runner')
from numen_runner import workload
from numen_runner.adapters import agent_argv,agent_events,parse_agent
profile={'agent':'pi','provider_id':'openai','auth_type':'api_key','model_id':'numen-fixture','reasoning_effort':'high','operation':'version_recipe'}
argv=agent_argv(profile)+['--extension','/opt/numen/pi-offline-fixture.ts']
code,out,_=workload.run_process(argv,dict(os.environ),'Read repeatedly, then answer.',None,events=agent_events('pi'))
print(json.dumps({'code':code,'kept':len(out),'result':parse_agent('pi',out,None)}))
"""
    script = f"""
import {{mkdir,writeFile}} from 'node:fs/promises';import {{spawnSync}} from 'node:child_process';
await mkdir('/workspace/inputs/source',{{recursive:true}});await mkdir('/workspace/outputs',{{recursive:true}});await mkdir(process.env.PI_CODING_AGENT_DIR,{{recursive:true}});
await writeFile('/workspace/inputs/source/big.js','x'.repeat(900*1024));
const child=spawnSync('python',['-c',{json.dumps(runner)}],{{cwd:'/workspace',env:process.env,encoding:'utf8',timeout:25000}});
console.log(child.stdout.trim().split('\\n').pop()||JSON.stringify({{stderr:child.stderr.slice(-1500)}}));
"""
    observed = image_script(script, files={"pi-offline-fixture.ts": extension.encode()},
                            env={"OPENAI_API_KEY": "synthetic-pi-key-no-access"})
    # Twenty 900 KB reads put about 90 MB of events on Pi's stdout, far over the 16 MiB bound.
    assert observed.get("code") == 0, observed
    assert observed["result"] == {"reads": 20} and observed["kept"] < 64 * 1024


def pi_final(text):
    message = {"role": "assistant", "stopReason": "stop", "content": [{"type": "text", "text": text}]}
    return pi_line({"type": "message_end", "message": message}) + pi_line({"type": "agent_end"})


def test_pi_malformed_final_answer_gets_one_bounded_restatement(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(workload, "WORK", tmp_path)
    schema = {"type": "object", "required": ["metadata"], "additionalProperties": False,
              "properties": {"metadata": {"type": "object"}}}
    calls = []

    def run(argv, env, data=None, timeout=1800, max_bytes=0, events=None):
        calls.append((argv, data))
        return 0, pi_final('{"metadata": {"files": ["determine_version.py"]}}'), ""

    monkeypatch.setattr(workload, "run_process", run)
    profile = {"agent": "pi", "provider_id": "deepseek", "model_id": "deepseek/model"}
    prose = "Recipe written to outputs/determine_version.py with fixtures."
    assert workload.agent_result(profile, {}, pi_final(prose), schema, None) == {
        "metadata": {"files": ["determine_version.py"]}}
    (argv, prompt), = calls
    assert "--no-tools" in argv and prose in prompt and '"result_repair"' in capsys.readouterr().out
    # A schema mismatch is restated too; an empty answer has nothing to restate.
    assert workload.agent_result(profile, {}, pi_final('{"status": "ok"}'), schema, None)["metadata"]
    with pytest.raises(ValueError, match="not valid JSON"):
        workload.agent_result(profile, {}, pi_final(""), schema, None)
    assert len(calls) == 2


@DOCKER
def test_pinned_pi_prose_final_answer_is_restated_as_the_result():
    extension = """
import {AssistantMessageEventStream} from '@earendil-works/pi-ai/compat';
export default function(api){
 api.registerProvider('openai',{baseUrl:'https://offline.invalid',apiKey:'$OPENAI_API_KEY',api:'numen-offline-fixture',
 models:[{id:'numen-fixture',name:'Offline fixture',reasoning:true,input:['text'],cost:{input:0,output:0,cacheRead:0,cacheWrite:0},contextWindow:32000,maxTokens:2048}],
 streamSimple(model,context,options){
  const events=new AssistantMessageEventStream();
  const asked=JSON.stringify(context.messages).includes('Your previous final answer');
  const msg={role:'assistant',api:model.api,provider:model.provider,model:model.id,content:[],usage:{input:1,output:1,cacheRead:0,cacheWrite:0,totalTokens:2,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}},stopReason:'stop',timestamp:Date.now()};
  queueMicrotask(()=>{
   events.push({type:'start',partial:msg});
   msg.content.push({type:'text',text:asked?JSON.stringify({metadata:{restated:true,tools:api.getActiveTools().length}}):'The recipe files are written.'});
   events.push({type:'done',reason:'stop',message:msg});events.end(msg);
  });return events;
 }});
}
"""
    runner = """
import json,os,sys
sys.path.insert(0,'/opt/runner')
from numen_runner import workload
from numen_runner.adapters import agent_argv,agent_events,pi_repair_argv
fixture=['--extension','/opt/numen/pi-offline-fixture.ts']
workload.pi_repair_argv=lambda p:pi_repair_argv(p)+fixture
profile={'agent':'pi','provider_id':'openai','auth_type':'api_key','model_id':'numen-fixture','reasoning_effort':'high','operation':'version_recipe'}
schema={'type':'object','required':['metadata'],'additionalProperties':False,'properties':{'metadata':{'type':'object'}}}
code,out,_=workload.run_process(agent_argv(profile)+fixture,dict(os.environ),'Write the recipe.',None,events=agent_events('pi'))
print(json.dumps({'code':code,'result':workload.agent_result(profile,dict(os.environ),out,schema,None)}))
"""
    script = f"""
import {{mkdir}} from 'node:fs/promises';import {{spawnSync}} from 'node:child_process';
await mkdir('/workspace/inputs',{{recursive:true}});await mkdir('/workspace/outputs',{{recursive:true}});await mkdir(process.env.PI_CODING_AGENT_DIR,{{recursive:true}});
const child=spawnSync('python',['-c',{json.dumps(runner)}],{{cwd:'/workspace',env:process.env,encoding:'utf8',timeout:25000}});
console.log(child.stdout.trim().split('\\n').pop()||JSON.stringify({{stderr:child.stderr.slice(-1500)}}));
"""
    observed = image_script(script, files={"pi-offline-fixture.ts": extension.encode()},
                            env={"OPENAI_API_KEY": "synthetic-pi-key-no-access"})
    assert observed.get("code") == 0, observed
    assert observed["result"] == {"metadata": {"restated": True, "tools": 0}}
