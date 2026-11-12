"""Claude contract proofs; fixtures never make provider/login/inference calls."""
import json
import os
import time
from pathlib import Path

import httpx
import pytest

from numen_runner import workload
from numen_runner.adapters import agent_argv, parse_agent

MODEL_API_DOC = 'https://platform.claude.com/docs/en/api/models/list'
CLI_DOC = 'https://code.claude.com/docs/en/cli-reference'
PINNED_CLI_EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max']
HTTPX_CLIENT = httpx.Client


def profile(auth_type='api_key', operation='commit_analysis'):
    return {'agent':'claude', 'provider_id':'claude', 'auth_type':auth_type,
            'operation':operation, 'model_id':'claude-opus-5', 'reasoning_effort':None,
            'credential':{'api_key':'synthetic-api-not-real'} if auth_type=='api_key' else {
                'credentials_json':{'claudeAiOauth':{'accessToken':'synthetic-oauth-not-real',
                    'refreshToken':'synthetic-refresh-not-real','expiresAt':int(time.time()*1000)+3600000,
                    'scopes':['user:inference','user:profile']}}}}


def mock_model_api(monkeypatch, handler):
    original_client=HTTPX_CLIENT
    def client(**options):
        options.update(transport=httpx.MockTransport(handler),trust_env=False)
        return original_client(**options)
    monkeypatch.setattr(workload.httpx,'Client',client)


def test_claude_catalog_uses_documented_effort_booleans_and_only_pinned_cli_levels(monkeypatch):
    # Official API schema: capability.effort.<level>.supported, not supported_levels.
    model={'id':'claude-opus-5','display_name':'Claude Opus 5','capabilities':{'effort':{
        'supported':True,'low':{'supported':True},'medium':{'supported':False},
        'high':{'supported':True},'xhigh':{'supported':False},'max':{'supported':True},
        'future_unknown_level':{'supported':True}}}}
    mock_model_api(monkeypatch,lambda _request:httpx.Response(200,json={'data':[model],'has_more':False}))
    result=workload.capabilities(profile(),{'ANTHROPIC_API_KEY':'synthetic-api-not-real'},20)
    assert result['status']=='ready' and result['usage'] is None
    assert result['models'][0]['reasoning_efforts']==['low','high','max']
    assert set(result['models'][0]['reasoning_efforts']).issubset(PINNED_CLI_EFFORTS)


def test_claude_nullable_capabilities_preserve_model_with_unknown_effort(monkeypatch):
    # capabilities:null is explicitly allowed by the model endpoint's ModelInfo schema.
    mock_model_api(monkeypatch,lambda _request:httpx.Response(200,json={'data':[
        {'id':'claude-legacy-fixture','display_name':'Legacy fixture','capabilities':None}],'has_more':False}))
    result=workload.capabilities(profile(),{'ANTHROPIC_API_KEY':'synthetic-api-not-real'},20)
    assert result['status']=='ready'
    assert result['models'][0]['reasoning_efforts']==[]
    assert result['models'][0]['default_effort'] is None


def test_claude_provider_catalog_follows_documented_after_id_pagination(monkeypatch):
    requests=[]
    def response(request):
        assert request.url.host=='api.anthropic.com' and request.method=='GET'
        requests.append(dict(request.url.params))
        if request.url.params.get('after_id')=='claude-page-one':
            return httpx.Response(200,json={'data':[{'id':'claude-page-two'}],'last_id':'claude-page-two','has_more':False})
        return httpx.Response(200,json={'data':[{'id':'claude-page-one'}],'last_id':'claude-page-one','has_more':True})
    mock_model_api(monkeypatch,response)
    models=workload.provider_catalog(profile(),{'ANTHROPIC_API_KEY':'synthetic-api-not-real'})
    assert [model['id'] for model in models]==['claude-page-one','claude-page-two']
    assert len(requests)==2 and requests[1]['after_id']=='claude-page-one'


def test_claude_auth_modes_cache_permissions_and_refresh_detection(tmp_path,monkeypatch):
    home=tmp_path/'private'
    env={'CLAUDE_CONFIG_DIR':str(home/'.claude')}
    native=profile('native_oauth')
    workload.setup_auth(native,env)
    cache_path=Path(env['CLAUDE_CONFIG_DIR'])/'.credentials.json'
    assert json.loads(cache_path.read_text())==native['credential']['credentials_json']
    assert cache_path.stat().st_mode&0o777==0o600
    assert cache_path.parent.stat().st_mode&0o777==0o700
    assert 'ANTHROPIC_API_KEY' not in env
    monkeypatch.setattr(workload,'PRIVATE',home)
    job={'kind':'capabilities','profile':native}
    assert workload.refreshed_credential(job) is None
    cache=json.loads(cache_path.read_text())
    cache['claudeAiOauth']['accessToken']='synthetic-rotated-not-real'
    cache_path.write_text(json.dumps(cache))
    assert workload.refreshed_credential(job)=={'credentials_json':cache}
    api_env={'CLAUDE_CONFIG_DIR':str(tmp_path/'api-only')}
    workload.setup_auth(profile(),api_env)
    assert api_env['ANTHROPIC_API_KEY']=='synthetic-api-not-real'
    assert not Path(api_env['CLAUDE_CONFIG_DIR']).exists()


def test_claude_api_and_native_argv_keep_bare_and_target_tool_contracts_separate(tmp_path):
    schema=tmp_path/'schema.json'
    schema.write_text(json.dumps(workload.NATIVE_SCHEMA))
    api=profile(operation='version_recipe')
    api['reasoning_effort']='high'
    args=agent_argv(api,str(schema))
    assert '--bare' in args and '--restricted' in args
    assert args[args.index('--effort')+1]=='high'
    assert args[args.index('--setting-sources')+1]==''
    assert args[args.index('--permission-prompts')+1]=='none'
    assert args[args.index('--tools')+1]=='Read,Grep,Glob,Write,Edit'
    assert 'mcp__numen_target__target_fetch' in args[args.index('--allowedTools')+1]
    assert set(json.loads(args[args.index('--mcp-config')+1])['mcpServers'])=={'numen_target'}
    assert '--strict-mcp-config' in args
    assert not any('dangerously' in value for value in args)
    native=agent_argv(profile('native_oauth'),str(schema))
    assert '--bare' not in native
    assert '--effort' not in native
    triage=agent_argv(profile(operation='commit_triage'),str(schema))
    assert triage[triage.index('--tools')+1]=='Read,Grep,Glob'


def test_claude_successful_structured_envelope_is_decoded_without_text_fallback():
    result={'category':'Insufficient context','confidence':{'basis':'fixture only'}}
    event={'type':'result','subtype':'success','is_error':False,
           'structured_output':{'result_json':json.dumps(result)},'result':'ignored text'}
    assert parse_agent('claude',json.dumps(event),None)==result


@pytest.mark.parametrize('event',[
    {'type':'result','subtype':'error_max_turns','is_error':True},
    {'type':'result','subtype':'success','result':'ordinary text without structured output'},
    {'type':'result','subtype':'success','structured_output':{'result_json':'not JSON'}},
])
def test_claude_failed_or_invalid_protocol_never_becomes_success(event):
    with pytest.raises((ValueError,KeyError,TypeError)):
        parse_agent('claude',json.dumps(event),None)


@pytest.mark.skipif(os.getenv('NUMEN_DOCKER_TESTS')!='1',reason='explicit credential-free Docker/native CLI proof')
def test_pinned_claude_initialization_accepts_native_flags_and_reports_effort_levels():
    import docker
    script='''import json,subprocess,os
args=['claude','--print','--input-format','stream-json','--output-format','stream-json','--verbose','--restricted','--setting-sources','','--strict-mcp-config','--mcp-config','{"mcpServers":{}}','--tools','Read,Grep,Glob,Write,Edit','--allowedTools','Read,Grep,Glob,Write,Edit','--permission-mode','dontAsk','--permission-prompts','none','--no-session-persistence']
data=json.dumps({'type':'control_request','request_id':'fixture-init','request':{'subtype':'initialize'}})+'\\n'
env={**os.environ,'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1'}
values=[]
for effort in ['low','medium','high','xhigh','max']:
 p=subprocess.run(args+['--effort',effort],input=data,capture_output=True,text=True,timeout=15,env=env)
 events=[json.loads(line)for line in p.stdout.splitlines()if line.startswith('{')]
 response=events[0]['response']
 assert p.returncode==0 and response['subtype']=='success'
 models=response['response']['models']
 native=next(model for model in models if model.get('supportsEffort'))
 values.append({'selected':effort,'levels':native['supportedEffortLevels'],'mode':response['response']['current_permission_mode'],'account':response['response']['account']})
print(json.dumps(values))
'''
    client=docker.from_env(timeout=60)
    output=client.containers.run('asset-monitor-claude:0.1.0',['python','-c',script],network_mode='none',user='10001:10001',read_only=True,
        cap_drop=['ALL'],security_opt=['no-new-privileges:true'],remove=True,working_dir='/workspace',mem_limit='768m',pids_limit=64,
        tmpfs={'/workspace':'rw,size=32m,uid=10001,gid=10001','/home/job':'rw,size=32m,uid=10001,gid=10001','/tmp':'rw,size=32m,uid=10001,gid=10001'})
    results=json.loads(output)
    assert len(results)==5
    assert all(value['selected'] in value['levels'] and value['mode']=='dontAsk' for value in results)
    assert all(value['account']['tokenSource']=='none' for value in results)


def test_claude_catalog_deduplicates_pages_and_rejects_repeated_cursor(monkeypatch):
    def pages(request):
        if request.url.params.get('after_id')=='page-one':
            return httpx.Response(200,json={'data':[{'id':'duplicate'},{'id':'second'}],'last_id':'second','has_more':False})
        return httpx.Response(200,json={'data':[{'id':'first'},{'id':'duplicate'}],'last_id':'page-one','has_more':True})
    mock_model_api(monkeypatch,pages)
    assert [m['id'] for m in workload.provider_catalog(profile(),{'ANTHROPIC_API_KEY':'synthetic'})]==['first','duplicate','second']
    mock_model_api(monkeypatch,lambda _r:httpx.Response(200,json={'data':[{'id':'duplicate'}],'last_id':'loop','has_more':True}))
    with pytest.raises(ValueError):
        workload.provider_catalog(profile(),{'ANTHROPIC_API_KEY':'synthetic'})


def test_claude_native_catalog_uses_post_cli_cache_and_never_api_key(monkeypatch,tmp_path):
    native=profile('native_oauth')
    env={'CLAUDE_CONFIG_DIR':str(tmp_path/'.claude')}
    workload.setup_auth(native,env)
    cache_path=Path(env['CLAUDE_CONFIG_DIR'])/'.credentials.json'
    calls=[]
    def cli(argv,_env,**_options):
        calls.append(argv)
        cache=json.loads(cache_path.read_text())
        cache['claudeAiOauth']['accessToken']='synthetic-post-cli-rotation'
        cache_path.write_text(json.dumps(cache))
        return 0,json.dumps({'loggedIn':True,'authMethod':'claude.ai'}),''
    def api(request):
        assert request.headers['authorization']=='Bearer synthetic-post-cli-rotation'
        assert 'x-api-key' not in request.headers
        assert request.headers['anthropic-beta']=='oauth-2025-04-20'
        return httpx.Response(200,json={'data':[{'id':'claude-native-fixture','capabilities':None}],'has_more':False})
    monkeypatch.setattr(workload,'run_process',cli)
    mock_model_api(monkeypatch,api)
    assert workload.capabilities(native,env,20)['models'][0]['id']=='claude-native-fixture'
    assert calls==[['claude','auth','status','--json']]


@pytest.mark.skipif(os.getenv('NUMEN_DOCKER_TESTS')!='1',reason='explicit credential-free native tool execution fixture')
def test_pinned_claude_restricted_tools_and_structured_result_with_loopback_provider():
    import docker
    script=r'''import json,os,subprocess,threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from numen_runner.adapters import agent_argv,parse_agent
from numen_runner.workload import NATIVE_SCHEMA
work=Path('/workspace');(work/'outputs').mkdir();(work/'inputs').mkdir();(work/'inputs/source-fixture.txt').write_text('public fixture')
private=Path('/home/job/private-fixture.txt');private.write_text('synthetic-private-read-must-be-denied')
(work/'schema.json').write_text(json.dumps(NATIVE_SCHEMA))
observed={'requests':0,'private_denied':False,'names':[],'write_result':None,'read_result':None,'discovery':None,'schemas':{}}
class H(BaseHTTPRequestHandler):
 def log_message(self,*_args):pass
 def do_GET(self):
  data={'id':'claude-opus-5','type':'model','display_name':'Fixture','created_at':'2026-01-01T00:00:00Z','capabilities':None,'max_input_tokens':200000,'max_tokens':8192}
  self.reply(data)
 def reply(self,data):
  raw=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def do_POST(self):
  body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
  if self.path.startswith('/v1/messages/count_tokens'):self.reply({'input_tokens':10});return
  observed['requests']+=1;n=observed['requests']
  tools=body.get('tools',[]);observed['names']=sorted(t.get('name','')for t in tools)
  observed['schemas']={t['name']:t.get('input_schema')for t in tools if t.get('name')in['Read','Edit']}
  if n>1:
   results=[b for m in body.get('messages',[])for b in (m.get('content',[])if isinstance(m.get('content'),list)else[])if b.get('type')=='tool_result']
   if results:
    last=results[-1]
    if n==2:observed['read_result']=last;observed['private_denied']=last.get('is_error') is True and 'synthetic-private-read-must-be-denied' not in json.dumps(last)
    if n==3:observed['discovery']=last
    if n==4:observed['write_result']=last
  structured=next((t.get('name')for t in tools if 'result_json' in t.get('input_schema',{}).get('properties',{})),None)
  if n==1:name,inputs='Read',{'file_path':'/home/job/private-fixture.txt'}
  elif n==2:name,inputs='Read',{'file_path':'/workspace/inputs'}
  elif n==3:name,inputs='Edit',{'file_path':'/workspace/outputs/report.md','old_string':'','new_string':'fixture native report'}
  elif n==4 and structured:name,inputs=structured,{'result_json':json.dumps({'category':'Insufficient context','evidence':'fixture only'})}
  else:name,inputs=None,None
  content={'type':'tool_use','id':'tool_fixture_'+str(n),'name':name,'input':inputs}if name else {'type':'text','text':json.dumps({'result_json':json.dumps({'category':'Insufficient context','evidence':'fixture only'})})}
  message={'id':'msg_fixture_'+str(n),'type':'message','role':'assistant','model':'claude-opus-5','content':[content],'stop_reason':'tool_use'if name else'end_turn','stop_sequence':None,'usage':{'input_tokens':10,'output_tokens':10}}
  if not body.get('stream'):self.reply(message);return
  events=[('message_start',{'type':'message_start','message':{**message,'content':[],'stop_reason':None}})]
  block={**content,'input':{}}if name else {**content,'text':''}
  events.append(('content_block_start',{'type':'content_block_start','index':0,'content_block':block}))
  delta={'type':'input_json_delta','partial_json':json.dumps(inputs)}if name else{'type':'text_delta','text':content['text']}
  events.extend([('content_block_delta',{'type':'content_block_delta','index':0,'delta':delta}),('content_block_stop',{'type':'content_block_stop','index':0}),('message_delta',{'type':'message_delta','delta':{'stop_reason':message['stop_reason'],'stop_sequence':None},'usage':{'output_tokens':10}}),('message_stop',{'type':'message_stop'})])
  raw=''.join('event: '+kind+'\ndata: '+json.dumps(value)+'\n\n'for kind,value in events).encode()
  self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
server=ThreadingHTTPServer(('127.0.0.1',0),H)
threading.Thread(target=server.serve_forever,daemon=True).start()
env={**os.environ,'ANTHROPIC_API_KEY':'sk-ant-synthetic-fixture-not-a-real-key','ANTHROPIC_BASE_URL':'http://127.0.0.1:'+str(server.server_port),'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC':'1','CLAUDE_CONFIG_DIR':'/home/job/.claude'}
args=agent_argv({'agent':'claude','provider_id':'claude','model_id':'claude-opus-5','auth_type':'api_key','operation':'commit_analysis','reasoning_effort':None})+['--max-turns','6']
p=subprocess.run(args,input='Execute the fixture tool calls and return structured output.',cwd=work,capture_output=True,text=True,timeout=25,env=env)
result=None
try:result=parse_agent('claude',p.stdout,None)
except Exception:pass
report=work/'outputs/report.md'
print(json.dumps({'exit':p.returncode,'private_denied':observed['private_denied'],'requests':observed['requests'],'report_written':report.exists()and report.read_text()=='fixture native report','result':result,'tools':observed['names'],'stderr_empty':not p.stderr,'report_exists':report.exists(),'report_text':report.read_text()if report.exists()else None,'write_result':observed['write_result'],'schemas':observed['schemas'],'read_result':observed['read_result'],'discovery':observed['discovery']}))
server.shutdown()
'''
    client=docker.from_env(timeout=45)
    output=client.containers.run('asset-monitor-claude:0.1.0',['python','-c',script],network_mode='none',user='10001:10001',read_only=True,
        cap_drop=['ALL'],security_opt=['no-new-privileges:true'],remove=True,working_dir='/workspace',mem_limit='768m',pids_limit=64,
        tmpfs={'/workspace':'rw,size=32m,uid=10001,gid=10001','/home/job':'rw,size=32m,uid=10001,gid=10001','/tmp':'rw,size=32m,uid=10001,gid=10001'})
    result=json.loads(output)
    assert result['exit']==0,result
    assert result['private_denied'] and result['report_written'],json.dumps(result)
    assert result['result']=={'category':'Insufficient context','evidence':'fixture only'},result
    assert 'source-fixture.txt' in json.dumps(result['discovery']),json.dumps(result)
    assert 'Bash' not in result['tools'] and 'WebFetch' not in result['tools']
