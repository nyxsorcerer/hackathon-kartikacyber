from fastapi.testclient import TestClient
from numen_runner.broker import create_app

class OfflineEngine:
    def ping(self):
        raise RuntimeError("offline")
    def cleanup(self, run_id):
        pass

def test_auth_rejects_missing_and_wrong_token(tmp_path):
    app = create_app("test-token", tmp_path, engine=OfflineEngine(), execute=False)
    with TestClient(app) as client:
        assert client.get("/internal/runs/missing").status_code == 401
        assert client.post("/internal/runs", headers={"X-Broker-Token": "wrong"}, json={}).status_code == 401

def test_submission_idempotency_and_cancel_without_execution(tmp_path):
    app = create_app("test-token", tmp_path, engine=OfflineEngine(), execute=False)
    with TestClient(app) as client:
        headers = {"X-Broker-Token": "test-token"}
        body = {"attempt_token": "attempt", "kind": "probe", "inputs": []}
        first = client.post("/internal/runs", headers=headers, json=body).json()
        assert client.post("/internal/runs", headers=headers, json=body).json()["run_id"] == first["run_id"]
        assert client.post(f"/internal/runs/{first['run_id']}/cancel", headers=headers).json()["status"] == "cancelled"
        assert "credential" not in client.get(f"/internal/runs/{first['run_id']}", headers=headers).text


def test_validation_errors_never_echo_secret_fields(tmp_path):
    app=create_app("test-token",tmp_path,engine=OfflineEngine(),execute=False)
    with TestClient(app) as client:
        response=client.post('/internal/runs',headers={"X-Broker-Token":"test-token"},json={"attempt_token":"x","kind":"agent","profile":{"credential":{"api_key":"secret-must-never-return"},"unexpected_secret":"another-secret"}})
        assert response.status_code==422 and 'secret-must-never-return' not in response.text and 'another-secret' not in response.text


def test_a_rejected_run_names_the_rule_it_broke_without_its_values(tmp_path, caplog):
    app=create_app("test-token",tmp_path,engine=OfflineEngine(),execute=False)
    body={"attempt_token":"x","kind":"probe","inputs":[{"path":"a.txt","content_base64":"c2VjcmV0LXZhbHVl"}],
          "limits":{"timeout_seconds":"secret-limit-value"}}
    with TestClient(app) as client:
        response=client.post('/internal/runs',headers={"X-Broker-Token":"test-token"},json=body)
    assert response.status_code==422
    message=response.json()["message"]
    assert message.startswith("Run payload failed execution contract validation: ") and "limits" in message
    assert "secret-limit-value" not in response.text and "c2VjcmV0LXZhbHVl" not in response.text
    assert "Rejected run payload" in caplog.text and "secret-limit-value" not in caplog.text


def test_native_credential_ingress_is_separate_deleted_and_not_persisted(tmp_path):
    app=create_app("test-token",tmp_path,engine=OfflineEngine(),execute=False)
    with TestClient(app) as client:
        headers={"X-Broker-Token":"test-token"}
        run=client.post('/internal/runs',headers=headers,json={"attempt_token":"x","kind":"probe"}).json()['run_id']
        import time
        app.state.store.credentials[run]=(time.monotonic()+60,{"auth_json":{"tokens":{"access_token":"private-token"}}})
        assert 'private-token' not in client.get('/internal/runs/'+run,headers=headers).text
        assert client.get('/internal/runs/'+run+'/credential',headers=headers).json()['credential']['auth_json']['tokens']['access_token']=='private-token'
        assert client.delete('/internal/runs/'+run+'/credential',headers=headers).status_code==204
        assert client.get('/internal/runs/'+run+'/credential',headers=headers).status_code==404
        assert 'private-token' not in (tmp_path/(run+'.json')).read_text()


def test_rotated_cache_survives_broker_output_validation_failure(tmp_path):
    import time
    class NativeEngine(OfflineEngine):
        def run(self,*_args):
            return {"result":{"unexpected":"invalid application output"},"outputs":[],"credential":{"auth_json":{"tokens":{"access_token":"rotated-private-value","refresh_token":"rotated-private-refresh"}}}}
    app=create_app("protected-test-token",tmp_path,engine=NativeEngine())
    headers={"X-Broker-Token":"protected-test-token"}
    body={"attempt_token":"native-bad-output","kind":"agent","profile":{"agent":"codex","auth_type":"native_oauth","operation":"audit_context","model_id":"m","credential":{"auth_json":{"tokens":{"access_token":"original-private-value","refresh_token":"original-private-refresh"}}}},"output_schema":{"type":"object","required":["required_field"]}}
    with TestClient(app) as client:
        run=client.post('/internal/runs',headers=headers,json=body).json()['run_id']
        for _ in range(100):
            response=client.get('/internal/runs/'+run,headers=headers)
            if response.json()['status']=='failed':
                break
            time.sleep(.01)
        state=response.json()
        assert state['status']=='failed' and state['credential_updated']
        assert 'rotated-private-value' not in response.text
        assert client.get('/internal/runs/'+run+'/credential',headers=headers).json()['credential']['auth_json']['tokens']['access_token']=='rotated-private-value'


def test_triage_reply_passes_through_without_the_triage_schema(tmp_path):
    import time
    replies=iter([{"reply":"Not JSON: application code judges this"}, {"decision":"unrelated"}])
    class TriageEngine(OfflineEngine):
        def run(self,*_args):
            return {"result":next(replies),"outputs":[]}
    app=create_app("protected-test-token",tmp_path,engine=TriageEngine())
    headers={"X-Broker-Token":"protected-test-token"}
    schema={"type":"object","required":["decision"],"additionalProperties":False,"properties":{"decision":{"type":"string"}}}
    profile={"agent":"pi","provider_id":"deepseek","operation":"commit_triage","model_id":"m","credential":{"api_key":"k"}}
    with TestClient(app) as client:
        states=[]
        for token in ("triage-reply","triage-object"):
            run=client.post('/internal/runs',headers=headers,json={"attempt_token":token,"kind":"agent","profile":profile,"output_schema":schema}).json()['run_id']
            for _ in range(100):
                state=client.get('/internal/runs/'+run,headers=headers).json()
                if state['status'] in {'succeeded','failed'}:
                    break
                time.sleep(.01)
            states.append(state)
    assert (states[0]['status'],states[0]['result'])==('succeeded',{"reply":"Not JSON: application code judges this"})
    assert states[1]['status']=='failed'  # Anything but {reply} is a broken workload, even if it fits the schema.


LOGIN_RUN = {"attempt_token":"login","kind":"account_login","profile":{"agent":"claude","provider_id":"claude","auth_type":"native_oauth"}}


def test_login_input_is_accepted_only_for_running_login_and_never_persisted(tmp_path):
    app=create_app("test-token",tmp_path,engine=OfflineEngine(),execute=False)
    headers={"X-Broker-Token":"test-token"}
    code={"code":"private-authorization-code#state"}
    with TestClient(app) as client:
        assert client.post('/internal/runs/missing/login-input',json=code).status_code==401
        run=client.post('/internal/runs',headers=headers,json=LOGIN_RUN).json()['run_id']
        assert client.post(f'/internal/runs/{run}/login-input',headers=headers,json=code).status_code==409
        app.state.store.change(run,status="running")
        rejected=client.post(f'/internal/runs/{run}/login-input',headers=headers,json={"code":"private bad\ncode"})
        assert rejected.status_code==422 and 'private bad' not in rejected.text
        assert client.post(f'/internal/runs/{run}/login-input',headers=headers,json=code).status_code==202
        assert app.state.store.login_inputs[run]==code["code"]
        assert 'private-authorization-code' not in client.get('/internal/runs/'+run,headers=headers).text
        assert 'private-authorization-code' not in (tmp_path/(run+'.json')).read_text()
        probe=client.post('/internal/runs',headers=headers,json={"attempt_token":"probe","kind":"probe"}).json()['run_id']
        app.state.store.change(probe,status="running")
        assert client.post(f'/internal/runs/{probe}/login-input',headers=headers,json=code).status_code==409


def test_login_engine_receives_operator_input_once(tmp_path):
    import threading
    import time
    received=[]
    waiting=threading.Event()
    class LoginEngine(OfflineEngine):
        def ping(self):
            return True
        def run(self,run_id,request,cancelled,event,login_input=None):
            waiting.set()
            deadline=time.monotonic()+5
            while time.monotonic()<deadline and not received:
                code=login_input()
                if code:
                    received.append(code)
                time.sleep(.01)
            assert login_input() is None
            return {"result":{"status":"ready","auth_type":"native_oauth"},"outputs":[],
                    "credential":{"credentials_json":{"claudeAiOauth":{"accessToken":"private-access"}}}}
    app=create_app("protected-test-token",tmp_path,engine=LoginEngine())
    headers={"X-Broker-Token":"protected-test-token"}
    with TestClient(app) as client:
        run=client.post('/internal/runs',headers=headers,json=LOGIN_RUN).json()['run_id']
        assert waiting.wait(5)
        assert client.post(f'/internal/runs/{run}/login-input',headers=headers,json={"code":"private-authorization-code#state"}).status_code==202
        for _ in range(500):
            state=client.get('/internal/runs/'+run,headers=headers).json()
            if state['status']=='succeeded':
                break
            time.sleep(.01)
        assert state['status']=='succeeded' and state['credential_updated']
        assert received==["private-authorization-code#state"]
        assert run not in app.state.store.login_inputs


def test_runs_execute_concurrently_up_to_the_configured_limit(tmp_path):
    import threading
    import time
    barrier = threading.Barrier(2, timeout=10)

    class ParallelEngine(OfflineEngine):
        def run(self, *_args, **_kwargs):
            barrier.wait()  # Both runs must be inside the Engine at once.
            return {"result": {}, "outputs": []}

    app = create_app("concurrency-test-token", tmp_path, engine=ParallelEngine(), concurrency=2)
    headers = {"X-Broker-Token": "concurrency-test-token"}
    with TestClient(app) as client:
        runs = [client.post("/internal/runs", headers=headers, json={"attempt_token": f"parallel-{i}", "kind": "probe"}).json()["run_id"]
                for i in range(2)]
        for _ in range(200):
            states = [client.get("/internal/runs/" + run, headers=headers).json()["status"] for run in runs]
            if all(state in {"succeeded", "failed", "cancelled"} for state in states):
                break
            time.sleep(.05)
    assert states == ["succeeded", "succeeded"]
