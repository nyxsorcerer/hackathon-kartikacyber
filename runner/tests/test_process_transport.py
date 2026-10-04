"""Real subprocess-pipe proof; the fixture never contacts a provider."""
import os
import signal
import subprocess
import sys
import threading

from numen_runner import workload


def test_native_process_drains_output_while_submitting_a_large_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(workload, "WORK", tmp_path)
    processes = []
    popen = subprocess.Popen

    def tracked_process(*args, **kwargs):
        process = popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(workload.subprocess, "Popen", tracked_process)
    result, errors = [], []
    prompt = "p" * 262144
    child = (
        "import sys; "
        "sys.stdout.buffer.write(b'o'*131072); sys.stdout.flush(); "
        "data=sys.stdin.buffer.read(); "
        "sys.stderr.write('received='+str(len(data)))"
    )

    def execute():
        try:
            result.append(workload.run_process([sys.executable, "-c", child], os.environ.copy(), prompt, timeout=3))
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=execute)
    thread.start()
    try:
        thread.join(timeout=3)
        assert not thread.is_alive(), "CLI input/output backpressure prevented completion"
        assert not errors
        code, stdout, stderr = result[0]
        assert code == 0 and stdout == "o" * 131072 and stderr == "received=262144"
    finally:
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
        thread.join(timeout=3)
