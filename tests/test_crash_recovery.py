"""End-to-end crash recovery: start a real run_web.py subprocess, submit a run, kill the process
outright (SIGKILL — no graceful shutdown, no chance to update any state), start a fresh subprocess
pointed at the same database file, and confirm it finds and can recover the interrupted run."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from _common import ROOT

RUN_BODY = {"defenses": ["baseline", "defensive_prompt", "classifier", "tool_validator"],
           "attack_modes": ["static", "adaptive_demo"], "attack_budget": 400,
           "seeds": [1, 2, 3, 4, 5], "scenario_ids": None}


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def _post(url, body, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class CrashRecoveryEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "runs.db")
        self.env = dict(os.environ, RTBT_RUNS_DB=self.db_path)
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            try:
                p.kill()
                p.wait(timeout=5)
            except Exception:
                pass
            if p.stdout:
                p.stdout.close()
        self.tmp.cleanup()

    def _start_server(self):
        port = _free_port()
        proc = subprocess.Popen([sys.executable, "run_web.py", "--port", str(port)], cwd=str(ROOT), env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.procs.append(proc)
        base = f"http://127.0.0.1:{port}"
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                _get(f"{base}/api/suite", timeout=2)
                return proc, base
            except Exception:
                time.sleep(0.2)
        raise AssertionError("server never came up")

    def test_a_killed_server_leaves_an_interrupted_run_that_a_fresh_server_can_see_and_recover(self):
        proc1, base1 = self._start_server()
        status, data = _post(f"{base1}/api/experiments", RUN_BODY)
        self.assertEqual(status, 202, data)
        run_id = data["run_id"]

        # Let a little real work happen (so at least one campaign likely completes and is
        # persisted) but not the whole run — a big budget keeps this run alive long enough.
        time.sleep(0.8)

        proc1.kill()  # SIGKILL: no graceful shutdown, no atexit, nothing — a genuine crash
        proc1.wait(timeout=10)

        # A fresh process, same database file — this is "constructing a new runner" against
        # whatever was persisted before the crash.
        proc2, base2 = self._start_server()
        try:
            interrupted = _get(f"{base2}/api/experiments/interrupted")["runs"]
            self.assertEqual([r["run_id"] for r in interrupted], [run_id])
            entry = interrupted[0]
            self.assertEqual(entry["status"], "interrupted")
            self.assertTrue(any(e["decision"] == "marked_interrupted_on_startup" for e in entry["recovery_log"]))

            # abandon: no new run, permanently logged, cannot be recovered again afterward
            status, data = _post(f"{base2}/api/experiments/{run_id}/recover", {"decision": "abandon"})
            self.assertEqual(status, 200, data)
            still_interrupted = _get(f"{base2}/api/experiments/interrupted")["runs"]
            self.assertEqual(still_interrupted, [])  # no longer listed as needing a decision
            status, data = _post(f"{base2}/api/experiments/{run_id}/recover", {"decision": "resume"})
            self.assertEqual(status, 409, data)  # already decided; not re-offered
        finally:
            proc2.kill()
            proc2.wait(timeout=10)

    def test_a_normally_completed_run_never_shows_up_as_interrupted(self):
        proc1, base1 = self._start_server()
        small_budget_body = {**RUN_BODY, "attack_budget": 3}  # small enough to finish fast
        status, data = _post(f"{base1}/api/experiments", small_budget_body)
        run_id = data["run_id"]

        deadline = time.time() + 20
        st = {"status": "running"}
        while time.time() < deadline and st["status"] == "running":
            st = _get(f"{base1}/api/experiments/{run_id}/status")
            time.sleep(0.2)
        self.assertEqual(st["status"], "complete")
        proc1.kill()
        proc1.wait(timeout=10)

        proc2, base2 = self._start_server()
        try:
            self.assertEqual(_get(f"{base2}/api/experiments/interrupted")["runs"], [])
        finally:
            proc2.kill()
            proc2.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
