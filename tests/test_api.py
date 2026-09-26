from __future__ import annotations

import http.client
import importlib.util
import json
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

from _common import ROOT

spec = importlib.util.spec_from_file_location("run_web", ROOT / "run_web.py")
run_web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_web)

RUN = {"defenses": ["baseline", "classifier", "tool_validator"], "attack_modes": ["static", "adaptive_demo"],
       "attack_budget": 6, "seeds": [1, 2, 3], "scenario_ids": ["email-summary-exfil", "cal-schedule-sync"]}


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run_web.Handler.log_message = lambda *args, **kwargs: None  # keep test output readable
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), run_web.Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.run_id = cls.post("/api/experiments", RUN)[1]["run_id"]
        cls.wait_for(cls.run_id)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    @classmethod
    def request(cls, method, path, body=None, raw=False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(cls.base + path, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = resp.read()
                return resp.status, (payload if raw else json.loads(payload)), resp.headers
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            return exc.code, (payload if raw else json.loads(payload)), exc.headers

    @classmethod
    def get(cls, path, raw=False):
        return cls.request("GET", path, raw=raw)

    @classmethod
    def post(cls, path, body=None):
        status, data, _ = cls.request("POST", path, body if body is not None else {})
        return status, data

    @classmethod
    def wait_for(cls, run_id, timeout=60):
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = cls.get(f"/api/experiments/{run_id}/status")[1]
            if status["status"] != "running":
                return status
            time.sleep(0.1)
        raise AssertionError("run did not finish")

    def test_run_completes_and_reports_progress(self):
        status = self.get(f"/api/experiments/{self.run_id}/status")[1]
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["campaigns_total"], 2 * 2 * 3 * 3)
        self.assertEqual(status["campaigns_done"], status["campaigns_total"])

    def test_post_and_get_on_the_same_path_are_routed_by_method(self):
        """Regression: GET and POST /api/experiments once collided and POST always returned 404."""
        self.assertEqual(self.get("/api/experiments")[0], 200)
        self.assertIn(self.run_id, [r["run_id"] for r in self.get("/api/experiments")[1]])

    def test_event_stream_can_be_filtered_and_resumed(self):
        everything = self.get(f"/api/experiments/{self.run_id}/events?since=0")[1]
        rounds = self.get(f"/api/experiments/{self.run_id}/events?since=0&types=round,campaign_complete")[1]
        self.assertEqual({e["type"] for e in rounds["events"]}, {"round", "campaign_complete"})
        self.assertEqual(everything["next_since"], rounds["next_since"])
        self.assertLess(len(rounds["events"]), len(everything["events"]))
        tail = self.get(f"/api/experiments/{self.run_id}/events?since={everything['next_since']}")[1]
        self.assertEqual(tail["events"], [])

    def test_summary_carries_manifest_provenance_and_matched_budgets(self):
        s = self.get(f"/api/experiments/{self.run_id}/summary")[1]
        self.assertEqual(s["manifest"]["seeds"], [1, 2, 3])
        self.assertEqual(s["provenance"]["demonstration_warning"], "Demonstration data only. These results are not research evidence.")
        self.assertTrue(all(g["matched"] for g in s["matched_budget"]))
        self.assertEqual(len(s["campaigns"]), 36)
        self.assertIn("adaptation_curve", s["campaigns"][0]["metrics"])

    def test_stats_are_per_scenario_and_pooled_with_honest_intervals(self):
        st = self.get(f"/api/experiments/{self.run_id}/stats")[1]
        self.assertIn("campaign_average_asr", st["metrics"])
        row = next(r for r in st["per_scenario"] if r["scenario_id"] == "email-summary-exfil" and r["defense_id"] == "baseline")
        self.assertEqual(row["stats"]["campaign_average_asr"]["n"], 3)
        self.assertIsNotNone(row["stats"]["campaign_average_asr"]["ci_95_low"])
        self.assertTrue(st["static_vs_adaptive"])

    def test_campaign_detail_accepts_url_encoded_ids(self):
        """Campaign ids contain colons; the dashboard percent-encodes them."""
        cid = self.get(f"/api/experiments/{self.run_id}/summary")[1]["campaigns"][0]["campaign_id"]
        status, detail, _ = self.get(f"/api/experiments/{self.run_id}/campaigns/{urllib.parse.quote(cid, safe='')}")
        self.assertEqual(status, 200)
        self.assertEqual(detail["campaign_id"], cid)
        self.assertTrue(detail["rounds"][0]["oracle"]["oracle_code"])
        self.assertEqual(self.get(f"/api/experiments/{self.run_id}/campaigns/nope")[0], 404)

    def test_csv_export(self):
        status, body, headers = self.get(f"/api/experiments/{self.run_id}/comparison.csv", raw=True)
        self.assertEqual(status, 200)
        self.assertIn("text/csv", headers["Content-Type"])
        self.assertTrue(body.decode().startswith("scenario_id,environment,attack_mode,defense_id"))
        self.assertEqual(len(body.decode().strip().splitlines()), 37)

    def test_full_report_download(self):
        report = self.get(f"/api/experiments/{self.run_id}")[1]
        self.assertEqual(len(report["campaigns"]), 36)
        self.assertIn("suite_content_hash", report["manifest"])

    def test_invalid_configurations_are_rejected_immediately_with_a_readable_message(self):
        for bad, needle in (({**RUN, "attack_budget": 0}, "attack_budget"), ({**RUN, "scenario_ids": ["nope"]}, "Unknown scenario"),
                            ({**RUN, "attack_modes": ["adaptive_ollama"]}, "model_config"), ({**RUN, "defenses": []}, "defense"),
                            ({**RUN, "defenses": ["baseline", "magic_shield"]}, "Unknown defense"), ({**RUN, "seeds": [1, 1]}, "Duplicate")):
            status, data = self.post("/api/experiments", bad)
            self.assertEqual(status, 400, bad)
            self.assertIn(needle, data["error"])

    def test_unknown_runs_and_routes_return_404(self):
        self.assertEqual(self.get("/api/experiments/doesnotexist/status")[0], 404)
        self.assertEqual(self.get("/api/experiments/doesnotexist/summary")[0], 404)
        self.assertEqual(self.post("/api/experiments/doesnotexist/cancel")[0], 404)
        self.assertEqual(self.get("/api/nothing-here")[0], 404)

    def test_dashboard_files_are_served_and_path_traversal_is_refused(self):
        for path, needle in (("/", b"AgentGuard"), ("/styles.css", b"--ink"), ("/app.js", b"AgentGuard dashboard")):
            status, body, _ = self.get(path, raw=True)
            self.assertEqual(status, 200)
            self.assertIn(needle, body)
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1])
        conn.request("GET", "/../run_web.py")
        self.assertIn(conn.getresponse().status, (403, 404))

    def test_cancel_endpoint_accepts_a_request_for_a_known_run(self):
        status, data = self.post(f"/api/experiments/{self.run_id}/cancel")
        self.assertEqual((status, data["cancelling"]), (200, True))


if __name__ == "__main__":
    unittest.main()
