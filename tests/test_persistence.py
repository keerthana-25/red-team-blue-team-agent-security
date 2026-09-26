from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from _common import ROOT  # noqa: F401 (import establishes sys.path for the rtbt package)

from rtbt.persistence import STATEFUL_ATTACK_MODES, RunStore


class RunStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "runs.db"

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_completed_campaign_is_recorded_and_never_needs_to_be_repeated(self):
        store = RunStore(self.db_path)
        store.create_run("run1", {"defenses": ["baseline"]})
        store.record_campaign_start("run1", "c1", scenario_id="s", defense_id="baseline", attack_mode="static",
                                    target_mode="simulated", seed=1, attack_budget=10)
        store.record_campaign_complete("run1", "c1", {"campaign_id": "c1", "status": "complete"})
        campaigns = store.get_campaigns("run1")
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(campaigns[0]["status"], "complete")
        self.assertEqual(campaigns[0]["result"]["campaign_id"], "c1")

    def test_a_process_death_simulated_by_a_fresh_store_on_the_same_file_finds_the_interruption(self):
        """This is the core scenario: 'construct a new runner' against persisted partial state."""
        store1 = RunStore(self.db_path)
        store1.create_run("run1", {"defenses": ["baseline", "tool_validator"]})
        store1.record_campaign_start("run1", "c1", scenario_id="s", defense_id="baseline", attack_mode="static",
                                     target_mode="simulated", seed=1, attack_budget=10)
        store1.record_campaign_complete("run1", "c1", {"campaign_id": "c1", "status": "complete"})
        store1.record_campaign_start("run1", "c2", scenario_id="s", defense_id="tool_validator", attack_mode="static",
                                     target_mode="simulated", seed=1, attack_budget=10)
        # the process "dies" here — c2 never completes, run1's status row is still 'running'
        store1.close()

        store2 = RunStore(self.db_path)  # a brand new instance — nothing shared with store1 in memory
        interrupted = store2.mark_stale_running_as_interrupted()
        self.assertEqual(interrupted, ["run1"])
        self.assertEqual(store2.get_run("run1")["status"], "interrupted")

        plan = store2.recovery_plan("run1")
        self.assertEqual(plan["completed_campaign_ids"], ["c1"])
        self.assertEqual(plan["incomplete_safe_same_id"], ["c2"])  # static: safe to just re-run
        self.assertEqual(plan["incomplete_needs_new_id"], [])

    def test_a_run_that_finished_normally_is_never_flagged_as_interrupted(self):
        store = RunStore(self.db_path)
        store.create_run("run1", {})
        store.update_run_status("run1", "complete")
        store2 = RunStore(self.db_path)
        self.assertEqual(store2.mark_stale_running_as_interrupted(), [])
        self.assertEqual(store2.get_run("run1")["status"], "complete")

    def test_a_stateful_attacker_incomplete_campaign_is_flagged_for_a_new_id_not_resumed_in_place(self):
        store = RunStore(self.db_path)
        store.create_run("run1", {})
        for mode in STATEFUL_ATTACK_MODES:
            store.record_campaign_start("run1", f"c-{mode}", scenario_id="s", defense_id="baseline",
                                        attack_mode=mode, target_mode="simulated", seed=1, attack_budget=10)
        store.record_campaign_start("run1", "c-static", scenario_id="s", defense_id="baseline", attack_mode="static",
                                    target_mode="simulated", seed=1, attack_budget=10)
        plan = store.recovery_plan("run1")
        self.assertEqual(set(plan["incomplete_needs_new_id"]), {f"c-{m}" for m in STATEFUL_ATTACK_MODES})
        self.assertIn("c-static", plan["incomplete_safe_same_id"])

    def test_every_recovery_decision_is_permanently_logged_and_never_silently_applied(self):
        store = RunStore(self.db_path)
        store.create_run("run1", {})
        store.update_run_status("run1", "interrupted")
        store.log_recovery_decision("run1", "abandon", "user chose to abandon it")
        log = store.get_recovery_log("run1")
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["decision"], "abandon")
        self.assertIn("abandon", log[0]["note"])

    def test_startup_scan_itself_leaves_an_audit_trail(self):
        store1 = RunStore(self.db_path)
        store1.create_run("run1", {})
        store1.close()
        store2 = RunStore(self.db_path)
        store2.mark_stale_running_as_interrupted()
        log = store2.get_recovery_log("run1")
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["decision"], "marked_interrupted_on_startup")

    def test_nothing_is_ever_deleted_completed_campaigns_survive_every_operation(self):
        store = RunStore(self.db_path)
        store.create_run("run1", {})
        store.record_campaign_start("run1", "c1", scenario_id="s", defense_id="baseline", attack_mode="static",
                                    target_mode="simulated", seed=1, attack_budget=5)
        store.record_campaign_complete("run1", "c1", {"campaign_id": "c1", "rounds": [1, 2, 3]})
        store.update_run_status("run1", "interrupted")
        store.log_recovery_decision("run1", "resume", "resuming")
        # even after all that bookkeeping, the original completed campaign's full data is intact
        c1 = next(c for c in store.get_campaigns("run1") if c["campaign_id"] == "c1")
        self.assertEqual(c1["result"]["rounds"], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
