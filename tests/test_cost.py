from __future__ import annotations

import unittest

from _common import SUITE

from rtbt.cost import PricingConfig, compute_cost_accounting
from rtbt.harness import ExperimentConfig, ExperimentRunner


class CostAccountingTests(unittest.TestCase):
    def test_a_fully_simulated_campaign_has_null_tokens_and_zero_not_unavailable_cost(self):
        """Zero is the honest answer here: nothing was ever called, so there is nothing to pay
        for — that is different from 'unavailable', which means something ran but has no price."""
        cost = compute_cost_accounting({"input_tokens": None, "output_tokens": None},
                                       {"input_tokens": None, "output_tokens": None}, {})
        self.assertIsNone(cost["attacker_input_tokens"])
        self.assertEqual(cost["estimated_attacker_cost"], 0.0)
        self.assertEqual(cost["total_estimated_cost"], 0.0)
        self.assertIsNone(cost["currency"])
        self.assertIsNone(cost["pricing_source"])

    def test_a_local_model_with_known_tokens_and_no_pricing_has_unavailable_not_zero_cost(self):
        cost = compute_cost_accounting({"input_tokens": 120, "output_tokens": 40}, None, {})
        self.assertEqual((cost["attacker_input_tokens"], cost["attacker_output_tokens"]), (120, 40))
        self.assertIsNone(cost["estimated_attacker_cost"])  # unavailable, not fabricated as 0
        self.assertIsNone(cost["total_estimated_cost"])

    def test_a_hosted_model_with_an_explicit_pricing_config_computes_a_real_number(self):
        pricing = PricingConfig(source_id="test-price-list-2026-09", currency="USD",
                                price_per_1k_input_tokens=0.001, price_per_1k_output_tokens=0.002)
        cost = compute_cost_accounting({"input_tokens": 1000, "output_tokens": 500}, None, {}, attacker_pricing=pricing)
        self.assertAlmostEqual(cost["estimated_attacker_cost"], 1000 / 1000 * 0.001 + 500 / 1000 * 0.002)
        self.assertEqual(cost["currency"], "USD")
        self.assertEqual(cost["pricing_source"], "test-price-list-2026-09")

    def test_never_a_vendor_price_hard_coded_the_config_must_be_supplied_explicitly(self):
        cost_no_pricing = compute_cost_accounting({"input_tokens": 1000, "output_tokens": 500}, None, {})
        self.assertIsNone(cost_no_pricing["estimated_attacker_cost"])  # no config given -> no number invented

    def test_every_default_campaign_in_a_real_sweep_reports_the_same_honest_shape(self):
        cfg = ExperimentConfig(defenses=("baseline", "classifier"), attack_modes=("static", "adaptive_demo"),
                               attack_budget=3, seeds=(1,), scenario_ids=("email-summary-exfil",))
        report = ExperimentRunner(suite=SUITE, config=cfg).run()
        for c in report.campaigns:
            self.assertIsNone(c.cost["attacker_input_tokens"])
            self.assertEqual(c.cost["total_estimated_cost"], 0.0)
        row = report.comparison_table()[0]
        self.assertEqual(row["total_estimated_cost"], 0.0)
        self.assertIsNone(row["pricing_source"])


if __name__ == "__main__":
    unittest.main()
