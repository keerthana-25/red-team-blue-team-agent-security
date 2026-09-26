from __future__ import annotations

import argparse
import importlib.util
import json
import unittest

from _common import ROOT, SUITE

spec = importlib.util.spec_from_file_location("run_demo", ROOT / "run_demo.py")
run_demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_demo)


class ExampleConfigTests(unittest.TestCase):
    def test_every_shipped_config_parses_and_validates(self):
        files = sorted((ROOT / "configs").glob("*.json"))
        self.assertGreaterEqual(len(files), 4)
        for path in files:
            with self.subTest(config=path.name):
                config = run_demo.build_config(argparse.Namespace(config=str(path)))
                config.validate(SUITE)

    def test_placeholders_are_never_mistaken_for_real_model_names_in_the_simulated_configs(self):
        for name in ("quick_demo.json", "full_simulated_sweep.json"):
            self.assertNotIn("model_config", json.loads((ROOT / "configs" / name).read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
