from __future__ import annotations

import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import unittest

from _common import ROOT

spec = importlib.util.spec_from_file_location("start", ROOT / "start.py")
start = importlib.util.module_from_spec(spec)
spec.loader.exec_module(start)


def run(args, env=None, timeout=120):
    return subprocess.run([sys.executable] + args, cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          encoding="utf-8", errors="replace", timeout=timeout)


class BusyPort:
    """Holds a real listening port for the duration of a test."""

    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        return self.sock.getsockname()[1]

    def __exit__(self, *exc):
        self.sock.close()


class LauncherTests(unittest.TestCase):
    def test_python_version_gate(self):
        self.assertTrue(start.python_ok((3, 9, 0)))
        self.assertTrue(start.python_ok((3, 12, 3)))
        self.assertFalse(start.python_ok((3, 8, 18)))

    def test_busy_ports_are_skipped(self):
        with BusyPort() as busy:
            port = start.find_free_port(busy, tries=10)
            self.assertGreater(port, busy)

    def test_running_out_of_ports_gives_a_clear_error(self):
        with BusyPort() as busy:
            with self.assertRaises(RuntimeError) as ctx:
                start.find_free_port(busy, tries=1)
            self.assertIn("No free port", str(ctx.exception))

    def test_help_lists_the_shortcuts(self):
        proc = run(["start.py", "--help"])
        self.assertEqual(proc.returncode, 0)
        for word in ("dashboard", "test", "demo", "--no-browser", "--port"):
            self.assertIn(word, proc.stdout)


class PortabilityTests(unittest.TestCase):
    def test_sample_experiment_runs_when_the_default_text_encoding_is_not_utf8(self):
        """Stand-in for Windows consoles and locales. This crashed on the first printed line before the fix."""
        env = dict(os.environ, LC_ALL="C", PYTHONCOERCECLOCALE="0", PYTHONUTF8="0")
        with tempfile.TemporaryDirectory() as out:
            proc = run(["-X", "utf8=0", "run_demo.py", "--config", os.path.join("configs", "quick_demo.json"), "--out-dir", out], env=env)
        self.assertEqual(proc.returncode, 0, proc.stdout[-600:])
        self.assertIn("DEMONSTRATION DATA ONLY", proc.stdout)

    def test_dashboard_explains_a_busy_port_instead_of_showing_a_traceback(self):
        with BusyPort() as busy:
            proc = run(["run_web.py", "--port", str(busy)], timeout=30)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Try a different one", proc.stdout)
        self.assertNotIn("Traceback", proc.stdout)


if __name__ == "__main__":
    unittest.main()
