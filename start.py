#!/usr/bin/env python3
"""One-command launcher for the Red Team vs. Blue Team prototype (AgentGuard platform).

    python3 start.py              check Python, run the tests, run a sample experiment, open the dashboard
    python3 start.py dashboard    just open the dashboard (the fast way back in)
    python3 start.py test         just run the automated tests
    python3 start.py demo         just run the sample experiment

On Windows use  py -3 start.py  (or  python start.py  if the py command is missing).
Add --no-browser to stop it opening a browser tab, or --port 8001 to choose the first port to try.
Uses only the Python standard library. Press Ctrl+C in this window to stop the dashboard.
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MIN_PYTHON = (3, 9)
FIRST_PORT = 8000
PORT_TRIES = 20


def say(text: str = "") -> None:
    print(text, flush=True)


def python_ok(version=None) -> bool:
    """True if this interpreter is new enough (3.9+, tested on 3.9, 3.10 and 3.12)."""
    version = version if version is not None else sys.version_info
    return tuple(version[:2]) >= MIN_PYTHON


def find_free_port(start: int = FIRST_PORT, tries: int = PORT_TRIES, host: str = "127.0.0.1") -> int:
    """First port from `start` that nothing else is using."""
    for port in range(start, start + tries):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((host, port))
        except OSError:
            continue
        finally:
            probe.close()
        return port
    raise RuntimeError(f"No free port between {start} and {start + tries - 1}. Close other programs and try again.")


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _run_captured(args: list) -> "subprocess.CompletedProcess":
    return subprocess.run(args, cwd=str(ROOT), env=_child_env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          encoding="utf-8", errors="replace")


def _tail(text: str, lines: int = 25) -> str:
    return "\n".join("    " + line for line in text.strip().splitlines()[-lines:])


def check_python() -> bool:
    found = f"{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}"
    if python_ok():
        say(f"  Python {found} found. That is fine.")
        return True
    say(f"  Python {found} is too old. This prototype needs Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer.")
    say("  Install the latest Python from https://www.python.org/downloads/ and run this again.")
    return False


def run_tests() -> bool:
    started = time.time()
    proc = _run_captured([sys.executable, "-m", "unittest", "discover", "-s", "tests"])
    match = re.search(r"Ran (\d+) tests? in ([\d.]+)s", proc.stdout)
    if proc.returncode == 0 and match:
        say(f"  All {match.group(1)} automated tests passed in {match.group(2)} seconds.")
        return True
    say(f"  The automated tests did not pass (took {time.time() - started:.1f} seconds). Last lines of the report:")
    say(_tail(proc.stdout))
    return False


def run_demo() -> bool:
    proc = _run_captured([sys.executable, "run_demo.py", "--config", str(Path("configs") / "quick_demo.json")])
    if proc.returncode != 0:
        say("  The sample experiment failed. Last lines of the report:")
        say(_tail(proc.stdout))
        return False
    saved = [line.strip() for line in proc.stdout.splitlines() if line.startswith(("Full report:", "Comparison CSV:"))]
    say("  Sample experiment finished. These numbers come from a simulated agent, so they are demonstration data only.")
    for line in saved:
        say("  " + line)
    return True


def run_dashboard(first_port: int, open_browser: bool) -> int:
    try:
        port = find_free_port(first_port)
    except RuntimeError as exc:
        say(f"  {exc}")
        return 1
    if port != first_port:
        say(f"  Port {first_port} is busy, so the dashboard will use port {port} instead.")
    url = f"http://127.0.0.1:{port}"
    say(f"  Dashboard address: {url}")
    say("  Leave this window open while you use the dashboard. Press Ctrl+C here to stop it.")
    say("")
    command = [sys.executable, "run_web.py", "--port", str(port)] + (["--open"] if open_browser else [])
    child = subprocess.Popen(command, cwd=str(ROOT), env=_child_env())
    try:
        return child.wait()
    except KeyboardInterrupt:
        try:
            return child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.terminate()
            return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="One-command launcher for Red Team vs. Blue Team for Tool-Using Agents.")
    parser.add_argument("what", nargs="?", default="all", choices=("all", "dashboard", "test", "demo"),
                        help="all (default), dashboard, test, or demo")
    parser.add_argument("--port", type=int, default=FIRST_PORT, help=f"first port to try (default {FIRST_PORT})")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser tab automatically")
    args = parser.parse_args(argv)

    if not (ROOT / "run_web.py").exists():
        say("This file must stay inside the project folder, next to run_web.py.")
        return 1

    steps = {"all": ["python", "tests", "demo", "dashboard"], "dashboard": ["python", "dashboard"],
             "test": ["python", "tests"], "demo": ["python", "demo"]}[args.what]
    say("Red Team vs. Blue Team prototype launcher")
    for number, step in enumerate(steps, start=1):
        titles = {"python": "Checking Python", "tests": "Running the automated tests",
                  "demo": "Running a sample experiment", "dashboard": "Starting the dashboard"}
        say(f"\nStep {number} of {len(steps)}: {titles[step]}")
        if step == "python":
            ok = check_python()
        elif step == "tests":
            ok = run_tests()
        elif step == "demo":
            ok = run_demo()
        else:
            return run_dashboard(args.port, open_browser=not args.no_browser)
        if not ok:
            say("\nStopped because a step failed. Nothing is broken on your computer; see the message above.")
            return 1
    say("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
