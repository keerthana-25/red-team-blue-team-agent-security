# Changelog

## 0.2.2: professor-ready prototype handoff

Aligned the package with the official project title and the repository name `cmpe295a-red-team-blue-team-prototype`, corrected the setup guide and current test count, and synchronized the documentation with the implemented SQLite-backed recovery behavior. The scenario validator now distinguishes one documented, approved research warning from unexpected validation failures. The current suite contains 156 passing tests.

## 0.2.1: easier to run

Added `start.py`, a one-command launcher that checks Python, runs the tests, runs a sample experiment and opens the dashboard, with shortcuts for each step. The dashboard can now open the browser itself once the server is listening (`--open`), which replaces the fragile "sleep, then open" trick, and it explains a busy port instead of printing a traceback.

Lowered the Python requirement from 3.10 to 3.9 after running the full suite on 3.9, 3.10 and 3.12; a Mac's built-in `python3` is 3.9.

Windows hardening, verified with a non-UTF-8 stand-in locale: every text file is now read and written as UTF-8 explicitly, console output no longer crashes on characters the console cannot show, and the dashboard no longer lets a second server share a busy port on Windows. Before the fix, one test failed and the sample experiment crashed on its first line under that locale.

The README's pasteable commands no longer contain trailing `#` notes (macOS zsh passes them as arguments) or `\` line continuations (PowerShell cannot paste them). Added tests for the launcher, busy ports and the non-UTF-8 case, bringing the total to 101.

## 0.2.0: ground-up rebuild

The original prototype (about a dozen informally assembled Python files, uploaded as a single zip) was rebuilt from scratch against a written specification. The old code was kept untouched for reference and nothing was copied forward without being rewritten and tested.

### What changed in kind

The oracle now decides success from environment state and never from text. The attacker interface can receive only an `AttackBrief` and a boolean, and tests enforce that identical briefs reach the attacker under every defense. Every defense hooks in through one runtime that guarantees a blocked write has no side effect. Budgets are matched and checked, attacker histories are independent per campaign, environments are rebuilt every round, and randomness is derived from seeds with no global state. Invalid rounds (timeouts, refusals, malformed output) are excluded and reported rather than counted as failures or successes.

Results are labeled component by component (target agent, attacker, defense) as simulated or real, and every report and dashboard screen carries a warning while any component is a simulation or fixture. A reproducibility manifest records the scenario suite hash, seeds, budgets, model settings and platform. A single module, guarded by a test, is the only code allowed to touch the network, restricted to local hosts by default.

### New

Three simulated environments (email, documents, calendar) with permission scopes; a validated scenario schema and nine hand-authored scenarios; a tool policy engine; four defenses; static, adaptive-demo and local-model attackers; simulated and real-model target agents; a standard-library statistics layer with honest handling of small samples and null results; a command-line runner with JSON and CSV export; a local web API and a five-view dashboard; example configs; and 95 tests.

### Bugs found and fixed during the rebuild

The tool policy engine did not recognize the plural `attendees` argument, so the tool validator silently allowed every calendar attack exactly like no defense at all. It now covers it, with a regression test.

The web server matched routes without regard to HTTP method, so starting a run always returned 404. Routes are now keyed by method, with a regression test.

Benign control rounds counted only content-filter blocks as false blocks, so a policy that wrongly refused a legitimate write showed a benign block rate of zero. Policy-level refusals now count.

Provenance labeling covered only the target and attacker. It now labels every component including defenses, so a demonstration classifier can no longer be hidden inside an otherwise real run.

Configuration validation did not reject unknown defense or attacker ids or duplicated seeds until a campaign failed partway through a run. It now rejects them before anything starts, and the API returns a 400 with the reason.

Cancelling a run discarded everything. It now keeps the completed campaigns and labels the manifest `cancelled`.

Dashboard: the round strip printed `[object HTMLSpanElement]` where a benign-round gap was inserted; result views did not refresh after a run selected from the sidebar finished loading; several tables were unreadably wide; and a 36-row comparison was replaced by a per-defense summary.

### Known gaps

The local-model attacker, real-model target and hosted-classifier adapter have only been tested against mocked responses. The simulated target and demonstration classifier are calibrated to the built-in payload styles. See `docs/LIMITATIONS.md`.
