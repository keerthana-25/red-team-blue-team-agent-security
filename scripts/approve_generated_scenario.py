#!/usr/bin/env python3
"""The only sanctioned way a generated candidate becomes a real suite scenario.

    python3 scripts/approve_generated_scenario.py --id generated-email-exfil-101 --reviewer "Your Name"

Re-validates the candidate one more time (never trusts a validation result from earlier — the
candidate file or the platform code could have changed since), requires an explicit reviewer name
on the command line (there is no default and no way to skip it), then copies the file into
scenarios/, adds it to scenarios/suite.json, and records the reviewer's decision in the
candidate's own generation_metadata.

Approval here means "safe to include in the suite," not "fully reviewed." The scenario's
validation_status is set to "unreviewed" (an ordinary suite member), not "reviewed" — it still
needs to go through docs/SCENARIO_REVIEW.md like any hand-authored scenario before anyone treats
its results as more than a demonstration.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rtbt.scenario_registry import load_suite, parse_scenario  # noqa: E402
from rtbt.util import utc_now_iso  # noqa: E402

sys.path.insert(0, str(ROOT / "scripts"))
from generate_scenario import GENERATED_DIR, validate_candidate  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--id", required=True, help="The candidate's scenario id, e.g. generated-email-exfil-101.")
    parser.add_argument("--reviewer", required=True, help="Your name. Recorded permanently in the scenario file.")
    args = parser.parse_args()

    candidate_path = GENERATED_DIR / f"{args.id}.json"
    if not candidate_path.exists():
        print(f"No candidate at {candidate_path.relative_to(ROOT)}. Run generate_scenario.py first.")
        return 1
    raw = json.loads(candidate_path.read_text(encoding="utf-8"))
    if raw.get("validation_status") != "generated_unreviewed":
        print(f"Refusing: validation_status is {raw.get('validation_status')!r}, not 'generated_unreviewed'. "
              "This file may already have been approved, or was hand-edited into an unexpected state.")
        return 1

    try:
        sc = parse_scenario(dict(raw), source=f"<approving:{args.id}>")
    except Exception as exc:
        print(f"Refusing: the candidate no longer passes schema/tool/authorization validation: {exc}")
        return 1
    live_results = validate_candidate(sc)
    failed = {k: v for k, v in live_results.items() if v}
    if failed:
        print(f"Refusing: {len(failed)} live check(s) fail right now: {failed}")
        return 1

    dest_scenarios_dir = ROOT / "scenarios"
    dest_filename = f"{args.id.replace('-', '_')}.json"
    dest_path = dest_scenarios_dir / dest_filename

    suite_manifest_path = dest_scenarios_dir / "suite.json"
    manifest = json.loads(suite_manifest_path.read_text(encoding="utf-8"))
    if dest_filename in manifest["scenarios"]:
        print(f"Refusing: {dest_filename} is already listed in suite.json.")
        return 1

    raw["validation_status"] = "unreviewed"  # a real suite member now, but still needs docs/SCENARIO_REVIEW.md
    raw["generation_metadata"]["reviewer_decision"] = {
        "reviewer": args.reviewer, "decision": "approved_for_suite_inclusion", "decided_at": utc_now_iso(),
    }
    dest_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    manifest["scenarios"] = sorted(manifest["scenarios"] + [dest_filename])
    suite_manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"Approved by {args.reviewer}. Wrote {dest_path.relative_to(ROOT)} and added it to suite.json.")
    print("It is now an ordinary 'unreviewed' suite scenario — run scripts/validate_scenarios.py and see "
          "docs/SCENARIO_REVIEW.md before treating anything it produces as more than a demonstration.")

    # Prove the suite actually loads correctly with the new member before declaring success.
    try:
        load_suite(dest_scenarios_dir)
    except Exception as exc:
        print(f"WARNING: the suite no longer loads after this change: {exc}. Reverting is your call, not automatic.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
