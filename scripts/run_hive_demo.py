#!/usr/bin/env python
"""Run the hive against seed targets — no LLM required.

Uses FakeCrewRunner + InProcessTransport so the full lifecycle (seed → recon →
fingerprint → vuln detect → exploit → done) exercises the real tool functions
through the Gateway security chain without calling an LLM.

Usage::

    python scripts/run_hive_demo.py [--target example.com] [--rounds 6]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure the project root is on sys.path
_project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_project_root))

from src.agents.hive import FakeCrewRunner, HiveOrchestrator, HivePhase
from src.domain.storage import SQLiteStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Hive penetration test demo")
    parser.add_argument("--target", default="example.com",
                        help="Seed target to scan (default: example.com)")
    parser.add_argument("--rounds", type=int, default=6,
                        help="Max hive rounds (default: 6)")
    parser.add_argument("--db", default=":memory:",
                        help="SQLite database path (default: :memory:)")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    store = SQLiteStore(args.db)
    runner = FakeCrewRunner(verbose=args.verbose)

    orch = HiveOrchestrator(
        store,
        project_id="demo-project",
        scope_id="demo-scope",
        session_id="demo-session",
        max_rounds=args.rounds,
        crew_runner=runner,
        verbose=args.verbose,
    )

    print(f"[Hive] Starting — target: {args.target}, max rounds: {args.rounds}")
    print("-" * 60)

    summary = orch.run(seed_targets=[args.target])

    print("-" * 60)
    print(f"[Hive] Run complete in {summary.rounds} round(s)")
    print(f"   Final phase:  {summary.final_phase.value}")
    print(f"   Total facts:  {summary.fact_count}")
    print(f"   Vulns found:  {summary.vuln_count}")
    print(f"   Verified:     {summary.verified_count}")
    print(f"   Truncated:    {summary.truncated}")

    if summary.blocked_reasons:
        print(f"   Blocked:      {', '.join(summary.blocked_reasons)}")

    print()
    print("Round log:")
    for entry in summary.round_log:
        extra = entry.get("reason", "")
        evidence = entry.get("evidence_count", 0)
        print(f"  Round {entry['round']:2d} | {entry['phase']:14s} | {evidence:2d} evidence"
              + (f" | {extra}" if extra else ""))

    # Print blackboard snapshot
    from src.blackboard.service import BlackboardService
    bb = BlackboardService(store)
    facts = bb.snapshot("demo-project")
    if facts:
        print(f"\n[Blackboard] {len(facts)} facts:")
        for f in facts:
            verified = "[V]" if f.data.get("verified") else ""
            print(f"  [{f.fact_type}] {f.asset_ref} {verified}")
            if args.verbose:
                import json
                print(f"    data: {json.dumps(f.data, ensure_ascii=False)[:200]}")

    store.close()


if __name__ == "__main__":
    main()