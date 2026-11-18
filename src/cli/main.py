"""Raplatform CLI — ``python -m raplatform scan --target example.com``

Commands::

    scan     Run a penetration test against target(s)
    status   Show blackboard state for a previous run
    report   Generate a summary report from blackboard facts

No LLM required — uses FakeCrewRunner + InProcessTransport for the full
hive lifecycle (recon → fingerprint → vuln detect → exploit → report).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_project_root))

from src.agents.hive import FakeCrewRunner, HiveOrchestrator, HivePhase
from src.blackboard.service import BlackboardService
from src.domain.storage import SQLiteStore


def cmd_scan(args: argparse.Namespace) -> None:
    """Run a penetration test against target(s)."""
    store = SQLiteStore(args.db)
    runner = FakeCrewRunner(verbose=args.verbose)

    orch = HiveOrchestrator(
        store,
        project_id=args.project,
        scope_id=args.scope,
        session_id=args.session,
        max_rounds=args.rounds,
        crew_runner=runner,
        verbose=args.verbose,
        demo_mode=not args.no_demo,
    )

    targets = [t.strip() for t in args.target.split(",") if t.strip()]
    print(f"Targets : {', '.join(targets)}")
    print(f"Rounds  : {args.rounds}")
    print(f"Project : {args.project}")
    print("-" * 50)

    summary = orch.run(seed_targets=targets)

    print("-" * 50)
    print(f"Phase   : {summary.final_phase.value}")
    print(f"Rounds  : {summary.rounds}")
    print(f"Facts   : {summary.fact_count}")
    print(f"Vulns   : {summary.vuln_count} ({summary.verified_count} verified)")
    if summary.truncated:
        print("(max rounds reached)")

    # Show facts
    bb = BlackboardService(store)
    facts = bb.snapshot(args.project)
    if not facts:
        print("\nNo facts on blackboard.")
        store.close()
        return

    by_type: dict[str, list] = {}
    for f in facts:
        by_type.setdefault(f.fact_type, []).append(f)

    print()
    for ftype, items in sorted(by_type.items()):
        print(f"[{ftype}] ({len(items)})")
        for item in items[:10]:  # limit
            verified = " [verified]" if item.data.get("verified") else ""
            detail = ""
            if ftype == "service.exposed":
                detail = f" :{item.data.get('port', '?')}/{item.data.get('service_name', '?')}"
            elif ftype == "fingerprint.detected":
                detail = f" {item.data.get('name', '?')} {item.data.get('extracted', '')}"
            elif ftype == "vulnerability.detected":
                detail = f" {item.data.get('name', '?')} ({item.data.get('severity', '?')})"
            print(f"  {item.asset_ref}{detail}{verified}")
    store.close()


def cmd_status(args: argparse.Namespace) -> None:
    """Show blackboard state from a previous run."""
    db_path = args.db
    if not Path(db_path).exists() and db_path != ":memory:":
        print(f"Error: database not found: {db_path}")
        sys.exit(1)

    store = SQLiteStore(db_path)
    bb = BlackboardService(store)
    facts = bb.snapshot(args.project)
    events = bb.events_since(args.project)

    print(f"Project  : {args.project}")
    print(f"Facts    : {len(facts)}")
    print(f"Events   : {len(events)}")
    print("-" * 40)

    if not facts:
        print("No facts on blackboard.")
        store.close()
        return

    by_type: dict[str, list] = {}
    for f in facts:
        by_type.setdefault(f.fact_type, []).append(f)

    for ftype, items in sorted(by_type.items()):
        print(f"\n[{ftype}] ({len(items)})")
        for item in items:
            verified = " [V]" if item.data.get("verified") else ""
            print(f"  {item.asset_ref}{verified} (conf={item.confidence:.0%})")

    store.close()


def cmd_report(args: argparse.Namespace) -> None:
    """Generate a summary report from blackboard facts."""
    db_path = args.db
    if not Path(db_path).exists() and db_path != ":memory:":
        print(f"Error: database not found: {db_path}")
        sys.exit(1)

    store = SQLiteStore(db_path)
    bb = BlackboardService(store)
    facts = bb.snapshot(args.project)

    assets = [f for f in facts if f.fact_type == "asset.discovered"]
    services = [f for f in facts if f.fact_type == "service.exposed"]
    fingerprints = [f for f in facts if f.fact_type == "fingerprint.detected"]
    vulns = [f for f in facts if f.fact_type == "vulnerability.detected"]
    verified = [v for v in vulns if v.data.get("verified")]

    print("=" * 50)
    print("  PENETRATION TEST REPORT")
    print("=" * 50)
    print(f"  Project    : {args.project}")
    print(f"  Assets     : {len(assets)}")
    print(f"  Services   : {len(services)}")
    print(f"  Tech Stack : {len(fingerprints)}")
    print(f"  Vulns      : {len(vulns)} ({len(verified)} verified)")
    print("-" * 50)

    if services:
        print("\n[SERVICES]")
        for s in services:
            print(f"  {s.asset_ref}:{s.data.get('port')} → {s.data.get('service_name')}"
                  + (f" ({s.data.get('banner', '')[:60]})" if s.data.get('banner') else ""))

    if fingerprints:
        print("\n[TECHNOLOGY]")
        for fp in fingerprints:
            print(f"  {fp.asset_ref}: {fp.data.get('name')} {fp.data.get('extracted', '')}")

    if vulns:
        print("\n[VULNERABILITIES]")
        for v in vulns:
            status = "[VERIFIED]" if v.data.get("verified") else "[PENDING]"
            print(f"  {status} {v.data.get('name', '?')}")
            print(f"    Target: {v.asset_ref}")
            print(f"    Severity: {v.data.get('severity', '?')}")
            print(f"    Category: {v.data.get('category', '?')}")
            if v.data.get("description"):
                print(f"    {v.data.get('description')[:120]}")

    if not services and not vulns:
        print("\n  No findings. Run a scan first:")
        print(f"    python -m src scan --target <target> --db {args.db}")

    store.close()


def cmd_plan(args: argparse.Namespace) -> None:
    """Generate a PTT plan from a natural-language goal."""
    import json

    from src.agents.registry import AgentRegistry
    from src.domain.models import AgentCapability, RiskLevel, Scope
    from src.planner import Planner

    store = SQLiteStore(args.db)

    # Ensure scope exists
    scope = store.get_scope(args.scope)
    if scope is None:
        scope = Scope(
            scope_id=args.scope,
            project_id=args.project,
            target_type="domain",
            target=args.scope,
            authorization_ref=f"auth-{args.project}",
        )
        store.save_scope(scope)

    registry = AgentRegistry(store)

    # Register default capabilities for technique matching
    _DEFAULT_CAPS = [
        ("info-gatherer", "Information Gatherer",
         ["T1046", "T1592", "T1590", "T1595"], ["ip", "domain", "url", "hostname"], "low"),
        ("framework-vuln", "Framework Vuln",
         ["T1190", "T1595", "T1210"], ["url", "service", "hostname"], "medium"),
        ("web-attack", "Web Attack",
         ["T1190", "T1595", "T1059"], ["url", "service", "endpoint"], "high"),
        ("component-vuln", "Component Vuln",
         ["T1190", "T1595", "T1210"], ["url", "service", "component"], "medium"),
        ("exploit-verifier", "Exploit Verifier",
         ["T1190", "T1059", "T1210"], ["url", "endpoint", "service"], "high"),
    ]
    for cid, name, techs, targets, risk in _DEFAULT_CAPS:
        if registry.get(cid) is None:
            registry.register(AgentCapability(
                capability_id=cid, name=name,
                techniques=techs, target_types=targets,
                input_schema=f"{cid}_input.schema.json",
                output_schema=f"{cid}_output.schema.json",
                risk_level=RiskLevel(risk),
            ))
    planner = Planner(store)

    try:
        tree = planner.generate(args.goal, scope, registry, project_id=args.project)
    except Exception as exc:
        print(f"Plan rejected: {exc}")
        store.close()
        sys.exit(1)

    plan = tree.plan

    if args.output:
        # Write JSON to file
        output_path = Path(args.output)
        output_path.write_text(
            json.dumps(plan.model_dump(mode="json"), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        print(f"Plan written to {output_path}")
    else:
        # Print summary to terminal
        print("=" * 60)
        print(f"  PTT PLAN: {plan.normalized_goal}")
        print("=" * 60)
        print(f"  Plan ID     : {plan.plan_id}")
        print(f"  Generated by: {plan.generated_by}")
        print(f"  Project     : {plan.project_id}")
        print(f"  Scope       : {plan.scope_id}")
        print(f"  Tactics     : {len(plan.tactics)}")
        print(f"  Techniques  : {len(plan.all_techniques())}")
        print(f"  Actions     : {len(plan.all_actions())}")
        print("-" * 60)

        for i, tactic in enumerate(plan.tactics):
            print(f"\n  [{tactic.tactic_id}] {tactic.name}")
            for j, technique in enumerate(tactic.techniques):
                print(f"    ├─ [{technique.technique_id}] {technique.name}")
                for k, action in enumerate(technique.actions):
                    prefix = "    │  └─" if k < len(technique.actions) - 1 else "    │  └─"
                    print(f"    │  {prefix} {action.action_id}: {action.name}")
                    print(f"    │     Risk: {action.risk_level.value} | Outputs: {', '.join(action.expected_outputs)}")
                    if action.side_effects:
                        print(f"    │     Side effects: {', '.join(action.side_effects)}")

        print(f"\n  Tree progress: {tree.progress()}")

    store.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="raplatform",
        description="Automated penetration testing platform",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── plan ──
    p_plan = sub.add_parser("plan", help="Generate a PTT plan from a goal")
    p_plan.add_argument("goal", help="Natural-language penetration testing goal")
    p_plan.add_argument("--project", default="default",
                        help="Project ID (default: default)")
    p_plan.add_argument("--scope", default="default-scope",
                        help="Scope ID / target for scope resolution")
    p_plan.add_argument("--db", default=":memory:",
                        help="SQLite database path (default: :memory:)")
    p_plan.add_argument("--output", "-o", default=None,
                        help="Write plan JSON to file instead of printing summary")

    # ── scan ──
    p_scan = sub.add_parser("scan", help="Run a penetration test")
    p_scan.add_argument("--target", "-t", default="127.0.0.1",
                        help="Target IP, hostname, or comma-separated list")
    p_scan.add_argument("--project", default="default",
                        help="Project ID (default: default)")
    p_scan.add_argument("--scope", default="default-scope",
                        help="Scope ID")
    p_scan.add_argument("--session", default="cli-session",
                        help="Session ID")
    p_scan.add_argument("--rounds", type=int, default=6,
                        help="Max hive rounds (default: 6)")
    p_scan.add_argument("--db", default=":memory:",
                        help="SQLite database path (default: :memory:)")
    p_scan.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    p_scan.add_argument("--no-demo", action="store_true",
                        help="Require HITL approval for HIGH risk actions (off by default in CLI)")

    # ── status ──
    p_status = sub.add_parser("status", help="Show blackboard state")
    p_status.add_argument("--project", default="default",
                          help="Project ID")
    p_status.add_argument("--db", default="raplatform.db",
                          help="Database path")

    # ── report ──
    p_report = sub.add_parser("report", help="Generate summary report")
    p_report.add_argument("--project", default="default",
                          help="Project ID")
    p_report.add_argument("--db", default="raplatform.db",
                          help="Database path")

    args = parser.parse_args()

    if args.command == "plan":
        cmd_plan(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "report":
        cmd_report(args)


if __name__ == "__main__":
    main()