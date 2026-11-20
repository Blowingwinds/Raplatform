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

from src.agents.capabilities import register_default_capabilities
from src.agents.hive import FakeCrewRunner, HiveOrchestrator, HivePhase
from src.blackboard.service import BlackboardService
from src.domain.storage import SQLiteStore
from src.planner.planner import Planner
from src.planner.providers import LLMProvider, LLMProviderError


def _build_planner(store: SQLiteStore, provider_name: str) -> Planner | None:
    """Construct a Planner for the requested provider (None keeps the default)."""
    if provider_name != "llm":
        return None
    try:
        llm = LLMProvider()
    except LLMProviderError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    print(f"Provider: LLM — {llm._config.describe()}")  # noqa: SLF001 (CLI display)
    return Planner(store, provider=llm)


def cmd_scan(args: argparse.Namespace) -> None:
    """Run a penetration test against target(s)."""
    store = SQLiteStore(args.db)
    runner = FakeCrewRunner(verbose=args.verbose)
    planner = _build_planner(store, args.provider)

    orch = HiveOrchestrator(
        store,
        project_id=args.project,
        scope_id=args.scope,
        session_id=args.session,
        max_rounds=args.rounds,
        crew_runner=runner,
        planner=planner,
        verbose=args.verbose,
        demo_mode=not args.no_demo,
    )

    targets = [t.strip() for t in args.target.split(",") if t.strip()]
    print(f"Targets : {', '.join(targets)}")
    print(f"Goal    : {args.goal or '(derived from targets)'}")
    print(f"Rounds  : {args.rounds}")
    print(f"Project : {args.project}")
    print(f"Mode    : {'demo (auto-approve)' if not args.no_demo else 'HITL (approval required)'}")
    print("-" * 50)

    summary = orch.run(seed_targets=targets, goal=args.goal)

    print("-" * 50)
    print(f"Status  : {summary.final_phase.value}")
    print(f"Rounds  : {summary.rounds}")
    print(f"Session : {summary.session_status}")
    print(f"Facts   : {summary.fact_count}")
    print(f"Vulns   : {summary.vuln_count} ({summary.verified_count} verified)")
    if summary.truncated:
        print("(max rounds reached)")

    # Phase 7 metrics
    print()
    print("── Attack Chain Metrics ──")
    dispatched = summary.actions_dispatched
    succeeded = summary.actions_succeeded
    rate = summary.success_rate
    print(f"  Actions: {dispatched} dispatched, {succeeded} succeeded "
          f"({summary.actions_failed} failed, {summary.actions_blocked} blocked)")
    print(f"  Success rate: {rate:.1%}")
    print(f"  Lease conflicts: {summary.lease_conflicts}")
    print(f"  HITL requests: {summary.hitle_requests}")
    print(f"  Events processed: {summary.events_processed}")

    # Show PTT progress if available
    for entry in summary.round_log:
        if "progress" in entry:
            p = entry["progress"]
            print(f"  PTT: total={p.get('total', 0)} ready={p.get('ready', 0)} "
                  f"ok={p.get('succeeded', 0)} fail={p.get('failed', 0)} "
                  f"blocked={p.get('blocked', 0)}")
            break  # show latest only

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


def cmd_approve(args: argparse.Namespace) -> None:
    """Approve a pending HITL approval request."""
    from src.domain.storage import SQLiteStore
    from src.policy.approval import ApprovalGate

    store = SQLiteStore(args.db)
    gate = ApprovalGate(store, demo_mode=False)
    try:
        req = gate.approve(args.request_id, decided_by=args.by or "cli")
        print(f"Approved: {req.request_id}")
        print(f"  Action : {req.action_id}")
        print(f"  State  : {req.state.value}")
    except Exception as exc:
        print(f"Error: {exc}")
        store.close()
        sys.exit(1)
    store.close()


def cmd_reject(args: argparse.Namespace) -> None:
    """Reject a pending HITL approval request."""
    from src.domain.storage import SQLiteStore
    from src.policy.approval import ApprovalGate

    store = SQLiteStore(args.db)
    gate = ApprovalGate(store, demo_mode=False)
    try:
        req = gate.reject(args.request_id, decided_by=args.by or "cli",
                          reason=args.reason or "")
        print(f"Rejected: {req.request_id}")
        print(f"  Action : {req.action_id}")
        print(f"  State  : {req.state.value}")
    except Exception as exc:
        print(f"Error: {exc}")
        store.close()
        sys.exit(1)
    store.close()


def cmd_pending(args: argparse.Namespace) -> None:
    """List pending HITL approval requests."""
    from src.policy.approval import ApprovalGate

    store = SQLiteStore(args.db)
    gate = ApprovalGate(store, demo_mode=False)
    pending = gate.pending_for(args.project)
    if not pending:
        print("No pending approval requests.")
    else:
        print(f"Pending approvals for {args.project}: {len(pending)}")
        print("-" * 50)
        for req in pending:
            print(f"  [{req.request_id}]")
            print(f"    Action     : {req.action_id}")
            print(f"    Capability : {req.capability_id}")
            print(f"    Risk       : {req.risk_level.value}")
            print(f"    Targets    : {', '.join(req.resource_refs) if req.resource_refs else 'n/a'}")
            print(f"    Created    : {req.created_at.isoformat()}")
            print(f"    Reason     : {req.reason}")
            print()
            print(f"    Approve: python -m src approve {req.request_id} --db {args.db}")
            print(f"    Reject : python -m src reject {req.request_id} --db {args.db}")
            print("-" * 50)
    store.close()


def cmd_tree(args: argparse.Namespace) -> None:
    """Show the PTT tree from the last run."""
    store = SQLiteStore(args.db)
    tree_data = store.get_ptt_tree(args.project)
    if tree_data is None:
        print(f"No PTT tree found for project '{args.project}'.")
        print(f"Run a scan first: python -m src scan --db {args.db}")
        store.close()
        return

    from src.planner.ptt_schema import PTTTree
    tree = PTTTree.from_persistable(tree_data)
    summary = tree.summary()
    progress = tree.progress()

    print("=" * 60)
    print(f"  PTT TREE: {summary['goal']}")
    print("=" * 60)
    print(f"  Plan ID     : {summary['plan_id']}")
    print(f"  Generated by: {summary['generated_by']}")
    print(f"  Tactics     : {summary['tactics']}")
    print(f"  Techniques  : {summary['techniques']}")
    print(f"  Actions     : {summary['actions']}")
    print("-" * 60)
    print(f"  Progress: "
          f"planned={progress['planned']} ready={progress['ready']} "
          f"running={progress['running']} succeeded={progress['succeeded']} "
          f"failed={progress['failed']} blocked={progress['blocked']} "
          f"skipped={progress['skipped']}")

    # Show per-action status
    print("\n  Action Status:")
    for action in tree._all_actions():
        status = tree.node_states.get(action.action_id, "unknown")
        marker = {
            "ready": "→",
            "running": "⚡",
            "succeeded": "✓",
            "failed": "✗",
            "blocked": "⊘",
            "skipped": "⏭",
        }.get(str(status.value) if hasattr(status, 'value') else str(status), " ")
        print(f"    [{marker}] {action.action_id} ({status}): {action.name}")

    store.close()


def cmd_status(args: argparse.Namespace) -> None:
    """Show blackboard state with agent/evidence traceability."""
    db_path = args.db
    if not Path(db_path).exists() and db_path != ":memory:":
        print(f"Error: database not found: {db_path}")
        sys.exit(1)

    store = SQLiteStore(db_path)
    bb = BlackboardService(store)
    facts = bb.snapshot(args.project)
    events = bb.events_since(args.project)

    print(f"Project   : {args.project}")
    print(f"Facts     : {len(facts)}")
    print(f"Events    : {len(events)}")
    print("-" * 60)

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
            agent = item.source_agent or "?"
            ev_ref = item.evidence_ref[:20] + "…" if item.evidence_ref else "?"
            print(f"  {item.asset_ref}{verified} (conf={item.confidence:.0%}) "
                  f"← agent:{agent} ev:{ev_ref}")

    store.close()


def cmd_report(args: argparse.Namespace) -> None:
    """Generate a full Markdown (and optionally HTML) penetration test report."""
    from src.blackboard.topology import TopologyService
    from src.reporting.generator import generate_markdown, wrap_html

    db_path = args.db
    if not Path(db_path).exists() and db_path != ":memory:":
        print(f"Error: database not found: {db_path}")
        sys.exit(1)

    store = SQLiteStore(db_path)
    bb = BlackboardService(store)
    topology = TopologyService(bb)

    # Load PTT tree if available
    tree_data = store.get_ptt_tree(args.project)

    md = generate_markdown(
        args.project, bb,
        topology=topology,
        tree_data=tree_data,
    )

    if args.format == "html":
        html = wrap_html(md, title=f"Penetration Test Report — {args.project}")
        if args.output:
            Path(args.output).write_text(html, encoding="utf-8")
            print(f"HTML report written to {args.output}")
        else:
            md_path = args.db.replace(".db", "_report.html")
            Path(md_path).write_text(html, encoding="utf-8")
            print(f"HTML report written to {md_path}")
    else:
        if args.output:
            Path(args.output).write_text(md, encoding="utf-8")
            print(f"Markdown report written to {args.output}")
        else:
            md_path = args.db.replace(".db", "_report.md")
            Path(md_path).write_text(md, encoding="utf-8")
            print(f"Markdown report written to {md_path}")

    store.close()


def cmd_demo(args: argparse.Namespace) -> None:
    """Run the complete demo: plan → scan → report → tree."""
    print("=" * 60)
    print("  RAPLATFORM DEMO — Full Penetration Test Lifecycle")
    print("=" * 60)
    print()

    # Phase 1: Plan
    print("── Phase 1: PTT Plan Generation ──")
    plan_args = argparse.Namespace(
        goal=args.goal, project=args.project, scope=args.scope,
        db=args.db, output=None,
    )
    cmd_plan(plan_args)

    print()

    # Phase 2: Scan
    print("── Phase 2: Hive Scan Execution ──")
    scan_args = argparse.Namespace(
        target=args.target, project=args.project, scope=args.scope,
        session=args.session, rounds=args.rounds, db=args.db,
        verbose=args.verbose, no_demo=args.no_demo,
    )
    cmd_scan(scan_args)

    print()

    # Phase 3: Status
    print("── Phase 3: Blackboard Status ──")
    status_args = argparse.Namespace(project=args.project, db=args.db)
    cmd_status(status_args)

    print()

    # Phase 4: Report
    print("── Phase 4: Report Generation ──")
    report_args = argparse.Namespace(
        project=args.project, db=args.db,
        format="md", output=None,
    )
    cmd_report(report_args)

    print()

    # Phase 5: PTT Tree
    print("── Phase 5: PTT Tree Status ──")
    tree_args = argparse.Namespace(project=args.project, db=args.db)
    cmd_tree(tree_args)

    print()
    print("=" * 60)
    print("  DEMO COMPLETE — All phases executed successfully")
    print("=" * 60)


def cmd_trace(args: argparse.Namespace) -> None:
    """Trace a fact back to its source agent and raw evidence."""
    from src.blackboard.service import BlackboardService
    from src.reporting.generator import trace_fact_chain

    db_path = args.db
    if not Path(db_path).exists() and db_path != ":memory:":
        print(f"Error: database not found: {db_path}")
        sys.exit(1)

    store = SQLiteStore(db_path)
    bb = BlackboardService(store)
    chain = trace_fact_chain(args.fact_id, bb)

    if chain is None:
        print(f"Fact '{args.fact_id}' not found.")
        store.close()
        return

    print("=" * 60)
    print("  EVIDENCE TRACE")
    print("=" * 60)
    print(f"  Fact ID      : {chain['fact']['fact_id']}")
    print(f"  Fact Type    : {chain['fact']['fact_type']}")
    print(f"  Asset        : {chain['fact']['asset_ref']}")
    print(f"  Confidence   : {chain['fact']['confidence']}")
    print(f"  Version      : {chain['fact']['version']}")
    print(f"  State        : {chain['fact']['state']}")
    print("-" * 60)
    print(f"  Source Agent : {chain['agent_id']}")
    print(f"  Session      : {chain['session_id']}")
    if chain['session']:
        print(f"  Session Status: {chain['session']['status']}")
    print("-" * 60)
    print("  Evidence:")
    if chain['evidence']:
        ev = chain['evidence']
        print(f"    Evidence ID : {ev.get('evidence_id', '?')}")
        print(f"    Agent       : {ev.get('agent_id', '?')}")
        print(f"    Kind        : {ev.get('kind', '?')}")
        print(f"    Task        : {ev.get('task_id', '?')}")
        print(f"    Captured    : {ev.get('captured_at', '?')}")
        payload = ev.get('raw_payload', {})
        print(f"    Payload keys: {list(payload.keys()) if isinstance(payload, dict) else 'n/a'}")
    else:
        print("    (evidence not found in storage)")
    print("=" * 60)

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
    register_default_capabilities(registry)

    planner = _build_planner(store, args.provider) or Planner(store)

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
    p_plan.add_argument("--provider", choices=("mock", "llm"), default="mock",
                        help="PTT planner backend (default: mock; 'llm' uses .env config)")

    # ── scan ──
    p_scan = sub.add_parser("scan", help="Run a penetration test")
    p_scan.add_argument("--target", "-t", default="127.0.0.1",
                        help="Target IP, hostname, or comma-separated list")
    p_scan.add_argument("--goal", default=None,
                        help="Natural-language goal for the PTT planner "
                             "(e.g. '执行完整渗透测试'; default: derive from targets)")
    p_scan.add_argument("--provider", choices=("mock", "llm"), default="mock",
                        help="PTT planner backend (default: mock; 'llm' uses .env config)")
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
    p_report = sub.add_parser("report", help="Generate Markdown/HTML report")
    p_report.add_argument("--project", default="default",
                          help="Project ID")
    p_report.add_argument("--db", default="raplatform.db",
                          help="Database path")
    p_report.add_argument("--format", default="md", choices=["md", "html"],
                          help="Report format (default: md)")
    p_report.add_argument("--output", "-o", default=None,
                          help="Output file path (default: <db>_report.md)")

    # ── approve ──
    p_approve = sub.add_parser("approve", help="Approve a pending HITL request")
    p_approve.add_argument("request_id", help="Approval request ID")
    p_approve.add_argument("--db", default="raplatform.db",
                           help="Database path")
    p_approve.add_argument("--by", default=None,
                           help="Who approved (default: cli)")

    # ── reject ──
    p_reject = sub.add_parser("reject", help="Reject a pending HITL request")
    p_reject.add_argument("request_id", help="Approval request ID")
    p_reject.add_argument("--db", default="raplatform.db",
                          help="Database path")
    p_reject.add_argument("--by", default=None,
                          help="Who rejected (default: cli)")
    p_reject.add_argument("--reason", default="",
                          help="Rejection reason")

    # ── pending ──
    p_pending = sub.add_parser("pending", help="List pending HITL requests")
    p_pending.add_argument("--project", default="default",
                           help="Project ID")
    p_pending.add_argument("--db", default="raplatform.db",
                           help="Database path")

    # ── tree ──
    p_tree = sub.add_parser("tree", help="Show PTT tree status")
    p_tree.add_argument("--project", default="default",
                        help="Project ID")
    p_tree.add_argument("--db", default="raplatform.db",
                        help="Database path")

    # ── demo ──
    p_demo = sub.add_parser("demo", help="Run full demo (plan → scan → report → tree)")
    p_demo.add_argument("--goal", default="发现授权网段的资产和服务",
                        help="NL goal for PTT plan generation")
    p_demo.add_argument("--target", "-t", default="127.0.0.1",
                        help="Target IP or hostname")
    p_demo.add_argument("--project", default="demo",
                        help="Project ID")
    p_demo.add_argument("--scope", default="demo-scope",
                        help="Scope ID")
    p_demo.add_argument("--session", default="demo-session",
                        help="Session ID")
    p_demo.add_argument("--rounds", type=int, default=6,
                        help="Max hive rounds")
    p_demo.add_argument("--db", default="demo.db",
                        help="Database path")
    p_demo.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    p_demo.add_argument("--no-demo", action="store_true",
                        help="Require HITL approval")

    # ── trace ──
    p_trace = sub.add_parser("trace", help="Trace a fact back to source agent + evidence")
    p_trace.add_argument("fact_id", help="Fact ID to trace")
    p_trace.add_argument("--db", default="raplatform.db",
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
    elif args.command == "approve":
        cmd_approve(args)
    elif args.command == "reject":
        cmd_reject(args)
    elif args.command == "pending":
        cmd_pending(args)
    elif args.command == "tree":
        cmd_tree(args)
    elif args.command == "demo":
        cmd_demo(args)
    elif args.command == "trace":
        cmd_trace(args)


if __name__ == "__main__":
    main()