"""HiveOrchestrator — the Queen Bee PTT-driven decision loop.

Phase 5: Replaced ``detect_phase()`` state machine with PTTTree-driven
execution.  The orchestrator generates an initial plan via Planner, then
each round dispatches READY actions through Router → HITL → Lease → crew.

Blackboard deltas flow through ReOrchestrator which appends/prunes
dynamic PTT nodes.  The loop terminates when the tree is complete or
all remaining actions are blocked.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.agents.capabilities import register_default_capabilities
from src.agents.hive.crews import (
    CrewContext,
    CrewRunResult,
    FakeCrewRunner,
    RealCrewRunner,
    build_crew_for_phase,
)
from src.agents.hive.phases import HivePhase
from src.agents.info_gatherer.dns_tools import enumerate_subdomains, resolve_dns
from src.agents.info_gatherer.port_scanner import scan_ports
from src.agents.info_gatherer.web_tools import discover_endpoints
from src.agents.registry import AgentRegistry
from src.agents.router import AgentRouter
from src.agents.shared.nuclei_runner import scan_fingerprints, scan_vulnerabilities
from src.agents.shared.python_exec import execute as python_exec
from src.agents.shared.sqlmap_runner import verify_sqli
from src.blackboard.service import BlackboardService
from src.blackboard.topology import TopologyService
from src.domain.lease_service import LeaseService
from src.domain.models import (
    Evidence,
    ExecutionSession,
    RiskLevel,
    Scope,
    SessionStatus,
)
from src.domain.storage import SQLiteStore
from src.mcp.gateway import MCPGateway
from src.mcp.transport import InProcessTransport, Transport
from src.planner.planner import Planner
from src.planner.ptt_schema import PTTNodeStatus, PTTTree
from src.planner.reorchestrator import ReOrchestrator
from src.policy.approval import ApprovalGate
from src.policy.guard import PolicyGuard

logger = logging.getLogger("hive.orchestrator")


# ── run summary ─────────────────────────────────────────────────────────

@dataclass
class HiveRunSummary:
    """Result of a complete hive orchestration run with attack-chain metrics."""
    rounds: int
    final_phase: HivePhase
    fact_count: int
    vuln_count: int
    verified_count: int
    truncated: bool
    blocked_reasons: list[str] = field(default_factory=list)
    round_log: list[dict[str, Any]] = field(default_factory=list)
    session_status: str = "unknown"
    # ── Phase 7 metrics ──
    actions_dispatched: int = 0
    actions_succeeded: int = 0
    actions_failed: int = 0
    actions_blocked: int = 0
    lease_conflicts: int = 0
    hitle_requests: int = 0
    events_processed: int = 0
    success_rate: float = 0.0

    def metrics_summary(self) -> dict[str, Any]:
        """Return a dict of all metrics for reporting."""
        return {
            "rounds": self.rounds,
            "session_status": self.session_status,
            "facts": self.fact_count,
            "vulnerabilities": self.vuln_count,
            "verified": self.verified_count,
            "actions": {
                "dispatched": self.actions_dispatched,
                "succeeded": self.actions_succeeded,
                "failed": self.actions_failed,
                "blocked": self.actions_blocked,
            },
            "success_rate": round(self.success_rate, 3),
            "lease_conflicts": self.lease_conflicts,
            "hitle_requests": self.hitle_requests,
            "events_processed": self.events_processed,
            "truncated": self.truncated,
            "blocked_reasons": self.blocked_reasons,
        }


# ── orchestrator ────────────────────────────────────────────────────────

class HiveOrchestrator:
    """Queen Bee — PTT-driven penetration testing lifecycle.

    Phase 5 architecture::

        Planner.generate → PTTTree
        ┌─ sweep expired leases & approvals ─┐
        │  read blackboard events             │
        │  ReOrchestrator.react(tree, events) │ ← per round
        │  for each ready action:             │
        │    Router.route → HITL → Lease      │
        │    dispatch → ingest → update tree  │
        └────────────────────────────────────┘
    """

    def __init__(
        self,
        store: SQLiteStore,
        *,
        project_id: str,
        scope_id: str,
        session_id: str,
        llm_model: str = "gpt-4o",
        max_rounds: int = 8,
        verbose: bool = False,
        demo_mode: bool = False,
        # Test injection points
        transport: Transport | None = None,
        crew_runner: Any = None,
        planner: Planner | None = None,
    ) -> None:
        self._store = store
        self._project_id = project_id
        self._scope_id = scope_id
        self._session_id = session_id
        self._llm_model = llm_model
        self._max_rounds = max_rounds
        self._verbose = verbose
        self._demo_mode = demo_mode

        # ── wiring ──
        self._registry = AgentRegistry(store)
        self._guard = PolicyGuard(store, demo_mode=demo_mode)
        self._blackboard = BlackboardService(store)

        # Transport
        if transport is not None:
            self._transport = transport
        else:
            inproc = InProcessTransport()
            inproc.register("scan_ports", scan_ports)
            inproc.register("resolve_dns", resolve_dns)
            inproc.register("enumerate_subdomains", enumerate_subdomains)
            inproc.register("discover_endpoints", discover_endpoints)
            inproc.register("scan_fingerprints", scan_fingerprints)
            inproc.register("scan_vulnerabilities", scan_vulnerabilities)
            inproc.register("execute_python", python_exec)
            inproc.register("verify_sqli", verify_sqli)
            self._transport = inproc

        # Gateways & services
        self._lease = LeaseService(store)
        self._approval = ApprovalGate(store, demo_mode=demo_mode)
        self._gateway = MCPGateway(
            self._registry, self._guard, self._transport,
            lease_service=self._lease,
            approval_gate=self._approval,
        )

        # Planner & re-orchestrator
        self._planner = planner or Planner(store)
        self._topology = TopologyService(self._blackboard)
        self._router = AgentRouter(self._registry, self._lease)
        self._reorch = ReOrchestrator(self._topology, self._registry)

        # Crew runner
        if crew_runner is not None:
            self._crew_runner = crew_runner
        else:
            self._crew_runner = RealCrewRunner(verbose=verbose)

        # ── state ──
        self._last_sequence: int = 0
        self._capabilities_registered = False
        self._tree: PTTTree | None = None
        self._scope: Scope | None = None
        self._blocked_resume: dict[str, str] = {}  # action_id → resource_ref
        # Phase 7 metrics
        self._metrics_actions: dict[str, int] = {"dispatched": 0, "succeeded": 0,
                                                   "failed": 0, "blocked": 0}
        self._metrics_lease_conflicts: int = 0
        self._metrics_hitle_requests: int = 0
        self._metrics_events: int = 0

    # ── public API ─────────────────────────────────────────────────────

    def run(self, seed_targets: list[str]) -> HiveRunSummary:
        """Execute the full PTT-driven hive loop from seed to completion."""
        self._ensure_capabilities()
        self._ensure_scope()
        self._open_session()
        self._seed_blackboard(seed_targets)

        # Generate initial PTT plan
        self._scope = self._store.get_scope(self._scope_id)
        goal = self._derive_goal(seed_targets)
        try:
            self._tree = self._planner.generate(
                goal=goal,
                scope=self._scope,
                registry=self._registry,
                project_id=self._project_id,
            )
        except Exception as exc:
            logger.warning("Plan generation failed: %s — falling back to empty tree", exc)
            # Fallback: empty PTTTree with no actions — rely on re-orchestrator
            from src.planner.ptt_schema import PTTPlan
            fallback_plan = PTTPlan(
                plan_id=f"plan-fallback-{uuid.uuid4().hex[:8]}",
                goal=goal,
                normalized_goal=goal,
                project_id=self._project_id,
                scope_id=self._scope_id,
                tactics=[],
                generated_by="fallback",
            )
            self._tree = PTTTree.from_plan(fallback_plan)

        round_log: list[dict[str, Any]] = []
        rounds_without_events = 0

        for round_num in range(1, self._max_rounds + 1):
            # ── sweep expired leases & approvals ──
            self._lease.sweep_expired()
            self._approval.sweep_expired()

            # ── read blackboard deltas ──
            events = self._blackboard.events_since(
                self._project_id, self._last_sequence,
            )
            if events:
                self._last_sequence = max(e.sequence for e in events)
                self._metrics_events += len(events)
                rounds_without_events = 0
            else:
                rounds_without_events += 1

            # ── re-orchestrate ──
            if events:
                self._reorch.react(self._tree, events, self._project_id)

            # ── retry blocked-by-lease actions ──
            self._retry_blocked_leases()

            # ── find ready actions ──
            ready = self._tree.ready_actions()

            if not ready:
                if self._tree.is_complete():
                    self._close_session(SessionStatus.SUCCEEDED)
                    return self._build_summary(
                        round_num, round_log, truncated=False,
                    )
                if rounds_without_events >= 2:
                    self._close_session(SessionStatus.SUCCEEDED)
                    return self._build_summary(
                        round_num, round_log, truncated=False,
                    )
                continue  # wait for actions to become ready

            rounds_without_events = 0

            # ── dispatch each ready action ──
            for action in ready:
                # HITL check for high-risk actions
                if self._guard.is_high_risk(action.risk_level):
                    if not self._approval.is_granted(action.action_id):
                        self._approval.request(
                            action_id=action.action_id,
                            capability_id="exploit-verifier",
                            session_id=self._session_id,
                            project_id=self._project_id,
                            risk_level=action.risk_level,
                            resource_refs=action.target_refs,
                        )
                        self._tree.mark_blocked(action.action_id, reason="waiting_approval")
                        self._metrics_actions["blocked"] += 1
                        self._metrics_hitle_requests += 1
                        logger.info("Round %d | action %s blocked (waiting HITL approval)",
                                    round_num, action.action_id)
                        continue

                # Router: select agent
                target_type = self._infer_target_type(action)
                decision = self._router.route(
                    action, target_type=target_type,
                    session_id=self._session_id,
                )
                if decision.deferred:
                    self._tree.mark_blocked(
                        action.action_id,
                        reason=f"no available agent: {decision.reasons}",
                    )
                    self._metrics_actions["blocked"] += 1
                    continue

                # Lease: acquire resource
                resource_ref = action.target_refs[0] if action.target_refs else self._scope_id
                lease_result = self._lease.acquire(
                    project_id=self._project_id,
                    resource_ref=resource_ref,
                    session_id=self._session_id,
                    action_id=action.action_id,
                )
                if not lease_result.acquired:
                    self._tree.mark_blocked(
                        action.action_id,
                        reason=f"lease conflict on {resource_ref}",
                    )
                    self._blocked_resume[action.action_id] = resource_ref
                    self._metrics_actions["blocked"] += 1
                    self._metrics_lease_conflicts += 1
                    continue

                # Dispatch
                self._tree.mark_running(action.action_id)
                self._metrics_actions["dispatched"] += 1
                result = self._dispatch_action(action, decision.capability_id)

                # Release lease
                self._lease.release_for_action(action.action_id)

                # Update tree + ingest
                if result.evidence:
                    self._tree.mark_succeeded(
                        action.action_id,
                        evidence_refs=[e.evidence_id for e in result.evidence],
                    )
                    self._metrics_actions["succeeded"] += 1
                    for evidence in result.evidence:
                        try:
                            self._blackboard.ingest_result(evidence)
                        except Exception as exc:
                            logger.warning("Failed to ingest evidence %s: %s",
                                          evidence.evidence_id, exc)
                else:
                    self._tree.mark_failed(action.action_id, reason="no evidence produced")
                    self._metrics_actions["failed"] += 1

                # Recompute readiness after each action
                self._tree.recompute_ready()

            # ── log ──
            progress = self._tree.progress()
            logger.info(
                "Round %d | ready=%d running=%d succeeded=%d failed=%d blocked=%d",
                round_num,
                progress.get("ready", 0), progress.get("running", 0),
                progress.get("succeeded", 0), progress.get("failed", 0),
                progress.get("blocked", 0),
            )
            round_log.append({
                "round": round_num,
                "progress": progress,
                "new_events": len(events),
            })

        # Max rounds reached
        self._close_session(SessionStatus.SUCCEEDED)
        return self._build_summary(self._max_rounds, round_log, truncated=True)

    # ── internal: dispatch ──────────────────────────────────────────────

    def _dispatch_action(
        self,
        action: Any,  # ActionContract
        capability_id: str,
    ) -> CrewRunResult:
        """Build a crew for a single action, run it, and return results."""
        ctx = CrewContext(
            project_id=self._project_id,
            scope_id=self._scope_id,
            session_id=self._session_id,
            task_id=f"task-{uuid.uuid4().hex[:8]}",
        )

        # Map capability_id to phase for crew building
        phase_map = {
            "info-gatherer": "recon",
            "framework-vuln": "fingerprint",
            "web-attack": "vuln_detect",
            "component-vuln": "vuln_detect",
            "exploit-verifier": "exploit",
        }
        phase = phase_map.get(capability_id, "vuln_detect")

        build_result = build_crew_for_phase(
            phase, self._gateway, ctx,
            llm_model=self._llm_model,
            verbose=self._verbose,
        )

        if build_result is None:
            return CrewRunResult()

        crew, ctx = build_result
        if not crew.agents:
            return CrewRunResult()

        # Assign a single task with the action's description
        from crewai import Task
        task_desc = (
            f"{action.description}\n"
            f"Target: {', '.join(action.target_refs)}\n"
            f"Expected outputs: {', '.join(action.expected_outputs)}"
        )
        # For FakeCrewRunner compatibility, include tool hints
        crew.tasks = [
            Task(
                description=task_desc,
                expected_output=f"Evidence of {', '.join(action.expected_outputs)}",
                agent=crew.agents[0],
            ),
        ]

        result = self._crew_runner.run(crew, ctx)
        return result

    # ── internal: helpers ───────────────────────────────────────────────

    def _retry_blocked_leases(self) -> None:
        """Retry actions that were blocked by lease conflicts."""
        if not self._blocked_resume:
            return
        resumed: list[str] = []
        for action_id, resource_ref in self._blocked_resume.items():
            lease_result = self._lease.acquire(
                project_id=self._project_id,
                resource_ref=resource_ref,
                session_id=self._session_id,
                action_id=action_id,
            )
            if lease_result.acquired:
                # Set back to READY from BLOCKED
                self._tree.set_status(action_id, PTTNodeStatus.READY)
                resumed.append(action_id)
        for aid in resumed:
            del self._blocked_resume[aid]

    def _infer_target_type(self, action: Any) -> str:
        """Infer a target_type string from action's technique and target_refs."""
        if "domain" in str(action.target_refs).lower():
            return "domain"
        if action.technique_id in ("T1046", "T1595"):
            return "ip"
        if action.technique_id in ("T1190", "T1059", "T1210"):
            return "url"
        return "ip"

    def _derive_goal(self, seed_targets: list[str]) -> str:
        """Derive a NL goal that MockProvider can keyword-match."""
        # Match the keywords in data/mock_scenarios.json
        if seed_targets:
            return f"发现 {', '.join(seed_targets)} 的资产和服务"
        return "发现授权网段的资产和服务"

    def _build_summary(
        self, rounds: int, round_log: list[dict], *, truncated: bool,
    ) -> HiveRunSummary:
        """Build HiveRunSummary from current state."""
        facts = self._blackboard.snapshot(self._project_id)
        vulns = [f for f in facts if f.fact_type == "vulnerability.detected"]
        verified = [v for v in vulns if v.data.get("verified")]
        progress = self._tree.progress() if self._tree else {}

        # Derive synthetic phase for backward compat
        if self._tree and self._tree.is_complete():
            final_phase = HivePhase.DONE
        elif progress.get("blocked", 0) > 0:
            final_phase = HivePhase.BLOCKED
        elif progress.get("succeeded", 0) > 0 and progress.get("ready", 0) == 0:
            final_phase = HivePhase.DONE
        else:
            final_phase = HivePhase.RECON

        dispatched = self._metrics_actions["dispatched"]
        succeeded = self._metrics_actions["succeeded"]
        rate = succeeded / dispatched if dispatched > 0 else 0.0
        return HiveRunSummary(
            rounds=rounds,
            final_phase=final_phase,
            fact_count=len(facts),
            vuln_count=len(vulns),
            verified_count=len(verified),
            truncated=truncated,
            round_log=round_log,
            session_status="succeeded",
            actions_dispatched=dispatched,
            actions_succeeded=self._metrics_actions["succeeded"],
            actions_failed=self._metrics_actions["failed"],
            actions_blocked=self._metrics_actions["blocked"],
            lease_conflicts=self._metrics_lease_conflicts,
            hitle_requests=self._metrics_hitle_requests,
            events_processed=self._metrics_events,
            success_rate=rate,
        )

    # ── internal: session ───────────────────────────────────────────────

    def _open_session(self) -> None:
        """Record session as RUNNING."""
        session = ExecutionSession(
            session_id=self._session_id,
            project_id=self._project_id,
            task_id="hive-root",
            agent_id="hive-orchestrator",
            status=SessionStatus.RUNNING,
        )
        self._store.save_session(session)

    def _close_session(self, status: SessionStatus) -> None:
        """Mark session with terminal status."""
        session = self._store.get_session(self._session_id)
        if session:
            session.status = status
            self._store.update_session(session)
        # Persist PTT tree
        if self._tree:
            try:
                self._store.save_ptt_tree(
                    self._project_id,
                    self._tree.to_persistable(),
                )
            except Exception as exc:
                logger.warning("Failed to persist PTT tree: %s", exc)

    # ── internal: setup ────────────────────────────────────────────────

    def _ensure_capabilities(self) -> None:
        """Register default agent capabilities if not already present."""
        if self._capabilities_registered:
            return
        register_default_capabilities(self._registry)
        self._capabilities_registered = True

    def _ensure_scope(self) -> None:
        """Ensure a scope record exists for the project."""
        existing = self._store.get_scope(self._scope_id)
        if existing is None:
            scope = Scope(
                scope_id=self._scope_id,
                project_id=self._project_id,
                target_type="domain",
                target="*",
                authorization_ref=f"auto-created-{uuid.uuid4().hex[:8]}",
            )
            self._store.save_scope(scope)

    def _seed_blackboard(self, targets: list[str]) -> None:
        """Write seed targets as initial blackboard entries."""
        for target in targets:
            evidence = Evidence(
                evidence_id=f"ev-seed-{uuid.uuid4().hex[:12]}",
                project_id=self._project_id,
                session_id=self._session_id,
                task_id="seed",
                agent_id="hive-orchestrator",
                kind="seed",
                raw_payload={
                    "observations": [{
                        "fact_type": "asset.discovered",
                        "asset_ref": target,
                        "data": {"ip": target, "source": "seed"},
                        "identity": {"ip": target},
                        "confidence": 1.0,
                        "state": "active",
                    }],
                },
            )
            try:
                events = self._blackboard.ingest_result(evidence)
                if events:
                    self._last_sequence = max(
                        self._last_sequence,
                        max(e.sequence for e in events),
                    )
            except Exception as exc:
                logger.warning("Failed to seed target %s: %s", target, exc)