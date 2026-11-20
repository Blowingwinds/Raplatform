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
from typing import Any, Callable

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

# Ports that are commonly HTTP(S) even when the banner probe reported "unknown".
_HTTP_PORT_HINTS: frozenset[int] = frozenset({
    80, 443, 3000, 4848, 5000, 7000, 8000, 8008, 8009, 8020,
    8080, 8088, 8282, 8443, 8484, 8585, 8888, 9000, 9090,
    9200, 9300, 10000,
})

# Scan order: web entrypoints first, then app servers, then data stores.
_PORT_PRIORITY: dict[int, int] = {
    80: 0, 443: 0, 8080: 1, 8009: 2, 8282: 3, 8484: 4,
    8585: 5, 8020: 6, 4848: 7, 9200: 8, 9300: 9,
}


_VERIFY_KEYWORDS = ("验证", "verify", "exploit", "利用", "confirmed")
_WEB_KEYWORDS = ("sqli", "xss", "ssrf", "ssti", "injection", "注入", "跨站", "web")


def _scan_priority(url: str) -> int:
    """Sort key for scan targets — lower is scanned first."""
    try:
        port = int(url.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return 99
    return _PORT_PRIORITY.get(port, 50)


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
        trace: Callable[[str], None] | None = None,
    ) -> None:
        self._store = store
        self._project_id = project_id
        self._scope_id = scope_id
        self._session_id = session_id
        self._llm_model = llm_model
        self._max_rounds = max_rounds
        self._verbose = verbose
        self._demo_mode = demo_mode
        self._trace = trace

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
        self._blocked_resume: dict[str, tuple[str, str | None]] = {}  # action_id → (resource_ref, capability_id)
        # Phase 7 metrics
        self._metrics_actions: dict[str, int] = {"dispatched": 0, "succeeded": 0,
                                                   "failed": 0, "blocked": 0}
        self._metrics_lease_conflicts: int = 0
        self._metrics_hitle_requests: int = 0
        self._metrics_events: int = 0
        # Concrete targets for the current run — used to resolve "*" refs
        # produced by the planner (wildcard = "everything in scope").
        self._seed_targets: list[str] = []

    # ── public API ─────────────────────────────────────────────────────

    def run(self, seed_targets: list[str], goal: str | None = None) -> HiveRunSummary:
        """Execute the full PTT-driven hive loop from seed to completion.

        *goal* is the natural-language intent handed to the planner.  When
        omitted it is derived from the seed targets (recon-only by default);
        pass e.g. "执行完整渗透测试" to plan recon + vuln detection + exploit.
        """
        self._seed_targets = list(seed_targets)
        self._ensure_capabilities()
        self._ensure_scope()
        self._open_session()
        self._seed_blackboard(seed_targets)

        # Generate initial PTT plan
        self._scope = self._store.get_scope(self._scope_id)
        goal = goal or self._derive_goal(seed_targets)
        try:
            self._tree = self._planner.generate(
                goal=goal,
                scope=self._scope,
                registry=self._registry,
                project_id=self._project_id,
            )
        except Exception as exc:
            logger.warning("Plan generation failed: %s — falling back to a minimal recon plan", exc)
            # Fallback: one合法最小侦察动作，保证蜂群仍能降级跑通
            # （PTTPlan 要求 tactics/techniques/actions 均非空，空计划会直接崩）
            from src.planner.ptt_schema import (
                ActionContract,
                PTTPlan,
                TacticNode,
                TechniqueNode,
            )
            fallback_target = seed_targets[0] if seed_targets else self._scope.target
            fallback_plan = PTTPlan(
                plan_id=f"plan-fallback-{uuid.uuid4().hex[:8]}",
                goal=goal,
                normalized_goal=goal,
                project_id=self._project_id,
                scope_id=self._scope_id,
                tactics=[
                    TacticNode(
                        tactic_id="reconnaissance",
                        name="Reconnaissance",
                        techniques=[
                            TechniqueNode(
                                technique_id="T1595",
                                name="Active Scanning",
                                actions=[
                                    ActionContract(
                                        action_id="act-fallback-scan",
                                        name="Fallback scan",
                                        description="规划失败时的降级侦察动作",
                                        technique_id="T1595",
                                        target_refs=[fallback_target],
                                        expected_outputs=["service.exposed"],
                                        risk_level="low",
                                        stop_conditions=["扫描完成"],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
                generated_by="fallback",
            )
            self._tree = PTTTree.from_plan(fallback_plan)

        round_log: list[dict[str, Any]] = []
        rounds_without_events = 0

        # Chain tactic order into implicit dependencies (see method docstring)
        self._chain_tactics_in_order()

        for round_num in range(1, self._max_rounds + 1):
            # ── sweep expired leases & approvals ──
            self._lease.sweep_expired()
            self._approval.sweep_expired()

            if self._trace:
                prog = self._tree.progress() if self._tree else {}
                self._emit_trace(
                    f"\n=== Round {round_num}/{self._max_rounds} ===  "
                    f"PTT total={prog.get('total', 0)} "
                    f"ready={prog.get('ready', 0)} running={prog.get('running', 0)} "
                    f"ok={prog.get('succeeded', 0)} fail={prog.get('failed', 0)} "
                    f"blocked={prog.get('blocked', 0)}"
                )

            # ── read blackboard deltas ──
            events = self._blackboard.events_since(
                self._project_id, self._last_sequence,
            )
            if events:
                self._last_sequence = max(e.sequence for e in events)
                self._metrics_events += len(events)
                rounds_without_events = 0
                if self._trace:
                    created = [
                        e.observation for e in events
                        if e.event_type == "fact.created" and e.observation is not None
                    ]
                    if created:
                        preview = ", ".join(
                            f"{f.fact_type}@{f.asset_ref}" for f in created[:8]
                        )
                        more = f" …+{len(created) - 8}" if len(created) > 8 else ""
                        self._emit_trace(
                            f"  [黑板] 新增 {len(created)} 条事实: {preview}{more}"
                        )
                    else:
                        self._emit_trace(f"  [黑板] 事件 {len(events)} 条（无新事实）")
            else:
                rounds_without_events += 1

            # ── re-orchestrate ──
            if events:
                nodes_before = set(self._tree.dynamic_nodes) if self._tree else set()
                statuses_before = dict(self._tree.node_states) if self._tree else {}

                self._reorch.react(self._tree, events, self._project_id)

                if self._trace and self._tree:
                    added = set(self._tree.dynamic_nodes) - nodes_before
                    if added:
                        names = []
                        for node_id in sorted(added)[:6]:
                            node = self._tree.dynamic_nodes[node_id]
                            names.append(
                                f"{node_id}({','.join(node.action.target_refs)})"
                            )
                        more = f" …+{len(added) - 6}" if len(added) > 6 else ""
                        self._emit_trace(
                            f"  [树] 动态追加 {len(added)} 个节点: {', '.join(names)}{more}"
                        )
                    pruned = [
                        aid for aid, st in self._tree.node_states.items()
                        if st == PTTNodeStatus.SKIPPED
                        and statuses_before.get(aid) != PTTNodeStatus.SKIPPED
                    ]
                    if pruned:
                        self._emit_trace(
                            f"  [树] 裁剪 {len(pruned)} 个节点: {', '.join(pruned[:6])}"
                        )

                # ── topology projection: persist network.relation facts ──
                try:
                    projected = self._topology.emit_relations(
                        self._project_id, session_id=self._session_id,
                    )
                    if self._trace and projected:
                        self._emit_trace(f"  [拓扑] 写入 {projected} 条 network.relation")
                except Exception as exc:
                    logger.warning("Topology projection failed: %s", exc)

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
                # The ready list is a round-start snapshot. An earlier failure in
                # this same loop can prune dependents to SKIPPED, so re-check the
                # live state before dispatching.
                live_status = self._tree.node_states.get(action.action_id)
                if live_status != PTTNodeStatus.READY:
                    if self._trace:
                        self._emit_trace(
                            f"  [跳过] {action.action_id} 已被裁剪（状态 {live_status}）"
                        )
                    continue

                # HITL check for high-risk actions (demo_mode auto-approves)
                if self._guard.needs_approval(action.risk_level):
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
                    prefer=self._preferred_capability(action),
                )
                if decision.deferred:
                    self._tree.mark_blocked(
                        action.action_id,
                        reason=f"no available agent: {decision.reasons}",
                    )
                    self._metrics_actions["blocked"] += 1
                    continue

                # Lease: acquire resource (target:port granularity)
                resource_ref = self._lease_resource_ref(action, self._seed_targets)
                lease_result = self._lease.acquire(
                    project_id=self._project_id,
                    resource_ref=resource_ref,
                    session_id=self._session_id,
                    action_id=action.action_id,
                    capability_id=decision.capability_id,
                )
                if not lease_result.acquired:
                    self._tree.mark_blocked(
                        action.action_id,
                        reason=f"lease conflict on {resource_ref}",
                    )
                    self._blocked_resume[action.action_id] = (resource_ref, decision.capability_id)
                    self._metrics_actions["blocked"] += 1
                    self._metrics_lease_conflicts += 1
                    continue

                # Dispatch
                self._tree.mark_running(action.action_id)
                self._metrics_actions["dispatched"] += 1
                if self._trace:
                    self._emit_trace(
                        f"  [调度] {action.action_id} → {decision.capability_id} "
                        f"(risk={str(action.risk_level)})"
                    )
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
                    if self._trace:
                        obs_total = sum(
                            len(e.raw_payload.get("observations", []) or [])
                            for e in result.evidence
                        )
                        self._emit_trace(
                            f"  [完成] {action.action_id} ✓ evidence={len(result.evidence)} "
                            f"observations={obs_total}"
                        )
                else:
                    self._tree.mark_failed(action.action_id, reason="no evidence produced")
                    self._metrics_actions["failed"] += 1
                    if self._trace:
                        self._emit_trace(f"  [失败] {action.action_id} ✗ 无 evidence")

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

            if self._trace:
                self._emit_trace(
                    f"  [轮末] ok={progress.get('succeeded', 0)} "
                    f"fail={progress.get('failed', 0)} "
                    f"blocked={progress.get('blocked', 0)} "
                    f"ready={progress.get('ready', 0)}"
                )

            # Persist the tree every round so external watchers see live state
            self._persist_tree()

        # Max rounds reached
        self._close_session(SessionStatus.SUCCEEDED)
        return self._build_summary(self._max_rounds, round_log, truncated=True)

    # ── internal: dispatch ──────────────────────────────────────────────

    def _emit_trace(self, message: str) -> None:
        """Send one trace line to the optional observer callback."""
        if self._trace is None:
            return
        try:
            self._trace(message)
        except Exception:  # noqa: BLE001 - observers must never break the run
            pass

    def _persist_tree(self) -> None:
        """Save the live tree so external watchers/CLI can read current state."""
        if not self._tree:
            return
        try:
            self._store.save_ptt_tree(
                self._project_id, self._tree.model_dump(mode="json"),
            )
        except Exception as exc:  # noqa: BLE001 - persistence is best-effort
            logger.debug("PTT tree persistence failed: %s", exc)

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
        hints = self._tool_hints(action, capability_id)
        hint_block = (
            "\n\nUse these tools in order:\n"
            + "\n".join(f"{i}. {h}" for i, h in enumerate(hints, 1))
            if hints else ""
        )
        task_desc = (
            f"{action.description}\n"
            f"Target: {', '.join(action.target_refs)}\n"
            f"Expected outputs: {', '.join(action.expected_outputs)}"
            f"{hint_block}"
        )
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
        for action_id, (resource_ref, capability_id) in self._blocked_resume.items():
            lease_result = self._lease.acquire(
                project_id=self._project_id,
                resource_ref=resource_ref,
                session_id=self._session_id,
                action_id=action_id,
                capability_id=capability_id,
            )
            if lease_result.acquired:
                # Set back to READY from BLOCKED
                self._tree.set_status(action_id, PTTNodeStatus.READY)
                resumed.append(action_id)
        for aid in resumed:
            del self._blocked_resume[aid]

    @staticmethod
    def _lease_resource_ref(action: Any, fallback_targets: list[str] | None = None) -> str:
        """Derive a port-level lease key from the action's first target ref.

        ``http://10.0.0.5:8080/x`` -> ``10.0.0.5:8080``
        ``10.0.0.5:22`` -> ``10.0.0.5:22`` (kept as-is)
        ``10.0.0.5`` -> ``10.0.0.5`` (target-level fallback)
        ``"*"`` or empty -> first of *fallback_targets* (concrete seed targets)
        """
        target_refs = [
            r for r in (getattr(action, "target_refs", None) or [])
            if r and r != "*"
        ]
        if not target_refs:
            target_refs = list(fallback_targets or [])
        target = target_refs[0] if target_refs else ""
        if not target:
            return "unscoped"
        if "://" in target:
            from urllib.parse import urlparse

            parsed = urlparse(target)
            host = parsed.hostname or target
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
            return f"{host}:{port}"
        return target

    def _preferred_capability(self, action: Any) -> str | None:
        """Prefer the capability whose tools actually produce this action's outputs.

        ATT&CK techniques overlap across capabilities (T1595 is claimed by
        info-gatherer, framework-vuln, web-attack and component-vuln), so
        technique-only routing sends vulnerability scans to the recon agent.
        Expected outputs plus the action description disambiguate.
        """
        outputs = set(getattr(action, "expected_outputs", None) or [])
        description = str(getattr(action, "description", "")).lower()
        risk = str(getattr(action, "risk_level", "")).lower()

        wants_vuln = bool(outputs & {"vulnerability.detected", "credential.validated"})
        wants_fp = "fingerprint.detected" in outputs

        if wants_vuln:
            high_risk = risk in ("high", "critical")
            wants_verify = (
                any(k in description for k in _VERIFY_KEYWORDS)
                or ("credential.validated" in outputs and high_risk)
            )
            # exploit-verifier is HIGH risk — only usable when the action allows it
            if wants_verify and high_risk:
                return "exploit-verifier"
            if any(k in description for k in _WEB_KEYWORDS):
                return "web-attack"
            # Default: framework-vuln carries the CVE template batch, which is
            # where metasploitable-style findings come from.
            return "framework-vuln"

        if wants_fp:
            return "framework-vuln"

        if outputs & {"service.exposed", "asset.discovered", "subdomain.discovered"}:
            return "info-gatherer"

        return None

    def _resolve_targets(self, action: Any) -> list[str]:
        """Resolve planner wildcard target refs (``"*"``) to concrete seed targets."""
        refs = [
            r for r in (getattr(action, "target_refs", None) or [])
            if r and r != "*"
        ]
        if refs:
            return refs
        return list(self._seed_targets)

    def _chain_tactics_in_order(self) -> None:
        """Give actions implicit dependencies on the preceding tactic's actions.

        Planners typically leave ``depends_on`` empty, which makes every action
        READY in round 1 — scans then fire before reconnaissance produced any
        service list, so multi-port expansion has nothing to expand from.
        Chaining tactic order makes reconnaissance finish first, and keeps the
        PTT execution order faithful to the plan.
        """
        tree = getattr(self, "_tree", None)
        if tree is None:
            return

        previous_ids: list[str] = []
        for tactic in tree.plan.tactics:
            actions = [
                act for tech in tactic.techniques for act in tech.actions
            ]
            if previous_ids:
                for act in actions:
                    if not act.depends_on:
                        act.depends_on = list(previous_ids)
            previous_ids.extend(act.action_id for act in actions)

        tree.recompute_ready()

    def _tool_hints(self, action: Any, capability_id: str | None = None) -> list[str]:
        """FakeCrewRunner-compatible tool calls derived from the routed capability.

        The runner extracts ``tool_name(k='v')`` patterns from the task text,
        so an action description without hints produces no tool calls and no
        evidence.  Hints mirror what a real LLM would choose for the same
        capability; ``"*"`` target refs resolve to this run's seed targets.
        """
        targets = self._resolve_targets(action)
        if not targets:
            return []
        target = targets[0]

        host, url = self._host_and_url(target)
        outputs = set(getattr(action, "expected_outputs", []) or [])
        description = str(getattr(action, "description", "")).lower()
        hints: list[str] = []

        cap = capability_id or ""
        is_recon = cap == "info-gatherer" or (
            not cap and outputs & {"service.exposed", "asset.discovered", "subdomain.discovered"}
        )

        if is_recon:
            # Precise per-output tooling: recon actions on the same host used to
            # re-run scan_ports + ffuf each time (4 identical passes per round).
            # service.exposed / asset.discovered -> port scan
            # subdomain.discovered / asset.discovered -> DNS (+ subdomain enum)
            if outputs & {"service.exposed", "asset.discovered"}:
                hints.append(f"scan_ports(target='{host}')")
            if outputs & {"asset.discovered", "subdomain.discovered"}:
                hints.append(f"resolve_dns(hostname='{host}')")
            if (
                outputs & {"asset.discovered", "subdomain.discovered"}
                and not self._is_ipv4(host)
            ):
                hints.append(f"enumerate_subdomains(domain='{host}')")
            if not hints:
                # No declared outputs to key off — fall back to a light recon pass
                hints.append(f"scan_ports(target='{host}')")
                hints.append(f"discover_endpoints(base_url='{url}')")
            return list(dict.fromkeys(hints))

        if cap in ("framework-vuln", "component-vuln"):
            for scan_url in self._scan_targets(url)[:3]:
                hints.append(f"scan_fingerprints(target='{scan_url}')")
                hints.append(
                    f"scan_vulnerabilities(target='{scan_url}', "
                    f"tags='cve,exposures,misconfig,default-login,auth-bypass')"
                )
            return list(dict.fromkeys(hints))

        if cap == "web-attack":
            # CVE coverage is handled by framework/component-vuln; keep this
            # call lightweight so multiple services fit the time budget.
            for scan_url in self._scan_targets(url)[:3]:
                hints.append(
                    f"scan_vulnerabilities(target='{scan_url}', "
                    f"tags='sqli,xss,ssrf,ssti,lfi,rfi,redirect,cors,file-upload')"
                )
            return list(dict.fromkeys(hints))

        if cap == "exploit-verifier":
            hints.append(f"verify_sqli(url='{url}')")
            return list(dict.fromkeys(hints))

        # No capability (direct dispatch in tests) — fall back to output inference
        if "fingerprint.detected" in outputs:
            hints.append(f"scan_fingerprints(target='{url}')")
        if "vulnerability.detected" in outputs:
            hints.append(f"scan_vulnerabilities(target='{url}')")
        if "verif" in description or "验证" in description:
            hints.append(f"verify_sqli(url='{url}')")
        return list(dict.fromkeys(hints))

    def _scan_targets(self, fallback: str) -> list[str]:
        """URLs to scan: every discovered web-ish service, ordered by priority.

        The planner only knows the seed target, so an action's own URL covers
        one port at most.  Expanding here makes the executed scan cover every
        service the recon phase found (8009 AJP, 9200 ElasticSearch, 8282
        Tomcat, ...), while keeping a hard cap on how many get scanned.
        """
        blackboard = getattr(self, "_blackboard", None)
        if blackboard is None:
            return [fallback]

        try:
            facts = blackboard.snapshot(self._project_id)
        except Exception:  # noqa: BLE001 - fall back to the action target
            return [fallback]

        urls: list[str] = []
        for fact in facts:
            if fact.fact_type != "service.exposed":
                continue
            port = fact.data.get("port")
            name = str(fact.data.get("service_name") or "").lower()
            if not isinstance(port, int):
                continue
            if name in ("https", "https-alt") or port == 443:
                urls.append(f"https://{fact.asset_ref}:{port}")
            elif name in ("http", "http-proxy", "http-alt") or port in _HTTP_PORT_HINTS:
                urls.append(f"http://{fact.asset_ref}:{port}")

        urls = list(dict.fromkeys(urls))
        urls.sort(key=_scan_priority)
        return urls[:3] or [fallback]

    @staticmethod
    def _host_and_url(target: str) -> tuple[str, str]:
        """Split a target ref into (host, http_url) for tool hints."""
        if "://" in target:
            from urllib.parse import urlparse

            parsed = urlparse(target)
            return parsed.hostname or target, target
        if ":" in target and target.rsplit(":", 1)[-1].isdigit():
            return target.rsplit(":", 1)[0], f"http://{target}"
        return target, f"http://{target}"

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        import ipaddress

        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False

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
        """Record session as RUNNING — idempotent when the same session is re-run."""
        session = self._store.get_session(self._session_id)
        if session is None:
            session = ExecutionSession(
                session_id=self._session_id,
                project_id=self._project_id,
                task_id="hive-root",
                agent_id="hive-orchestrator",
                status=SessionStatus.RUNNING,
            )
            self._store.save_session(session)
        else:
            session.status = SessionStatus.RUNNING
            self._store.update_session(session)

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