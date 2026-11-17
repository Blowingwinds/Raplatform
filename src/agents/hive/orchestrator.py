"""HiveOrchestrator — the Queen Bee decision loop.

The orchestrator reads the blackboard, detects the current phase, dispatches
the appropriate worker bee crew, ingests results back into the blackboard,
and loops until no more work remains or the max round limit is reached.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.agents.hive.crews import (
    CrewContext,
    CrewRunResult,
    FakeCrewRunner,
    RealCrewRunner,
    build_crew_for_phase,
)
from src.agents.hive.phases import HivePhase, PhaseContext, detect_phase, is_terminal
from src.agents.hive.tasks import (
    make_exploit_tasks,
    make_fingerprint_tasks,
    make_info_tasks,
    make_vuln_tasks,
)
from src.agents.info_gatherer.dns_tools import enumerate_subdomains, resolve_dns
from src.agents.info_gatherer.port_scanner import scan_ports
from src.agents.info_gatherer.web_tools import discover_endpoints
from src.agents.registry import AgentRegistry
from src.agents.shared.nuclei_runner import scan_fingerprints, scan_vulnerabilities
from src.agents.shared.python_exec import execute as python_exec
from src.agents.shared.sqlmap_runner import verify_sqli
from src.agents.shared.attack_dag import AttackDAG
from src.blackboard.service import BlackboardService
from src.domain.models import (
    AgentCapability,
    Evidence,
    FactState,
    RiskLevel,
    Scope,
)
from src.domain.storage import SQLiteStore
from src.mcp.gateway import MCPGateway
from src.mcp.models import CallResult, CallStatus
from src.mcp.transport import InProcessTransport, Transport
from src.policy.guard import PolicyGuard

logger = logging.getLogger("hive.orchestrator")

# ── default agent capabilities ──────────────────────────────────────────

_DEFAULT_CAPABILITIES: list[dict[str, Any]] = [
    {
        "capability_id": "info-gatherer",
        "name": "Information Gatherer",
        "techniques": ["T1046", "T1592", "T1590", "T1595"],
        "target_types": ["ip", "domain", "url", "hostname"],
        "input_schema": "info_gatherer_input.schema.json",
        "output_schema": "info_gatherer_output.schema.json",
        "risk_level": "low",
        "side_effects": [],
        "max_concurrency": 4,
    },
    {
        "capability_id": "framework-vuln",
        "name": "Framework Vulnerability Specialist",
        "techniques": ["T1190", "T1595", "T1210"],
        "target_types": ["url", "service", "hostname"],
        "input_schema": "framework_vuln_input.schema.json",
        "output_schema": "framework_vuln_output.schema.json",
        "risk_level": "medium",
        "side_effects": ["may trigger WAF alerts"],
        "max_concurrency": 1,
    },
    {
        "capability_id": "web-attack",
        "name": "Web Attack Specialist",
        "techniques": ["T1190", "T1595", "T1059"],
        "target_types": ["url", "service", "endpoint"],
        "input_schema": "web_attack_input.schema.json",
        "output_schema": "web_attack_output.schema.json",
        "risk_level": "high",
        "side_effects": ["may trigger WAF alerts", "active probing"],
        "max_concurrency": 1,
    },
    {
        "capability_id": "component-vuln",
        "name": "Component Vulnerability Specialist",
        "techniques": ["T1190", "T1595", "T1210"],
        "target_types": ["url", "service", "component"],
        "input_schema": "component_vuln_input.schema.json",
        "output_schema": "component_vuln_output.schema.json",
        "risk_level": "medium",
        "side_effects": ["may trigger WAF alerts"],
        "max_concurrency": 1,
    },
    {
        "capability_id": "exploit-verifier",
        "name": "Exploit Verifier",
        "techniques": ["T1190", "T1059", "T1210"],
        "target_types": ["url", "endpoint", "service"],
        "input_schema": "exploit_verifier_input.schema.json",
        "output_schema": "exploit_verifier_output.schema.json",
        "risk_level": "high",
        "side_effects": ["active exploitation", "may modify target state"],
        "max_concurrency": 1,
    },
]


# ── run summary ─────────────────────────────────────────────────────────

@dataclass
class HiveRunSummary:
    """Result of a complete hive orchestration run."""
    rounds: int
    final_phase: HivePhase
    fact_count: int
    vuln_count: int
    verified_count: int
    truncated: bool
    blocked_reasons: list[str] = field(default_factory=list)
    round_log: list[dict[str, Any]] = field(default_factory=list)


# ── orchestrator ────────────────────────────────────────────────────────

class HiveOrchestrator:
    """Queen Bee — orchestrates the penetration testing lifecycle.

    Reads the blackboard, detects phases, dispatches worker crews, ingests
    results, and loops until completion.

    Usage::

        store = SQLiteStore(":memory:")
        orch = HiveOrchestrator(
            store=store,
            project_id="proj-1",
            scope_id="scope-1",
            session_id="sess-1",
            llm_model="gpt-4o",
            max_rounds=8,
        )
        summary = orch.run(seed_targets=["example.com"])
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
        # Test injection points
        transport: Transport | None = None,
        crew_runner: Any = None,  # RealCrewRunner | FakeCrewRunner
    ) -> None:
        self._store = store
        self._project_id = project_id
        self._scope_id = scope_id
        self._session_id = session_id
        self._llm_model = llm_model
        self._max_rounds = max_rounds
        self._verbose = verbose

        # ── wiring ──
        self._registry = AgentRegistry(store)
        self._guard = PolicyGuard(store)
        self._blackboard = BlackboardService(store)

        # Transport: use InProcessTransport if not injected, with real tool handlers
        if transport is not None:
            self._transport = transport
        else:
            inproc = InProcessTransport()
            # Info-gatherer tools (registered by tool name for routing)
            inproc.register("scan_ports", scan_ports)
            inproc.register("resolve_dns", resolve_dns)
            inproc.register("enumerate_subdomains", enumerate_subdomains)
            inproc.register("discover_endpoints", discover_endpoints)
            # Vuln-detector tools
            inproc.register("scan_fingerprints", scan_fingerprints)
            inproc.register("scan_vulnerabilities", scan_vulnerabilities)
            inproc.register("execute_python", python_exec)
            # Exploit-verifier tools
            inproc.register("verify_sqli", verify_sqli)
            self._transport = inproc

        self._gateway = MCPGateway(self._registry, self._guard, self._transport)

        # Crew runner: real (LLM) or fake (test)
        if crew_runner is not None:
            self._crew_runner = crew_runner
        else:
            self._crew_runner = RealCrewRunner(verbose=verbose)

        # ── state ──
        self._last_sequence: int = 0
        self._dag = AttackDAG(project_id=project_id)
        self._capabilities_registered = False

    # ── public API ─────────────────────────────────────────────────────

    def run(self, seed_targets: list[str]) -> HiveRunSummary:
        """Execute the full hive loop from seed to completion."""
        self._ensure_capabilities()
        self._ensure_scope()
        self._seed_blackboard(seed_targets)

        round_log: list[dict[str, Any]] = []
        rounds_without_events = 0

        for round_num in range(1, self._max_rounds + 1):
            # ── read blackboard ──
            events = self._blackboard.events_since(self._project_id, self._last_sequence)
            facts = self._blackboard.snapshot(self._project_id)

            # ── update DAG ──
            for event in events:
                if event.observation is not None and event.event_type == "fact.created":
                    fact_dict = event.observation.model_dump(mode="json")
                    self._dag.on_fact_added(fact_dict)
                elif event.observation is not None and event.event_type == "fact.updated":
                    fact_dict = event.observation.model_dump(mode="json")
                    self._dag.on_fact_updated(fact_dict)

            if events:
                self._last_sequence = max(e.sequence for e in events)
                rounds_without_events = 0
            else:
                rounds_without_events += 1

            # ── detect phase ──
            phase_ctx = detect_phase(facts, self._dag, no_new_events_rounds=rounds_without_events)

            logger.info(
                "Round %d | phase=%s | services=%d fingerprints=%d vulns=%d unverified=%d | dag ready=%d blocked=%d",
                round_num, phase_ctx.phase.value,
                phase_ctx.services_count, phase_ctx.fingerprint_count,
                phase_ctx.vuln_count, phase_ctx.unverified_count,
                phase_ctx.dag_ready, phase_ctx.dag_blocked,
            )

            # ── check terminal ──
            if is_terminal(phase_ctx.phase):
                round_log.append({
                    "round": round_num, "phase": phase_ctx.phase.value,
                    "reason": phase_ctx.reason, "new_events": len(events),
                })
                return HiveRunSummary(
                    rounds=round_num,
                    final_phase=phase_ctx.phase,
                    fact_count=len(facts),
                    vuln_count=phase_ctx.vuln_count,
                    verified_count=phase_ctx.vuln_count - phase_ctx.unverified_count,
                    truncated=False,
                    blocked_reasons=[phase_ctx.reason] if phase_ctx.phase == HivePhase.BLOCKED else [],
                    round_log=round_log,
                )

            # ── dispatch ──
            result = self._run_phase(phase_ctx.phase, facts, seed_targets)
            round_log.append({
                "round": round_num, "phase": phase_ctx.phase.value,
                "evidence_count": len(result.evidence),
                "output_len": len(result.output),
            })

            if not result.evidence:
                rounds_without_events += 1

        # Max rounds reached
        facts = self._blackboard.snapshot(self._project_id)
        vulns = [f for f in facts if f.fact_type == "vulnerability.detected"]
        verified = [v for v in vulns if v.data.get("verified")]
        return HiveRunSummary(
            rounds=self._max_rounds,
            final_phase=HivePhase.DONE,
            fact_count=len(facts),
            vuln_count=len(vulns),
            verified_count=len(verified),
            truncated=True,
            round_log=round_log,
        )

    # ── internal: phase execution ──────────────────────────────────────

    def _run_phase(
        self,
        phase: HivePhase,
        facts: list,
        seed_targets: list[str],
    ) -> CrewRunResult:
        """Build a crew for the phase, create tasks, run, and ingest results."""
        ctx = CrewContext(
            project_id=self._project_id,
            scope_id=self._scope_id,
            session_id=self._session_id,
            task_id=f"task-{uuid.uuid4().hex[:8]}",
        )

        build_result = build_crew_for_phase(
            phase.value,
            self._gateway,
            ctx,
            llm_model=self._llm_model,
            verbose=self._verbose,
        )

        if build_result is None:
            return CrewRunResult()

        crew, ctx = build_result

        if not crew.agents:
            return CrewRunResult()

        # ── build tasks dynamically ──
        if phase == HivePhase.RECON or phase == HivePhase.SEED:
            crew.tasks = make_info_tasks(ctx, facts, crew.agents[0], seed_targets)
        elif phase == HivePhase.FINGERPRINT:
            # Just fingerprinting — use the framework agent
            crew.tasks = make_fingerprint_tasks(ctx, facts, crew.agents[0])
        elif phase == HivePhase.VULN_DETECT:
            if len(crew.agents) >= 3:
                crew.tasks = make_vuln_tasks(
                    ctx, facts,
                    crew.agents[0], crew.agents[1], crew.agents[2],
                )
            else:
                crew.tasks = make_fingerprint_tasks(ctx, facts, crew.agents[0])
        elif phase == HivePhase.EXPLOIT:
            crew.tasks = make_exploit_tasks(ctx, facts, crew.agents[0])

        if not crew.tasks:
            return CrewRunResult()

        # ── run ──
        result = self._crew_runner.run(crew, ctx)

        # ── ingest results into blackboard ──
        for evidence in result.evidence:
            try:
                self._blackboard.ingest_result(evidence)
            except Exception as exc:
                logger.warning("Failed to ingest evidence %s: %s", evidence.evidence_id, exc)

        return result

    # ── internal: setup ────────────────────────────────────────────────

    def _ensure_capabilities(self) -> None:
        """Register default agent capabilities if not already present."""
        if self._capabilities_registered:
            return
        for cap_dict in _DEFAULT_CAPABILITIES:
            cap_id = cap_dict["capability_id"]
            if self._registry.get(cap_id) is None:
                cap = AgentCapability(
                    capability_id=cap_id,
                    name=cap_dict["name"],
                    techniques=cap_dict["techniques"],
                    target_types=cap_dict["target_types"],
                    input_schema=cap_dict["input_schema"],
                    output_schema=cap_dict["output_schema"],
                    risk_level=RiskLevel(cap_dict["risk_level"]),
                    side_effects=cap_dict.get("side_effects", []),
                    max_concurrency=cap_dict.get("max_concurrency", 1),
                )
                self._registry.register(cap)
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