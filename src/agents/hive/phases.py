"""Hive phase detector — reads blackboard facts and determines what phase the hive is in.

Pure functions: no side effects, no I/O. Takes facts + DAG stats → returns a HivePhase.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from src.agents.shared.attack_dag import AttackDAG, NodeStatus
from src.domain.models import BlackboardFact


class HivePhase(StrEnum):
    """Phases of the hive penetration testing lifecycle."""
    SEED = "seed"           # only seed targets, no recon done yet
    RECON = "recon"         # dispatch info-gatherer crew
    FINGERPRINT = "fingerprint"  # services exist, need tech fingerprinting
    VULN_DETECT = "vuln_detect"  # fingerprints exist, need vuln detection
    EXPLOIT = "exploit"     # unverified vulnerabilities exist
    DONE = "done"           # no more work to do
    BLOCKED = "blocked"     # waiting for approval or all paths blocked


@dataclass
class PhaseContext:
    """Snapshot of blackboard state used for phase detection."""
    phase: HivePhase
    services_count: int
    fingerprint_count: int
    vuln_count: int
    unverified_count: int
    dag_ready: int
    dag_blocked: int
    dag_total: int
    reason: str = ""


# ── fact-type accessors ────────────────────────────────────────────────

def _facts_of_type(facts: list[BlackboardFact], fact_type: str) -> list[BlackboardFact]:
    return [f for f in facts if f.fact_type == fact_type]


def _facts_with_field(facts: list[BlackboardFact], key: str, value: object = None) -> list[BlackboardFact]:
    """Filter facts whose data dict contains a key (and optionally a specific value)."""
    result = []
    for f in facts:
        if key in f.data:
            if value is None or f.data.get(key) == value:
                result.append(f)
    return result


# ── phase detection ────────────────────────────────────────────────────

def detect_phase(
    facts: list[BlackboardFact],
    dag: AttackDAG | None = None,
    *,
    no_new_events_rounds: int = 0,
) -> PhaseContext:
    """Determine the current hive phase from blackboard facts and DAG state.

    Args:
        facts: All current blackboard facts for the project.
        dag: Optional AttackDAG for readiness / blocked counts.
        no_new_events_rounds: Number of consecutive rounds with no new events.

    Returns a PhaseContext with the detected phase and supporting statistics.
    """
    # Count facts by type
    services = _facts_of_type(facts, "service.exposed")
    fingerprints = _facts_of_type(facts, "fingerprint.detected")
    vulnerabilities = _facts_of_type(facts, "vulnerability.detected")
    unverified = [v for v in vulnerabilities if not v.data.get("verified")]

    services_count = len(services)
    fingerprint_count = len(fingerprints)
    vuln_count = len(vulnerabilities)
    unverified_count = len(unverified)

    # DAG stats
    dag_ready = 0
    dag_blocked = 0
    dag_total = 0
    if dag is not None:
        dag_ready = len(dag.ready_nodes())
        dag_blocked = len(dag.blocked_nodes())
        dag_total = len(dag.nodes)

    # ── decision tree ──────────────────────────────────────────────────

    # Stale: no progress for 2+ rounds
    if no_new_events_rounds >= 2:
        return PhaseContext(
            phase=HivePhase.DONE,
            services_count=services_count, fingerprint_count=fingerprint_count,
            vuln_count=vuln_count, unverified_count=unverified_count,
            dag_ready=dag_ready, dag_blocked=dag_blocked, dag_total=dag_total,
            reason=f"No new blackboard events for {no_new_events_rounds} rounds",
        )

    # No services at all → need recon
    if services_count == 0:
        return PhaseContext(
            phase=HivePhase.RECON,
            services_count=0, fingerprint_count=fingerprint_count,
            vuln_count=vuln_count, unverified_count=unverified_count,
            dag_ready=dag_ready, dag_blocked=dag_blocked, dag_total=dag_total,
            reason="No service.exposed facts — need information gathering",
        )

    # Services exist but no fingerprints → fingerprint phase
    if fingerprint_count == 0:
        return PhaseContext(
            phase=HivePhase.FINGERPRINT,
            services_count=services_count, fingerprint_count=0,
            vuln_count=vuln_count, unverified_count=unverified_count,
            dag_ready=dag_ready, dag_blocked=dag_blocked, dag_total=dag_total,
            reason=f"{services_count} service(s) exposed but no fingerprints — need tech detection",
        )

    # Fingerprints exist but no vulnerabilities → vuln detection
    if vuln_count == 0:
        return PhaseContext(
            phase=HivePhase.VULN_DETECT,
            services_count=services_count, fingerprint_count=fingerprint_count,
            vuln_count=0, unverified_count=0,
            dag_ready=dag_ready, dag_blocked=dag_blocked, dag_total=dag_total,
            reason=f"{fingerprint_count} fingerprint(s) detected — need vulnerability detection",
        )

    # Unverified vulnerabilities → exploit/verify
    if unverified_count > 0:
        return PhaseContext(
            phase=HivePhase.EXPLOIT,
            services_count=services_count, fingerprint_count=fingerprint_count,
            vuln_count=vuln_count, unverified_count=unverified_count,
            dag_ready=dag_ready, dag_blocked=dag_blocked, dag_total=dag_total,
            reason=f"{unverified_count} unverified vulnerability(s) — need exploitation/verification",
        )

    # DAG has ready nodes → still work to do
    if dag is not None and dag_ready > 0:
        return PhaseContext(
            phase=HivePhase.EXPLOIT,
            services_count=services_count, fingerprint_count=fingerprint_count,
            vuln_count=vuln_count, unverified_count=unverified_count,
            dag_ready=dag_ready, dag_blocked=dag_blocked, dag_total=dag_total,
            reason=f"{dag_ready} DAG node(s) ready — continue exploitation",
        )

    # DAG has only blocked nodes → blocked
    if dag is not None and dag_blocked > 0 and dag_ready == 0:
        return PhaseContext(
            phase=HivePhase.BLOCKED,
            services_count=services_count, fingerprint_count=fingerprint_count,
            vuln_count=vuln_count, unverified_count=unverified_count,
            dag_ready=0, dag_blocked=dag_blocked, dag_total=dag_total,
            reason=f"All {dag_blocked} remaining DAG node(s) blocked",
        )

    # All verified, no ready nodes → done
    return PhaseContext(
        phase=HivePhase.DONE,
        services_count=services_count, fingerprint_count=fingerprint_count,
        vuln_count=vuln_count, unverified_count=0,
        dag_ready=dag_ready, dag_blocked=dag_blocked, dag_total=dag_total,
        reason="All vulnerabilities verified — hive complete",
    )


def is_terminal(phase: HivePhase) -> bool:
    """True if the phase signals the hive should stop."""
    return phase in (HivePhase.DONE, HivePhase.BLOCKED)