"""Tests for the TopologyService / TopologyGraph module."""

import uuid

from src.blackboard.service import BlackboardService
from src.blackboard.topology import TopologyGraph, TopologyNode, TopologyService
from src.domain.models import Evidence
from src.domain.storage import SQLiteStore

PROJECT_ID = "project-topo"
SESSION_ID = "session-topo"
AGENT_ID = "recon-agent"


def _ingest(service: BlackboardService, observations: list[dict], evidence_id: str | None = None) -> None:
    """Seed facts via the Evidence + ingest_result pattern (mirrors orchestrator._seed_blackboard)."""
    evidence = Evidence(
        evidence_id=evidence_id or f"ev-{uuid.uuid4().hex[:12]}",
        project_id=PROJECT_ID,
        session_id=SESSION_ID,
        task_id="task-topo",
        agent_id=AGENT_ID,
        kind="mcp.response",
        raw_payload={"observations": observations},
    )
    service.ingest_result(evidence)


def _service_observation(asset_ref: str, protocol: str, port: int, service: str = "nginx") -> dict:
    return {
        "fact_type": "service.exposed",
        "asset_ref": asset_ref,
        "data": {"protocol": protocol, "port": port, "service": service},
        "identity": {"protocol": protocol, "port": port},
        "confidence": 0.9,
        "state": "active",
    }


def _fingerprint_observation(asset_ref: str, service_ref: str, product: str = "nginx/1.25") -> dict:
    return {
        "fact_type": "fingerprint.detected",
        "asset_ref": asset_ref,
        "data": {"service_ref": service_ref, "product": product},
        "identity": {"service_ref": service_ref},
        "confidence": 0.8,
        "state": "active",
    }


def _make_service() -> BlackboardService:
    return BlackboardService(SQLiteStore(":memory:"))


# ──────────────────────────────────────────────────────────────────────────
# Test 1: Build graph from seed facts, verify nodes and edges
# ──────────────────────────────────────────────────────────────────────────


def test_build_graph_creates_asset_and_service_nodes_with_edges():
    service = _make_service()
    _ingest(service, [
        {
            "fact_type": "asset.discovered",
            "asset_ref": "asset:10.0.0.1",
            "data": {"ip": "10.0.0.1", "source": "seed"},
            "identity": {"ip": "10.0.0.1"},
            "confidence": 1.0,
            "state": "active",
        },
        _service_observation("asset:10.0.0.1", "tcp", 443),
    ])

    topo = TopologyService(service).build(PROJECT_ID)

    # asset node exists
    assert "asset:10.0.0.1" in topo.nodes
    asset_node = topo.nodes["asset:10.0.0.1"]
    assert isinstance(asset_node, TopologyNode)
    assert asset_node.kind == "asset"
    assert asset_node.parent_ref is None
    assert len(asset_node.facts) == 2  # asset.discovered + service.exposed

    # service node keyed by protocol:port
    assert "tcp:443" in topo.nodes
    svc_node = topo.nodes["tcp:443"]
    assert svc_node.kind == "service"
    assert svc_node.fact_type == "service.exposed"
    assert svc_node.parent_ref == "asset:10.0.0.1"
    assert len(svc_node.facts) == 1

    # edge linking asset → service
    assert ("asset:10.0.0.1", "tcp:443") in topo.edges


# ──────────────────────────────────────────────────────────────────────────
# Test 2: unscanned_services() returns services without fingerprints
# ──────────────────────────────────────────────────────────────────────────


def test_unscanned_services_returns_services_lacking_fingerprint_siblings():
    service = _make_service()
    _ingest(service, [
        _service_observation("asset:10.0.0.1", "tcp", 443),
        _service_observation("asset:10.0.0.2", "tcp", 80),
    ])

    topo = TopologyService(service).build(PROJECT_ID)
    unscanned = topo.unscanned_services()

    refs = {node.ref for node in unscanned}
    assert refs == {"tcp:443", "tcp:80"}


# ──────────────────────────────────────────────────────────────────────────
# Test 3: unscanned_services() empty after fingerprint fact added
# ──────────────────────────────────────────────────────────────────────────


def test_unscanned_services_empty_after_fingerprint_added_for_that_asset():
    service = _make_service()
    _ingest(service, [
        _service_observation("asset:10.0.0.1", "tcp", 443),
    ])
    # fingerprint.detected on the same asset → service now considered scanned
    _ingest(service, [
        _fingerprint_observation("asset:10.0.0.1", "tcp:443"),
    ])

    topo = TopologyService(service).build(PROJECT_ID)
    assert topo.unscanned_services() == []


def test_unscanned_services_filters_only_matching_asset():
    """A fingerprint on asset A should not mark asset B's service as scanned."""
    service = _make_service()
    _ingest(service, [
        _service_observation("asset:10.0.0.1", "tcp", 443),
        _service_observation("asset:10.0.0.2", "tcp", 80),
        _fingerprint_observation("asset:10.0.0.1", "tcp:443"),
    ])

    topo = TopologyService(service).build(PROJECT_ID)
    unscanned = topo.unscanned_services()
    assert {node.ref for node in unscanned} == {"tcp:80"}


# ──────────────────────────────────────────────────────────────────────────
# Test 4: to_dict() returns proper structure


def test_to_dict_returns_proper_structure():
    service = _make_service()
    _ingest(service, [
        {
            "fact_type": "asset.discovered",
            "asset_ref": "asset:10.0.0.1",
            "data": {"ip": "10.0.0.1", "source": "seed"},
            "identity": {"ip": "10.0.0.1"},
            "confidence": 1.0,
            "state": "active",
        },
        _service_observation("asset:10.0.0.1", "tcp", 443),
    ])

    topo = TopologyService(service).build(PROJECT_ID)
    data = topo.to_dict()

    assert isinstance(data, dict)
    assert set(data.keys()) == {"nodes", "edges"}
    assert isinstance(data["nodes"], dict)
    assert isinstance(data["edges"], list)

    asset_dict = data["nodes"]["asset:10.0.0.1"]
    assert asset_dict["ref"] == "asset:10.0.0.1"
    assert asset_dict["kind"] == "asset"
    assert asset_dict["parent_ref"] is None
    assert isinstance(asset_dict["facts"], list)
    assert len(asset_dict["facts"]) == 2

    svc_dict = data["nodes"]["tcp:443"]
    assert svc_dict["kind"] == "service"
    assert svc_dict["fact_type"] == "service.exposed"
    assert svc_dict["parent_ref"] == "asset:10.0.0.1"

    # edges serialized as 2-element lists
    assert ["asset:10.0.0.1", "tcp:443"] in data["edges"]


# ──────────────────────────────────────────────────────────────────────────
# Bonus: delta() returns new refs since a sequence cutoff
# ──────────────────────────────────────────────────────────────────────────


def test_delta_returns_refs_for_events_after_cutoff():
    service = _make_service()
    events = []
    events += service.ingest_result(_evidence([
        {
            "fact_type": "asset.discovered",
            "asset_ref": "asset:10.0.0.1",
            "data": {"ip": "10.0.0.1", "source": "seed"},
            "identity": {"ip": "10.0.0.1"},
            "confidence": 1.0,
            "state": "active",
        },
    ]))
    cutoff = max(e.sequence for e in events)

    service.ingest_result(_evidence([
        _service_observation("asset:10.0.0.1", "tcp", 443),
    ]))

    topo_service = TopologyService(service)
    refs = topo_service.delta(PROJECT_ID, cutoff)
    assert "asset:10.0.0.1" in refs
    assert "tcp:443" in refs


def _evidence(observations: list[dict]) -> Evidence:
    return Evidence(
        evidence_id=f"ev-{uuid.uuid4().hex[:12]}",
        project_id=PROJECT_ID,
        session_id=SESSION_ID,
        task_id="task-topo",
        agent_id=AGENT_ID,
        kind="mcp.response",
        raw_payload={"observations": observations},
    )


# ──────────────────────────────────────────────────────────────────────────
# Bonus: unverified_vulns() returns vuln nodes without verified flag
# ──────────────────────────────────────────────────────────────────────────


def test_unverified_vulns_returns_only_unverified_vulnerability_nodes():
    service = _make_service()
    _ingest(service, [
        _service_observation("asset:10.0.0.1", "tcp", 443),
        {
            "fact_type": "vulnerability.detected",
            "asset_ref": "asset:10.0.0.1",
            "data": {
                "vulnerability_id": "CVE-2026-0001",
                "service_ref": "tcp:443",
                "matched_at": "asset:10.0.0.1",
                "description": "rce",
                "verified": False,
            },
            "identity": {"vulnerability_id": "CVE-2026-0001", "service_ref": "tcp:443"},
            "confidence": 0.3,
            "state": "active",
        },
        {
            "fact_type": "vulnerability.detected",
            "asset_ref": "asset:10.0.0.1",
            "data": {
                "vulnerability_id": "CVE-2026-0002",
                "service_ref": "tcp:443",
                "matched_at": "asset:10.0.0.1",
                "description": "xss",
                "verified": True,
            },
            "identity": {"vulnerability_id": "CVE-2026-0002", "service_ref": "tcp:443"},
            "confidence": 0.9,
            "state": "active",
        },
    ])

    topo = TopologyService(service).build(PROJECT_ID)
    unverified = topo.unverified_vulns()
    assert len(unverified) == 1
    assert unverified[0].fact_type == "vulnerability.detected"
    # the unverified node should hold the CVE-2026-0001 fact (verified=False),
    # not the CVE-2026-0002 fact (verified=True). fact_ids are opaque hashes,
    # so resolve them through the graph's fact index to inspect ``data``.
    unverified_fact_ids = {fid for node in unverified for fid in node.facts}
    unverified_cves = {
        topo._fact_index[fid].data.get("vulnerability_id")
        for fid in unverified_fact_ids
        if fid in topo._fact_index
    }
    assert unverified_cves == {"CVE-2026-0001"}


# ──────────────────────────────────────────────────────────────────────────
# Test 7: to_mermaid() generates valid Mermaid.js flowchart
# ──────────────────────────────────────────────────────────────────────────


def test_to_mermaid_generates_flowchart():
    service = _make_service()
    _ingest(service, [
        _service_observation("asset:10.0.0.1", "tcp", 443),
    ])

    topo = TopologyService(service).build(PROJECT_ID)
    mermaid = topo.to_mermaid()

    assert mermaid.startswith("```mermaid")
    assert "graph TD" in mermaid
    assert mermaid.endswith("```")
    # Should contain edge between asset and service
    assert " --> " in mermaid
