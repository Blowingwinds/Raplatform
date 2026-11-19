"""Report generator — Markdown + HTML reports from blackboard / topology / PTT."""

from __future__ import annotations

from datetime import datetime, timezone

from src.blackboard.service import BlackboardService
from src.blackboard.topology import TopologyService
from src.domain.models import BlackboardFact


def generate_markdown(
    project_id: str,
    blackboard: BlackboardService,
    topology: TopologyService | None = None,
    tree_data: dict | None = None,
) -> str:
    """Generate a complete Markdown penetration test report.

    Args:
        project_id: Project identifier.
        blackboard: BlackboardService for fact queries.
        topology: Optional TopologyService for graph visualization.
        tree_data: Optional persisted PTT tree dict.

    Returns a Markdown string.
    """
    facts = blackboard.snapshot(project_id)
    events = blackboard.events_since(project_id)

    # Categorize facts
    assets = [f for f in facts if f.fact_type == "asset.discovered"]
    subdomains = [f for f in facts if f.fact_type == "subdomain.discovered"]
    services = [f for f in facts if f.fact_type == "service.exposed"]
    fingerprints = [f for f in facts if f.fact_type == "fingerprint.detected"]
    vulns = [f for f in facts if f.fact_type == "vulnerability.detected"]
    credentials = [f for f in facts if f.fact_type == "credential.validated"]
    verified = [v for v in vulns if v.data.get("verified")]

    lines: list[str] = []

    # ── header ──
    lines.append("# Penetration Test Report")
    lines.append("")
    lines.append(f"**Project**: `{project_id}`")
    lines.append(f"**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"**Total Events**: {len(events)}")
    lines.append("")

    # ── executive summary ──
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Assets Discovered | {len(assets)} |")
    lines.append(f"| Subdomains | {len(subdomains)} |")
    lines.append(f"| Services Exposed | {len(services)} |")
    lines.append(f"| Technologies Fingerprinted | {len(fingerprints)} |")
    lines.append(f"| Vulnerabilities Detected | {len(vulns)} |")
    lines.append(f"| Vulnerabilities Verified | {len(verified)} |")
    lines.append(f"| Credentials Captured | {len(credentials)} |")
    lines.append("")

    # ── PTT tree summary ──
    if tree_data:
        lines.append("## PTT Execution Plan")
        lines.append("")
        goal = tree_data.get("plan", {}).get("goal", "N/A")
        progress = tree_data.get("node_states", {})
        total = len(progress)
        ok = sum(1 for s in progress.values() if s == "succeeded")
        failed = sum(1 for s in progress.values() if s == "failed")
        blocked = sum(1 for s in progress.values() if s == "blocked")
        lines.append(f"- **Goal**: {goal}")
        lines.append(f"- **Actions**: {total} total, {ok} succeeded, {failed} failed, {blocked} blocked")
        lines.append("")

    # ── topology ──
    if topology is not None:
        graph = topology.build(project_id)
        lines.append("## Network Topology")
        lines.append("")
        lines.append(graph.to_mermaid())
        lines.append("")

    # ── assets ──
    if assets or subdomains:
        lines.append("## Assets & Subdomains")
        lines.append("")
        for f in assets:
            ip = f.data.get("ip", "?")
            source = f.data.get("source", "?")
            lines.append(f"- **{f.asset_ref}** (IP: {ip}, source: {source}) "
                        f"`← agent:{f.source_agent}` `ev:{f.evidence_ref[:20]}…`")
        for f in subdomains:
            hostname = f.data.get("hostname", "?")
            lines.append(f"- **{hostname}** → {f.asset_ref} "
                        f"`← agent:{f.source_agent}`")
        lines.append("")

    # ── services ──
    if services:
        lines.append("## Services")
        lines.append("")
        lines.append("| Host | Port | Protocol | Service | Banner | Agent | Evidence |")
        lines.append("|------|------|----------|---------|--------|-------|----------|")
        for f in services:
            port = f.data.get("port", "?")
            proto = f.data.get("protocol", "?")
            svc = f.data.get("service_name", "?")
            banner = (f.data.get("banner", "") or "")[:40]
            lines.append(f"| {f.asset_ref} | {port} | {proto} | {svc} | {banner} "
                        f"| {f.source_agent} | `{f.evidence_ref[:16]}…` |")
        lines.append("")

    # ── technology ──
    if fingerprints:
        lines.append("## Technology Stack")
        lines.append("")
        for f in fingerprints:
            name = f.data.get("name", "?")
            extracted = f.data.get("extracted", "")
            lines.append(f"- **{name}** {extracted} on {f.asset_ref} "
                        f"`← agent:{f.source_agent}`")
        lines.append("")

    # ── vulnerabilities ──
    if vulns:
        lines.append("## Vulnerabilities")
        lines.append("")
        for v in vulns:
            status = "✅ VERIFIED" if v.data.get("verified") else "⏳ PENDING"
            severity = v.data.get("severity", "?").upper()
            name = v.data.get("name", "?")
            category = v.data.get("category", "?")
            description = v.data.get("description", "")
            matched = v.data.get("matched_at", v.asset_ref)

            lines.append(f"### [{severity}] {name} — {status}")
            lines.append(f"- **Target**: {matched}")
            lines.append(f"- **Category**: {category}")
            lines.append(f"- **Source Agent**: `{v.source_agent}`")
            lines.append(f"- **Evidence**: `{v.evidence_ref}`")
            if description:
                lines.append(f"- **Description**: {description[:200]}")
            lines.append("")

    # ── credentials ──
    if credentials:
        lines.append("## Captured Credentials")
        lines.append("")
        for c in credentials:
            cred_type = c.data.get("credential_type", "?")
            username = c.data.get("username", "***")
            lines.append(f"- **{cred_type}** user=`{username}` on {c.asset_ref} "
                        f"`← agent:{c.source_agent}`")
        lines.append("")

    # ── evidence traceability ──
    lines.append("## Evidence Traceability")
    lines.append("")
    lines.append("All facts are traceable to their source agent and raw evidence:")
    lines.append("")
    lines.append("| Fact ID | Type | Asset | Agent | Evidence ID |")
    lines.append("|---------|------|-------|-------|-------------|")
    for f in facts:
        lines.append(f"| `{f.fact_id[:16]}…` | {f.fact_type} | {f.asset_ref} "
                    f"| {f.source_agent} | `{f.evidence_ref[:16]}…` |")
    lines.append("")

    # ── footer ──
    lines.append("---")
    lines.append("*Report generated by Raplatform — Automated Penetration Testing Platform*")
    lines.append("")

    return "\n".join(lines)


def wrap_html(markdown: str, title: str = "Penetration Test Report") -> str:
    """Wrap a Markdown report in a self-contained HTML page.

    Uses a CDN-loaded Mermaid.js for topology rendering, so the page
    works offline (after first load) in any modern browser.
    """
    # Escape backticks for embedding in HTML
    md_escaped = markdown.replace("\\", "\\\\").replace("`", "\\`")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{startOnLoad:true}})</script>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         max-width: 960px; margin: 0 auto; padding: 2rem; line-height: 1.6;
         color: #333; }}
  h1 {{ border-bottom: 2px solid #1a73e8; padding-bottom: .5rem; }}
  h2 {{ border-bottom: 1px solid #ddd; padding-bottom: .3rem; margin-top: 2rem; }}
  h3 {{ margin-top: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: .9em; }}
  th {{ background: #f5f5f5; }}
  code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: .9em; }}
  .mermaid {{ background: #fafafa; padding: 1rem; border-radius: 6px; margin: 1rem 0; }}
</style>
</head>
<body>
<div id="content"></div>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script>
  document.getElementById('content').innerHTML = marked.parse(`{md_escaped}`);
</script>
</body>
</html>"""


def trace_fact_chain(
    fact_id: str,
    blackboard: BlackboardService,
) -> dict | None:
    """Trace a fact back through its evidence chain.

    Returns a dict with keys: fact, evidence, agent_id, session_id, task_id.
    Returns None if the fact is not found.
    """
    # Get all facts and find the one we want
    # blackboard stores facts by project — we need to find which project
    # In practice, we use snapshot() and filter
    facts_dict: dict[str, BlackboardFact] = {}
    # We need to get the fact from storage directly
    store = blackboard.store
    fact = store.get_fact(fact_id)
    if fact is None:
        return None

    evidence = store.get_evidence(fact.evidence_ref)
    session = store.get_session(fact.session_id) if fact.session_id else None

    return {
        "fact": {
            "fact_id": fact.fact_id,
            "fact_type": fact.fact_type,
            "asset_ref": fact.asset_ref,
            "confidence": fact.confidence,
            "version": fact.version,
            "state": fact.state.value,
            "data": fact.data,
        },
        "evidence": evidence.model_dump(mode="json") if evidence else None,
        "agent_id": fact.source_agent,
        "session_id": fact.session_id,
        "session": {
            "session_id": session.session_id,
            "status": session.status.value,
        } if session else None,
    }