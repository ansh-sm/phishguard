"""Attack graph builder for incident topology and campaign visual mapping."""

from __future__ import annotations

from typing import Optional, Any
from phishguard.models.report import ScanResult
from phishguard.storage.models import IncidentSummary
from phishguard.hunting.models import AttackGraph, GraphNode, GraphEdge, ThreatCampaign


class AttackGraphBuilder:
    """Constructs relational graphs for individual incidents and multi-stage campaigns."""

    @classmethod
    def build_incident_graph(cls, result: ScanResult) -> AttackGraph:
        """Construct full attack topology graph for an analyzed email incident."""
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        seen_nodes: set[str] = set()

        def add_node(node_id: str, label: str, node_type: str, props: Optional[dict[str, Any]] = None):
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                nodes.append(GraphNode(id=node_id, label=label, node_type=node_type, properties=props or {}))

        # Root Incident Node
        total_score_val = result.score.total_score if hasattr(result.score, "total_score") else float(result.score)
        incident_id = f"incident_{result.scan_id[:8]}"
        add_node(
            incident_id,
            f"Email: {result.metadata.subject[:30]}... ({result.verdict.value.upper()})",
            "email",
            {"score": total_score_val, "verdict": result.verdict.value, "scan_id": result.scan_id},
        )

        # Sender Envelope & Domain
        sender = result.metadata.from_email or "unknown@sender.com"
        sender_id = f"sender_{sender}"
        add_node(sender_id, f"Sender: {sender}", "email", {"from_email": sender})
        edges.append(GraphEdge(source=sender_id, target=incident_id, relationship="SENT"))

        # Originating IP
        orig_ip = result.headers.originating_ip if result.headers else None
        if orig_ip:
            ip_id = f"ip_{orig_ip}"
            add_node(ip_id, f"Origin IP: {orig_ip}", "ip", {"ip": orig_ip})
            edges.append(GraphEdge(source=ip_id, target=sender_id, relationship="HOSTED_BY"))

        # Recipients
        recipients = result.metadata.to_emails or (result.metadata.to if hasattr(result.metadata, "to") else [])
        if not recipients:
            rec_id = "rec_target_user"
            add_node(rec_id, "Target: Internal Corporate Mailbox", "recipient")
            edges.append(GraphEdge(source=incident_id, target=rec_id, relationship="TARGETED"))
        else:
            for rec in recipients:
                rec_id = f"rec_{rec}"
                add_node(rec_id, f"Victim: {rec}", "recipient", {"recipient": rec})
                edges.append(GraphEdge(source=incident_id, target=rec_id, relationship="TARGETED"))

        # Extracted URLs
        for i, url_art in enumerate(result.urls[:5]):  # Cap at top 5 to keep graph clean
            url_id = f"url_{i}_{url_art.domain}"
            label_text = f"Link: {url_art.defanged_url[:35]}..." if len(url_art.defanged_url) > 35 else url_art.defanged_url
            add_node(url_id, label_text, "url", {"domain": url_art.domain, "flags": url_art.flags})
            edges.append(GraphEdge(source=incident_id, target=url_id, relationship="CONTAINS_URL"))

            # If URL has high-risk domain, connect domain node
            if url_art.domain:
                dom_id = f"dom_{url_art.domain}"
                add_node(dom_id, f"Domain: {url_art.domain}", "domain")
                edges.append(GraphEdge(source=url_id, target=dom_id, relationship="RESOLVES_TO"))

        # Extracted Attachments
        for i, att in enumerate(result.attachments[:4]):
            att_id = f"att_{att.sha256[:10]}"
            add_node(
                att_id,
                f"Payload: {att.filename} ({att.sha256[:8]}...)",
                "hash",
                {"sha256": att.sha256, "file_type": att.file_type},
            )
            edges.append(GraphEdge(source=incident_id, target=att_id, relationship="CARRIED_PAYLOAD"))

        # MITRE ATT&CK Techniques
        for tech in result.mitre_techniques:
            tech_id = f"mitre_{tech.technique_id}"
            add_node(tech_id, f"{tech.technique_id}: {tech.name}", "technique", {"tactic": tech.tactic})
            edges.append(GraphEdge(source=incident_id, target=tech_id, relationship="EXHIBITED_TACTIC"))

        return AttackGraph(nodes=nodes, edges=edges)

    @classmethod
    def build_campaign_graph(
        cls,
        campaign: ThreatCampaign,
        incidents: list[IncidentSummary],
    ) -> AttackGraph:
        """Construct multi-incident campaign correlation graph."""
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        seen_nodes: set[str] = set()

        def add_node(node_id: str, label: str, node_type: str, props: Optional[dict[str, Any]] = None):
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                nodes.append(GraphNode(id=node_id, label=label, node_type=node_type, properties=props or {}))

        # Campaign Central Node
        camp_id = f"camp_{campaign.campaign_id[:8]}"
        add_node(camp_id, f"Campaign: {campaign.name}", "threat_actor", {"score": campaign.risk_score})

        # Connect shared IOCs
        for ioc in campaign.shared_iocs[:6]:
            ioc_id = f"ioc_{ioc}"
            node_type = "ip" if any(c.isdigit() for c in ioc) and "." in ioc and len(ioc) < 16 else "domain"
            add_node(ioc_id, f"Shared IOC: {ioc}", node_type)
            edges.append(GraphEdge(source=camp_id, target=ioc_id, relationship="UTILIZES_INFRA"))

        # Connect Primary Techniques
        for tech in campaign.primary_techniques[:4]:
            tech_id = f"tech_{tech}"
            add_node(tech_id, f"Tactic: {tech}", "technique")
            edges.append(GraphEdge(source=camp_id, target=tech_id, relationship="LEVERAGES"))

        # Connect associated incident samples
        for inc in incidents:
            inc_node_id = f"inc_{inc.scan_id[:8]}"
            label = f"Incident: {inc.from_domain} ➔ {inc.recipient or 'SOC'} (Score {int(inc.score)})"
            add_node(inc_node_id, label, "email", {"score": inc.score, "verdict": inc.verdict})
            edges.append(GraphEdge(source=camp_id, target=inc_node_id, relationship="SPAWNED_ATTACK"))

            # Connect incident to recipient if present
            if inc.recipient:
                rec_id = f"rec_{inc.recipient}"
                add_node(rec_id, f"Target: {inc.recipient}", "recipient")
                edges.append(GraphEdge(source=inc_node_id, target=rec_id, relationship="TARGETED"))

        return AttackGraph(nodes=nodes, edges=edges)
