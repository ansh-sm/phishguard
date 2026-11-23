"""Data models for Attack Graphs and Threat Campaign Clustering."""

from __future__ import annotations

import re
from typing import Optional, Any
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    """An individual entity node in the security incident attack graph."""
    id: str
    label: str
    node_type: str = Field(
        ...,
        description="Node type: email, ip, domain, url, hash, technique, recipient, threat_actor",
    )
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """A directed causal or relational connection between security entities."""
    source: str
    target: str
    relationship: str = Field(
        ...,
        description="Relationship: SENT_FROM, ORIGINATED_AT, DELIVERED_LINK, ATTACHED_FILE, EXHIBITS_TECHNIQUE, TARGETED",
    )
    properties: dict[str, Any] = Field(default_factory=dict)


class AttackGraph(BaseModel):
    """Topological graph capturing attack delivery paths and infrastructure relationships."""
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)

    def to_mermaid(self) -> str:
        """Render the attack graph as a Mermaid flowchart for markdown and interactive dashboards."""
        lines = ["flowchart LR"]

        # Class styles for visual SOC distinction
        lines.append("    classDef actor fill:#ff4d4f,stroke:#cf1322,color:#ffffff,font-weight:bold")
        lines.append("    classDef infra fill:#fa8c16,stroke:#d46b08,color:#ffffff")
        lines.append("    classDef threat fill:#f5222d,stroke:#a8071a,color:#ffffff")
        lines.append("    classDef email fill:#1890ff,stroke:#096dd9,color:#ffffff")
        lines.append("    classDef victim fill:#52c41a,stroke:#389e0d,color:#ffffff")
        lines.append("    classDef mitre fill:#722ed1,stroke:#531dab,color:#ffffff")

        def sanitize_id(raw: str) -> str:
            clean = re.sub(r"[^a-zA-Z0-9_]", "_", raw)
            return f"n_{clean}"

        for node in self.nodes:
            sid = sanitize_id(node.id)
            # Escape quotes in label
            safe_label = node.label.replace('"', "'")
            lines.append(f'    {sid}["{safe_label}"]')

            # Assign styling class based on node_type
            if node.node_type in ("threat_actor", "adversary"):
                lines.append(f"    class {sid} actor")
            elif node.node_type in ("ip", "domain", "nameserver"):
                lines.append(f"    class {sid} infra")
            elif node.node_type in ("url", "hash", "payload"):
                lines.append(f"    class {sid} threat")
            elif node.node_type == "email":
                lines.append(f"    class {sid} email")
            elif node.node_type == "recipient":
                lines.append(f"    class {sid} victim")
            elif node.node_type == "technique":
                lines.append(f"    class {sid} mitre")

        for edge in self.edges:
            src = sanitize_id(edge.source)
            tgt = sanitize_id(edge.target)
            rel = edge.relationship.replace('"', "'")
            lines.append(f'    {src} -->|"{rel}"| {tgt}')

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to standard node-edge format for frontend graphing engines (Cytoscape/D3)."""
        return {
            "nodes": [n.model_dump() for n in self.nodes],
            "edges": [e.model_dump() for e in self.edges],
        }


class ThreatCampaign(BaseModel):
    """Correlated cluster of phishing incidents sharing adversary infrastructure or tactics."""
    campaign_id: str
    name: str
    confidence: float = 0.85
    risk_score: float = 85.0
    incident_ids: list[str] = Field(default_factory=list)
    first_seen: str
    last_seen: str
    primary_techniques: list[str] = Field(default_factory=list)
    shared_iocs: list[str] = Field(default_factory=list)
    victim_count: int = 1
    graph: Optional[AttackGraph] = None
