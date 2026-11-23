"""Unit tests for attack graph topologies and threat campaign clustering."""

from pathlib import Path
import pytest

from phishguard.models.report import ScanResult
from phishguard.parser.eml_parser import EmlParser
from phishguard.storage.models import IncidentSummary
from phishguard.hunting.models import AttackGraph, ThreatCampaign
from phishguard.hunting.graph_builder import AttackGraphBuilder
from phishguard.hunting.campaign import CampaignClusterer
from phishguard.cli import _run_analysis


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Fixture providing an analyzed email ScanResult."""
    sample_path = Path("samples/phishing_account_alert.eml")
    parser = EmlParser()
    parsed = parser.parse_file(sample_path)
    import asyncio
    return asyncio.run(_run_analysis(parsed, offline=True))


def test_attack_graph_builder_single_incident(sample_scan_result: ScanResult):
    """Verify single-incident topological attack graph creation."""
    graph = AttackGraphBuilder.build_incident_graph(sample_scan_result)
    assert len(graph.nodes) > 0
    assert len(graph.edges) > 0

    node_types = {n.node_type for n in graph.nodes}
    assert "email" in node_types
    assert "recipient" in node_types

    edge_rels = {e.relationship for e in graph.edges}
    assert "SENT" in edge_rels or "TARGETED" in edge_rels

    # Check to_dict() export
    graph_dict = graph.to_dict()
    assert "nodes" in graph_dict
    assert "edges" in graph_dict
    assert len(graph_dict["nodes"]) == len(graph.nodes)


def test_attack_graph_to_mermaid(sample_scan_result: ScanResult):
    """Verify Mermaid flowchart generation syntax."""
    graph = AttackGraphBuilder.build_incident_graph(sample_scan_result)
    mermaid_str = graph.to_mermaid()

    assert mermaid_str.startswith("flowchart LR")
    assert "classDef" in mermaid_str
    assert "-->" in mermaid_str


def test_c_class_subnet_extraction():
    """Verify IPv4 /24 subnet grouping helper."""
    assert CampaignClusterer.get_c_class_subnet("198.51.100.23") == "198.51.100.0/24"
    assert CampaignClusterer.get_c_class_subnet("invalid_ip") is None
    assert CampaignClusterer.get_c_class_subnet(None) is None


def test_campaign_clusterer_grouping():
    """Verify clustering of incidents by shared payload hash and sender infrastructure."""
    incidents = [
        IncidentSummary(
            scan_id="PG-001",
            timestamp="2026-11-20T10:00:00Z",
            verdict="MALICIOUS",
            score=95.0,
            confidence="HIGH",
            from_email="attacker@spoofed.xyz",
            from_domain="spoofed.xyz",
            recipient="ceo@target.com",
            subject="Urgent Wire Transfer",
            originating_ip="198.51.100.5",
            file_sha256="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            mitre_techniques="T1566.002,T1036",
        ),
        IncidentSummary(
            scan_id="PG-002",
            timestamp="2026-11-21T11:00:00Z",
            verdict="MALICIOUS",
            score=90.0,
            confidence="HIGH",
            from_email="attacker@spoofed.xyz",
            from_domain="spoofed.xyz",
            recipient="cfo@target.com",
            subject="Invoice Payment Confirmation",
            originating_ip="198.51.100.5",
            file_sha256="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            mitre_techniques="T1566.002",
        ),
        IncidentSummary(
            scan_id="PG-003",
            timestamp="2026-11-22T12:00:00Z",
            verdict="SUSPICIOUS",
            score=45.0,
            confidence="MEDIUM",
            from_email="newsletter@marketing.org",
            from_domain="marketing.org",
            recipient="dev@target.com",
            subject="Weekly Digest",
            originating_ip="192.0.2.1",
            file_sha256=None,
            mitre_techniques=None,
        ),
    ]

    campaigns = CampaignClusterer.cluster_incidents(incidents, min_cluster_size=1)
    assert len(campaigns) >= 2

    # Top campaign should be the weaponized hash cluster with 2 incidents
    top_camp = campaigns[0]
    assert len(top_camp.incident_ids) == 2
    assert "deadbeef" in top_camp.name or "deadbeef" in top_camp.shared_iocs[0]
    assert top_camp.victim_count == 2
    assert top_camp.risk_score >= 90.0
    assert top_camp.graph is not None

    # Verify campaign attack graph contains adversary and target nodes
    camp_nodes = {n.node_type for n in top_camp.graph.nodes}
    assert "threat_actor" in camp_nodes
    assert "recipient" in camp_nodes
