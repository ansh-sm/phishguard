"""Threat campaign clustering and correlation engine."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Optional
from phishguard.storage.models import IncidentSummary
from phishguard.hunting.models import ThreatCampaign, AttackGraph
from phishguard.hunting.graph_builder import AttackGraphBuilder


class CampaignClusterer:
    """Discovers and correlates persistent threat campaigns across historical incidents."""

    @classmethod
    def get_c_class_subnet(cls, ip: Optional[str]) -> Optional[str]:
        """Extract /24 subnet from an IPv4 address for infrastructure clustering."""
        if not ip or "." not in ip:
            return None
        parts = ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None

    @classmethod
    def cluster_incidents(
        cls,
        incidents: list[IncidentSummary],
        min_cluster_size: int = 1,
    ) -> list[ThreatCampaign]:
        """Cluster historical incident telemetry into actionable adversary campaigns."""
        if not incidents:
            return []

        # 1. Bucket incidents by strongest correlation pivots
        # Pivot Priority: Payload SHA-256 > Origin IP > Domain > Subnet
        buckets: dict[str, list[IncidentSummary]] = defaultdict(list)
        pivot_type_map: dict[str, str] = {}

        for inc in incidents:
            if inc.file_sha256:
                key = f"hash:{inc.file_sha256}"
                buckets[key].append(inc)
                pivot_type_map[key] = "Payload Hash"
            elif inc.originating_ip and not inc.originating_ip.startswith("127."):
                key = f"ip:{inc.originating_ip}"
                buckets[key].append(inc)
                pivot_type_map[key] = "Originating IP"
            elif inc.from_domain:
                key = f"domain:{inc.from_domain}"
                buckets[key].append(inc)
                pivot_type_map[key] = "Sender Domain"
            else:
                key = f"technique:{inc.mitre_techniques or 'unknown'}"
                buckets[key].append(inc)
                pivot_type_map[key] = "Tactics"

        campaigns: list[ThreatCampaign] = []

        for key, inc_list in buckets.items():
            if len(inc_list) < min_cluster_size:
                continue

            # Deterministic campaign identifier
            raw_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
            campaign_id = f"CMP-{raw_hash.upper()}"

            # Extract shared indicators and metrics
            shared_iocs: set[str] = set()
            techniques_set: set[str] = set()
            timestamps: list[str] = []
            recipients: set[str] = set()
            scores: list[float] = []

            for inc in inc_list:
                scores.append(inc.score)
                timestamps.append(inc.timestamp)
                if inc.recipient:
                    recipients.add(inc.recipient)
                if inc.originating_ip:
                    shared_iocs.add(inc.originating_ip)
                if inc.from_domain:
                    shared_iocs.add(inc.from_domain)
                if inc.file_sha256:
                    shared_iocs.add(inc.file_sha256)
                if inc.mitre_techniques:
                    for t in inc.mitre_techniques.split(","):
                        cleaned_t = t.strip()
                        if cleaned_t:
                            techniques_set.add(cleaned_t)

            timestamps.sort()
            first_seen = timestamps[0] if timestamps else "Unknown"
            last_seen = timestamps[-1] if timestamps else "Unknown"
            avg_score = sum(scores) / len(scores) if scores else 50.0
            max_score = max(scores) if scores else 50.0

            # Generate intuitive campaign name
            pivot_kind = pivot_type_map.get(key, "General")
            pivot_val = key.split(":", 1)[1] if ":" in key else key

            if "hash" in key:
                name = f"Weaponized Stager Cluster [{pivot_val[:10]}...]"
            elif "ip" in key:
                name = f"Adversary Relay [{pivot_val}] Campaign"
            elif "domain" in key:
                name = f"Targeted Brand Squatting [{pivot_val}]"
            else:
                name = f"Coordinated Multi-Vector Tactic Cluster [{pivot_val}]"

            # Compute campaign risk score
            campaign_risk = min(100.0, max(max_score, avg_score + (len(inc_list) * 5.0)))

            temp_campaign = ThreatCampaign(
                campaign_id=campaign_id,
                name=name,
                confidence=min(0.98, 0.70 + (len(inc_list) * 0.05)),
                risk_score=round(campaign_risk, 1),
                incident_ids=[i.scan_id for i in inc_list],
                first_seen=first_seen,
                last_seen=last_seen,
                primary_techniques=sorted(list(techniques_set)),
                shared_iocs=sorted(list(shared_iocs)),
                victim_count=max(1, len(recipients)),
            )

            # Generate Attack Graph for this campaign
            temp_campaign.graph = AttackGraphBuilder.build_campaign_graph(temp_campaign, inc_list)
            campaigns.append(temp_campaign)

        # Sort campaigns by risk score descending
        campaigns.sort(key=lambda c: (c.risk_score, len(c.incident_ids)), reverse=True)
        return campaigns
