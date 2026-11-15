"""
Indicator of Compromise (IOC) Extraction and Threat Hunting Export Subsystem.
Compliant with OASIS STIX 2.1 and standard SIEM blocklist formats (CSV/JSON).
"""

import csv
from datetime import datetime, timezone
import io
import json
from pathlib import Path
from typing import Any, Optional
import uuid

from pydantic import BaseModel, Field

from phishguard.models.report import ScanResult, VerdictEnum


class IOCItem(BaseModel):
    """Represents a single extracted Indicator of Compromise."""
    ioc_type: str = Field(description="Type: ipv4, ipv6, domain, url, email, sha256, md5")
    value: str = Field(description="Raw indicator value")
    defanged_value: str = Field(description="Defanged safe representation")
    threat_category: str = Field(description="Category: phishing, origin-mta, credential-harvest, attachment")
    confidence: str = Field(description="HIGH, MEDIUM, LOW")
    description: str = Field(default="")


class IOCBundle(BaseModel):
    """Collection of extracted IOCs from an incident analysis."""
    scan_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verdict: VerdictEnum
    total_iocs: int = 0
    items: list[IOCItem] = Field(default_factory=list)


class IOCExtractor:
    """
    Extracts, deduplicates, and formats Indicators of Compromise (IOCs) from ScanResult.
    """

    def extract(self, result: ScanResult) -> IOCBundle:
        """Extract all actionable IOCs from a completed ScanResult."""
        items: list[IOCItem] = []
        seen_keys: set[str] = set()

        def add_item(ioc_type: str, val: str, defanged: str, category: str, conf: str, desc: str):
            key = f"{ioc_type}:{val.lower().strip()}"
            if key not in seen_keys and val.strip():
                seen_keys.add(key)
                items.append(
                    IOCItem(
                        ioc_type=ioc_type,
                        value=val.strip(),
                        defanged_value=defanged.strip(),
                        threat_category=category,
                        confidence=conf,
                        description=desc,
                    )
                )

        # 1. Sender Emails
        if result.metadata.from_email:
            defanged_email = result.metadata.from_email.replace("@", "[@]")
            add_item("email", result.metadata.from_email, defanged_email, "phishing-sender", "HIGH", "Declared Sender Address")

        if result.metadata.reply_to_email and result.metadata.reply_to_email != result.metadata.from_email:
            defanged_reply = result.metadata.reply_to_email.replace("@", "[@]")
            add_item("email", result.metadata.reply_to_email, defanged_reply, "reply-to-redirect", "HIGH", "Suspicious Reply-To Collector")

        # 2. Sender Domains
        if result.metadata.from_domain:
            defanged_dom = result.metadata.from_domain.replace(".", "[.]")
            add_item("domain", result.metadata.from_domain, defanged_dom, "sender-domain", "HIGH", "Sender Origin Domain")

        if result.metadata.reply_to_domain and result.metadata.reply_to_domain != result.metadata.from_domain:
            defanged_rdom = result.metadata.reply_to_domain.replace(".", "[.]")
            add_item("domain", result.metadata.reply_to_domain, defanged_rdom, "reply-to-domain", "HIGH", "Reply-To Destination Domain")

        # 3. Network Origin IPs (Public routable only)
        if result.headers.originating_ip:
            defanged_ip = result.headers.originating_ip.replace(".", "[.]")
            add_item("ipv4", result.headers.originating_ip, defanged_ip, "origin-mta", "HIGH", "Originating External Sending MTA")

        for hop in result.headers.hops:
            if hop.client_ip and not hop.is_private_ip:
                defanged_hop_ip = hop.client_ip.replace(".", "[.]")
                add_item("ipv4", hop.client_ip, defanged_hop_ip, "transit-mta", "MEDIUM", f"Intermediate Transit Relay Hop #{hop.hop_index}")

        # 4. URLs & Embedded Domains
        for url_artifact in result.urls:
            conf = "HIGH" if (url_artifact.threat_intel_flagged or url_artifact.is_mismatched_anchor or url_artifact.risk_score > 30) else "MEDIUM"
            add_item("url", url_artifact.raw_url, url_artifact.defanged_url, "phishing-link", conf, f"Body link (Risk score: {url_artifact.risk_score})")

            # Also add bare domain if not standard platform
            if url_artifact.domain and not url_artifact.is_ip_host:
                defanged_u_dom = url_artifact.domain.replace(".", "[.]")
                add_item("domain", url_artifact.domain, defanged_u_dom, "link-domain", conf, "Domain hosting embedded URL")

        # 5. Attachment Hashes
        for att in result.attachments:
            conf = "HIGH" if att.risk_score > 30 else "MEDIUM"
            add_item("sha256", att.sha256, att.sha256, "malicious-attachment", conf, f"SHA-256 for attachment: {att.filename}")
            add_item("md5", att.md5, att.md5, "malicious-attachment", conf, f"MD5 for attachment: {att.filename}")

        return IOCBundle(
            scan_id=result.scan_id,
            timestamp=result.timestamp,
            verdict=result.verdict,
            total_iocs=len(items),
            items=items,
        )


class IOCExporter:
    """
    Serializes an IOCBundle into industry-standard threat sharing formats:
    - CSV Blocklist (Firewall/EDR ready)
    - JSON Observable Bundle
    - OASIS STIX 2.1 Threat Intelligence Bundle
    """

    def to_csv(self, bundle: IOCBundle, output_path: Optional[Path] = None) -> str:
        """Export IOCs as CSV blocklist."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ioc_type", "value", "defanged_value", "threat_category", "confidence", "description", "scan_id"])

        for item in bundle.items:
            writer.writerow([
                item.ioc_type,
                item.value,
                item.defanged_value,
                item.threat_category,
                item.confidence,
                item.description,
                bundle.scan_id,
            ])

        csv_str = output.getvalue()
        if output_path:
            p = Path(output_path).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(csv_str, encoding="utf-8")

        return csv_str

    def to_json(self, bundle: IOCBundle, output_path: Optional[Path] = None) -> str:
        """Export IOCs as structured JSON bundle."""
        json_str = bundle.model_dump_json(indent=2)
        if output_path:
            p = Path(output_path).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json_str, encoding="utf-8")
        return json_str

    def to_stix21(self, bundle: IOCBundle, output_path: Optional[Path] = None) -> str:
        """
        Export IOCs as an OASIS STIX 2.1 compliant Threat Intelligence Bundle.
        """
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects: list[dict[str, Any]] = []

        # 1. Report / Incident Object
        report_id = f"report--{uuid.uuid4()}"
        indicator_ids = []

        # 2. Convert each IOC into a STIX 2.1 Indicator SDO
        for item in bundle.items:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)

            # Generate STIX 2.1 pattern
            pattern = self._build_stix_pattern(item.ioc_type, item.value)

            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"PhishGuard IOC: {item.ioc_type.upper()} {item.defanged_value}",
                "description": item.description or f"Phishing observable identified by PhishGuard in scan {bundle.scan_id}",
                "indicator_types": ["malicious-activity", "phishing"],
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": now_iso,
                "confidence": 90 if item.confidence == "HIGH" else 60,
                "labels": [item.threat_category, bundle.verdict.value.lower()],
            }
            objects.append(indicator_obj)

        # Append parent Report object
        report_obj = {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"PhishGuard Forensic Incident Report - {bundle.scan_id}",
            "description": f"Automated phishing triage analysis. Verdict: {bundle.verdict.value} with {bundle.total_iocs} IOCs.",
            "report_types": ["threat-report"],
            "published": now_iso,
            "object_refs": indicator_ids,
        }
        objects.insert(0, report_obj)

        stix_bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

        stix_str = json.dumps(stix_bundle, indent=2)
        if output_path:
            p = Path(output_path).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(stix_str, encoding="utf-8")

        return stix_str

    @staticmethod
    def _build_stix_pattern(ioc_type: str, val: str) -> str:
        """Construct standard STIX 2.1 pattern expression."""
        clean_val = val.replace("'", "\\'")
        if ioc_type in ("ipv4", "ip"):
            return f"[ipv4-addr:value = '{clean_val}']"
        elif ioc_type == "ipv6":
            return f"[ipv6-addr:value = '{clean_val}']"
        elif ioc_type == "domain":
            return f"[domain-name:value = '{clean_val}']"
        elif ioc_type == "url":
            return f"[url:value = '{clean_val}']"
        elif ioc_type == "email":
            return f"[email-addr:value = '{clean_val}']"
        elif ioc_type == "sha256":
            return f"[file:hashes.'SHA-256' = '{clean_val}']"
        elif ioc_type == "md5":
            return f"[file:hashes.'MD5' = '{clean_val}']"
        return f"[network-traffic:dst_ref.value = '{clean_val}']"
