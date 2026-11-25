"""Live DNS resolver and SPF/DMARC policy validator."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Optional, Any
from pydantic import BaseModel, Field


class SpfValidationResult(BaseModel):
    """Detailed SPF record evaluation for a sender domain."""
    domain: str
    raw_record: Optional[str] = None
    has_spf: bool = False
    ip_authorized: bool = False
    qualifier: str = "?"
    mechanism_matched: Optional[str] = None
    warnings: list[str] = Field(default_factory=list)


class DmarcValidationResult(BaseModel):
    """Detailed DMARC record evaluation for a sender domain."""
    domain: str
    raw_record: Optional[str] = None
    has_dmarc: bool = False
    policy: str = "none"
    subdomain_policy: Optional[str] = None
    percentage: int = 100
    rua: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class DomainDnsInspection(BaseModel):
    """Aggregated DNS authentication & routing assessment for an email domain."""
    domain: str
    originating_ip: Optional[str] = None
    mx_records: list[str] = Field(default_factory=list)
    spf: SpfValidationResult
    dmarc: DmarcValidationResult
    risk_score: float = 0.0
    risk_reasons: list[str] = Field(default_factory=list)


class DnsPolicyValidator:
    """Performs active DNS queries and evaluates email authentication policies."""

    @classmethod
    def query_txt_records(cls, domain: str, mock_records: Optional[dict[str, list[str]]] = None) -> list[str]:
        """Fetch TXT records for domain or use mock database in offline/test mode."""
        if mock_records and domain in mock_records:
            return mock_records[domain]

        # Use system nslookup as fallback for cross-platform zero-dependency TXT resolution
        try:
            import subprocess
            cmd = ["nslookup", "-q=txt", domain]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3.0)
            txts: list[str] = []
            for line in res.stdout.splitlines():
                if "text =" in line.lower() or '"' in line:
                    match = re.search(r'"([^"]+)"', line)
                    if match:
                        txts.append(match.group(1))
            return txts
        except Exception:
            return []

    @classmethod
    def query_mx_records(cls, domain: str, mock_records: Optional[dict[str, list[str]]] = None) -> list[str]:
        """Fetch MX mail exchanger hostnames for domain."""
        if mock_records and f"MX:{domain}" in mock_records:
            return mock_records[f"MX:{domain}"]

        try:
            import subprocess
            cmd = ["nslookup", "-q=mx", domain]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3.0)
            mx_hosts: list[str] = []
            for line in res.stdout.splitlines():
                if "mail exchanger =" in line.lower():
                    parts = line.split("mail exchanger =")
                    if len(parts) > 1:
                        mx_hosts.append(parts[1].strip().split()[-1].strip("."))
            return mx_hosts
        except Exception:
            return []

    @classmethod
    def evaluate_spf(
        cls,
        domain: str,
        originating_ip: Optional[str],
        mock_records: Optional[dict[str, list[str]]] = None,
    ) -> SpfValidationResult:
        """Parse and evaluate SPF record against originating IP."""
        txts = cls.query_txt_records(domain, mock_records=mock_records)
        spf_records = [t for t in txts if t.startswith("v=spf1")]

        if not spf_records:
            return SpfValidationResult(
                domain=domain,
                has_spf=False,
                warnings=["Domain published no SPF (v=spf1) record."],
            )

        raw = spf_records[0]
        warnings: list[str] = []
        if len(spf_records) > 1:
            warnings.append("Multiple SPF records detected (RFC 7208 syntax violation).")

        mechanisms = raw.split()[1:]
        ip_auth = False
        qualifier = "?"
        matched_mech = None

        if "+all" in mechanisms or "all" in mechanisms:
            warnings.append("SPF contains '+all' or permissive 'all' mechanism, allowing any IP to spoof domain.")

        # Test originating IP against mechanisms if provided
        if originating_ip:
            try:
                client_ip = ipaddress.ip_address(originating_ip)
                for mech in mechanisms:
                    # Parse qualifier
                    mech_qual = "+"
                    clean_mech = mech
                    if mech[0] in ("+", "-", "~", "?"):
                        mech_qual = mech[0]
                        clean_mech = mech[1:]

                    if clean_mech.startswith("ip4:"):
                        net_str = clean_mech[4:]
                        net = ipaddress.ip_network(net_str, strict=False)
                        if client_ip in net:
                            ip_auth = (mech_qual == "+")
                            qualifier = mech_qual
                            matched_mech = mech
                            break

                    elif clean_mech.startswith("ip6:"):
                        net_str = clean_mech[4:]
                        net = ipaddress.ip_network(net_str, strict=False)
                        if client_ip in net:
                            ip_auth = (mech_qual == "+")
                            qualifier = mech_qual
                            matched_mech = mech
                            break

                    elif clean_mech == "all":
                        qualifier = mech_qual
                        matched_mech = mech
                        ip_auth = (mech_qual == "+")
                        break
            except Exception:
                warnings.append(f"Invalid originating IP address: {originating_ip}")

        return SpfValidationResult(
            domain=domain,
            raw_record=raw,
            has_spf=True,
            ip_authorized=ip_auth,
            qualifier=qualifier,
            mechanism_matched=matched_mech,
            warnings=warnings,
        )

    @classmethod
    def evaluate_dmarc(
        cls,
        domain: str,
        mock_records: Optional[dict[str, list[str]]] = None,
    ) -> DmarcValidationResult:
        """Query and parse DMARC policy from _dmarc.<domain>."""
        dmarc_host = f"_dmarc.{domain}"
        txts = cls.query_txt_records(dmarc_host, mock_records=mock_records)
        dmarc_records = [t for t in txts if t.startswith("v=DMARC1")]

        if not dmarc_records:
            return DmarcValidationResult(
                domain=domain,
                has_dmarc=False,
                policy="none",
                warnings=["Domain has no published DMARC record at _dmarc." + domain],
            )

        raw = dmarc_records[0]
        warnings: list[str] = []

        # Parse tags (p=..., sp=..., pct=..., rua=...)
        tags: dict[str, str] = {}
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        policy = tags.get("p", "none").lower()
        subdomain_policy = tags.get("sp")
        pct = int(tags.get("pct", "100")) if tags.get("pct", "").isdigit() else 100

        rua_list = [r.strip() for r in tags.get("rua", "").split(",") if r.strip()]

        if policy == "none":
            warnings.append("DMARC policy is set to 'p=none' (monitoring only; does not block spoofed emails).")
        if pct < 100:
            warnings.append(f"DMARC enforcement percentage is limited to {pct}%.")

        return DmarcValidationResult(
            domain=domain,
            raw_record=raw,
            has_dmarc=True,
            policy=policy,
            subdomain_policy=subdomain_policy,
            percentage=pct,
            rua=rua_list,
            warnings=warnings,
        )

    @classmethod
    def inspect_domain(
        cls,
        domain: str,
        originating_ip: Optional[str] = None,
        mock_records: Optional[dict[str, list[str]]] = None,
    ) -> DomainDnsInspection:
        """Execute end-to-end DNS authentication and spoofing resilience audit."""
        clean_domain = domain.strip().lower().lstrip("@")
        spf_res = cls.evaluate_spf(clean_domain, originating_ip, mock_records=mock_records)
        dmarc_res = cls.evaluate_dmarc(clean_domain, mock_records=mock_records)
        mx_records = cls.query_mx_records(clean_domain, mock_records=mock_records)

        risk_score = 0.0
        risk_reasons: list[str] = []

        if not spf_res.has_spf:
            risk_score += 25.0
            risk_reasons.append("Missing SPF record (v=spf1).")
        elif not spf_res.ip_authorized and originating_ip and spf_res.qualifier in ("-", "~"):
            risk_score += 35.0
            risk_reasons.append(f"Originating IP {originating_ip} is NOT authorized by SPF ({spf_res.qualifier}all).")

        if not dmarc_res.has_dmarc:
            risk_score += 30.0
            risk_reasons.append("Missing DMARC policy.")
        elif dmarc_res.policy == "none":
            risk_score += 15.0
            risk_reasons.append("DMARC policy is 'none' (insufficient spoofing protection).")

        if not mx_records and not mock_records:
            # Domain cannot receive mail
            risk_score += 10.0
            risk_reasons.append("No MX mail exchanger records found.")

        return DomainDnsInspection(
            domain=clean_domain,
            originating_ip=originating_ip,
            mx_records=mx_records,
            spf=spf_res,
            dmarc=dmarc_res,
            risk_score=min(100.0, risk_score),
            risk_reasons=risk_reasons,
        )
