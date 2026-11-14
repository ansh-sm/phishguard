"""
Header Forensics and Hop Route Reconstruction Subsystem.
"""

from datetime import datetime
import ipaddress
import re
from typing import Optional
import dateutil.parser

from phishguard.models.email import EmailMetadata, ReceivedHop
from phishguard.parser.eml_parser import ParsedEmail


class ReceivedHopParser:
    """
    Parses and traces RFC 5321/5322 'Received:' header routing hops.
    Reconstructs hops in chronological order (origin to final recipient gateway).
    """

    # Regex patterns for RFC 5321 Received header components
    # e.g.: "from mail-relay.paypa1-update.com (185.220.101.5) by mx.enterprise.corp (Postfix) with ESMTPS id 4X98Kj2 for <target@corp.com>; Fri, 14 Nov 2026 18:22:15 +0000"
    IP_REGEX = re.compile(
        r"(?:\[?(\b(?:\d{1,3}\.){3}\d{1,3}\b)\]?)|"  # IPv4
        r"(?:\[?([a-fA-F0-9:]{3,39})\]?)"            # IPv6
    )
    FROM_REGEX = re.compile(r"\bfrom\s+([^\s();]+)", re.IGNORECASE)
    BY_REGEX = re.compile(r"\bby\s+([^\s();]+)", re.IGNORECASE)
    WITH_REGEX = re.compile(r"\bwith\s+([^\s();]+)", re.IGNORECASE)

    def parse_hops(self, raw_received_headers: list[str]) -> list[ReceivedHop]:
        """
        Parses raw Received header lines into ordered ReceivedHop instances.
        Headers are passed in the order found in the EML (top-to-bottom: newest to oldest).
        This method reverses them so Hop 0 is closest to the origin.
        """
        if not raw_received_headers:
            return []

        # Reverse list so chronological order is origin -> destination
        chronological_headers = list(reversed(raw_received_headers))
        hops: list[ReceivedHop] = []

        previous_dt: Optional[datetime] = None

        for idx, raw_header in enumerate(chronological_headers):
            normalized = " ".join(raw_header.split())
            
            # Split off date clause if present (usually follows semicolon)
            date_clause = None
            date_dt = None
            if ";" in normalized:
                parts = normalized.rsplit(";", 1)
                routing_part = parts[0].strip()
                date_clause = parts[1].strip()
                try:
                    date_dt = dateutil.parser.parse(date_clause)
                except Exception:
                    date_dt = None
            else:
                routing_part = normalized

            # Extract from host
            from_match = self.FROM_REGEX.search(routing_part)
            from_host = from_match.group(1) if from_match else None

            # Extract by host
            by_match = self.BY_REGEX.search(routing_part)
            by_host = by_match.group(1) if by_match else None

            # Extract with protocol
            with_match = self.WITH_REGEX.search(routing_part)
            protocol = with_match.group(1) if with_match else None

            # Extract IP address from routing clause
            client_ip = self._extract_ip(routing_part)
            is_private = self._is_private_ip(client_ip) if client_ip else False

            # Latency delta from previous hop
            delay_seconds = None
            if previous_dt and date_dt:
                try:
                    delta = (date_dt - previous_dt).total_seconds()
                    delay_seconds = delta
                except Exception:
                    delay_seconds = None

            if date_dt:
                previous_dt = date_dt

            hops.append(
                ReceivedHop(
                    hop_index=idx,
                    from_host=from_host,
                    by_host=by_host,
                    client_ip=client_ip,
                    is_private_ip=is_private,
                    protocol=protocol,
                    timestamp=date_dt,
                    raw_date=date_clause,
                    delay_from_previous_seconds=delay_seconds,
                )
            )

        return hops

    def _extract_ip(self, routing_text: str) -> Optional[str]:
        """Extract first valid IPv4 or IPv6 found in parentheses or brackets."""
        # Focus on the part immediately following 'from' or in brackets/parentheses
        for match in self.IP_REGEX.finditer(routing_text):
            candidate = match.group(1) or match.group(2)
            if candidate and self._validate_ip(candidate):
                return candidate
        return None

    @staticmethod
    def _validate_ip(ip_str: str) -> bool:
        """Validate if string is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if IP address belongs to RFC 1918 private, loopback, or reserved range."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
        except ValueError:
            return False


class HeaderForensicsEngine:
    """
    Forensic analysis of email headers:
    - Originating external IP identification
    - Latency anomaly and clock skew detection
    - Missing standard RFC headers
    - Header injection & anomalies
    """

    def __init__(self):
        self.hop_parser = ReceivedHopParser()

    def analyze_headers(self, parsed_email: ParsedEmail) -> tuple[list[ReceivedHop], Optional[str], list[str], float]:
        """
        Runs forensic inspection on headers.
        Returns:
            (hops, originating_ip, anomalies_list, risk_score_deduction)
        """
        anomalies: list[str] = []
        risk_score: float = 0.0

        # 1. Parse Received hops
        hops = self.hop_parser.parse_hops(parsed_email.received_headers)

        # 2. Identify true originating external IP
        originating_ip = None
        for hop in hops:
            if hop.client_ip and not hop.is_private_ip:
                originating_ip = hop.client_ip
                break

        # Fallback if all IPs are private or none found
        if not originating_ip and hops:
            for hop in hops:
                if hop.client_ip:
                    originating_ip = hop.client_ip
                    break

        # 3. Check for hop anomalies
        if not hops:
            anomalies.append("No Received headers present (Message may be locally generated or stripped)")
            risk_score += 10.0
        else:
            # Check for negative latency / clock skew
            for hop in hops:
                if hop.delay_from_previous_seconds is not None and hop.delay_from_previous_seconds < -300:
                    anomalies.append(
                        f"Significant negative latency detected at hop #{hop.hop_index} "
                        f"({hop.delay_from_previous_seconds}s). Possible header falsification or severe clock skew."
                    )
                    risk_score += 5.0
                    break

        # 4. RFC 5322 Compliance anomalies
        raw_headers_lower = [k.lower() for k, _ in parsed_email.headers]

        # Duplicate From headers (dangerous RFC violation)
        from_count = raw_headers_lower.count("from")
        if from_count > 1:
            anomalies.append(f"Multiple 'From' headers detected ({from_count}). Critical RFC 5322 violation / parser exploit lure.")
            risk_score += 25.0

        # Missing Message-ID or Date
        if "message-id" not in raw_headers_lower:
            anomalies.append("Missing standard 'Message-ID' header.")
            risk_score += 5.0
        if "date" not in raw_headers_lower:
            anomalies.append("Missing standard 'Date' header.")
            risk_score += 5.0

        # Check for CRLF / header injection indicators in header keys or values
        for k, v in parsed_email.headers:
            if "\r" in v or "\n" in v:
                # Normal unfolding has \r\n followed by whitespace; bare newlines without whitespace indicate injection
                if re.search(r"[\r\n]+[^\s\t]", v):
                    anomalies.append(f"Unsanitized newline detected in header '{k}'. Potential header injection.")
                    risk_score += 15.0

        # Check X-Mailer / User-Agent indicators
        x_mailer = parsed_email.metadata.x_mailer or ""
        user_agent = parsed_email.metadata.user_agent or ""
        suspicious_mailers = ["phpmailer", "darkmailer", "massmailer", "directmail", "super mailer", "bulk email"]
        for tool in suspicious_mailers:
            if tool in x_mailer.lower() or tool in user_agent.lower():
                anomalies.append(f"Suspicious mass-mailing software signature detected: '{x_mailer or user_agent}'.")
                risk_score += 10.0
                break

        return hops, originating_ip, anomalies, min(30.0, risk_score)
