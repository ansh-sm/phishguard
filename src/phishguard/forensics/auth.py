"""
Email Authentication Parser (SPF, DKIM, DMARC).
"""

import re
from typing import Optional
from phishguard.models.email import AuthenticationResults, AuthStatus


class AuthResultsParser:
    """
    Parses RFC 8601 'Authentication-Results' and 'Received-SPF' headers.
    """

    SPF_REGEX = re.compile(
        r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE
    )
    SPF_IP_REGEX = re.compile(r"\b(?:sender\s+IP\s+is|client-ip=)\s*([0-9a-fA-F.:]+)", re.IGNORECASE)
    SPF_DOMAIN_REGEX = re.compile(r"\bsmtp\.mailfrom=([^\s;]+)", re.IGNORECASE)

    DKIM_REGEX = re.compile(
        r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b", re.IGNORECASE
    )
    DKIM_DOMAIN_REGEX = re.compile(r"\b(?:header\.[id]=|header\.i=@)([^\s;]+)", re.IGNORECASE)
    DKIM_SELECTOR_REGEX = re.compile(r"\bheader\.s=([^\s;]+)", re.IGNORECASE)

    DMARC_REGEX = re.compile(
        r"\bdmarc=(pass|fail|none|temperror|permerror)\b", re.IGNORECASE
    )
    DMARC_ACTION_REGEX = re.compile(r"\baction=(none|quarantine|reject)\b", re.IGNORECASE)

    def parse(self, auth_headers: list[str]) -> AuthenticationResults:
        """
        Parse raw Authentication-Results or Received-SPF headers into structured AuthenticationResults.
        """
        combined = " ; ".join(auth_headers)
        if not combined.strip():
            return AuthenticationResults(raw_header=None)

        # 1. Parse SPF
        spf_status = AuthStatus.UNKNOWN
        spf_match = self.SPF_REGEX.search(combined)
        if spf_match:
            try:
                spf_status = AuthStatus(spf_match.group(1).lower())
            except ValueError:
                spf_status = AuthStatus.UNKNOWN

        spf_ip_match = self.SPF_IP_REGEX.search(combined)
        spf_sender_ip = spf_ip_match.group(1).strip("()[]") if spf_ip_match else None

        spf_domain_match = self.SPF_DOMAIN_REGEX.search(combined)
        spf_domain = spf_domain_match.group(1).strip("<>") if spf_domain_match else None

        # 2. Parse DKIM
        dkim_status = AuthStatus.UNKNOWN
        dkim_match = self.DKIM_REGEX.search(combined)
        if dkim_match:
            try:
                dkim_status = AuthStatus(dkim_match.group(1).lower())
            except ValueError:
                dkim_status = AuthStatus.UNKNOWN

        dkim_domain_match = self.DKIM_DOMAIN_REGEX.search(combined)
        dkim_domain = dkim_domain_match.group(1).lstrip("@") if dkim_domain_match else None

        dkim_sel_match = self.DKIM_SELECTOR_REGEX.search(combined)
        dkim_selector = dkim_sel_match.group(1) if dkim_sel_match else None

        # 3. Parse DMARC
        dmarc_status = AuthStatus.UNKNOWN
        dmarc_match = self.DMARC_REGEX.search(combined)
        if dmarc_match:
            try:
                dmarc_status = AuthStatus(dmarc_match.group(1).lower())
            except ValueError:
                dmarc_status = AuthStatus.UNKNOWN

        dmarc_act_match = self.DMARC_ACTION_REGEX.search(combined)
        dmarc_action = dmarc_act_match.group(1).lower() if dmarc_act_match else None

        return AuthenticationResults(
            spf_status=spf_status,
            spf_domain=spf_domain,
            spf_sender_ip=spf_sender_ip,
            dkim_status=dkim_status,
            dkim_domain=dkim_domain,
            dkim_selector=dkim_selector,
            dmarc_status=dmarc_status,
            dmarc_action=dmarc_action,
            raw_header=combined,
        )
