"""
Multi-Vector Scoring Model for PhishGuard SOC.
"""

from typing import Optional
from phishguard.models.email import AuthStatus
from phishguard.models.forensics import (
    AttachmentArtifact,
    HeaderAnalysis,
    QuishingResult,
    UrlArtifact,
)
from phishguard.models.report import ScoreBreakdown, SeverityEnum, VerdictEnum


class ScoringEngine:
    """
    Transparent, explainable multi-vector scoring engine.
    Calculates weighted risk scores (0-100) across Header, URL, Attachment, and Content vectors.
    """

    CONTENT_URGENCY_KEYWORDS = [
        "urgent", "immediately", "within 24 hours", "account suspended",
        "temporarily limited", "unauthorized login", "action required",
        "permanent closure", "password expired", "wire transfer", "gift card"
    ]

    CREDENTIAL_KEYWORDS = [
        "verify your identity", "confirm your account", "verify password",
        "update billing", "login to confirm", "sign in to verify"
    ]

    def calculate(
        self,
        headers: HeaderAnalysis,
        urls: list[UrlArtifact],
        attachments: list[AttachmentArtifact],
        quishing: Optional[QuishingResult],
        plain_body: str,
        subject: str,
    ) -> tuple[ScoreBreakdown, VerdictEnum, SeverityEnum, float, list[str]]:
        """
        Calculates all sub-scores, verdict, severity, forensic confidence, and key findings.
        """
        key_findings: list[str] = []

        # 1. Header Risk Sub-score (Max 30)
        h_score = headers.risk_score
        auth = headers.auth

        if auth.dmarc_status == AuthStatus.FAIL:
            h_score += 15.0
            key_findings.append(f"DMARC validation failed (Action: {auth.dmarc_action or 'none'}).")
        if auth.spf_status in (AuthStatus.FAIL, AuthStatus.PERMERROR):
            h_score += 15.0
            key_findings.append(f"SPF validation failed for sender IP {auth.spf_sender_ip or 'unknown'}.")
        elif auth.spf_status == AuthStatus.SOFTFAIL:
            h_score += 8.0
            key_findings.append("SPF softfail: sender IP is not strictly authorized by sender policy.")

        if auth.dkim_status == AuthStatus.FAIL:
            h_score += 10.0
            key_findings.append("DKIM cryptographic signature verification failed.")

        for anomaly in headers.anomalies:
            if anomaly not in key_findings:
                key_findings.append(anomaly)

        header_score = min(30.0, h_score)

        # 2. URL & Threat Intel Sub-score (Max 35)
        u_score = 0.0
        for u in urls:
            if u.threat_intel_flagged:
                u_score += 35.0
                key_findings.append(f"Malicious URL detected: {u.defanged_url} (Flagged by {u.threat_intel_source}).")
                break
            if u.is_mismatched_anchor:
                u_score += 25.0
                key_findings.append(f"Deceptive hyperlink: Anchor text claims legitimate site, href routes to {u.defanged_url}.")
            if u.is_ip_host:
                u_score += 15.0
            if u.is_high_risk_tld or u.domain_entropy > 4.2:
                u_score += 10.0

        url_score = min(35.0, u_score)

        # 3. Attachment Forensics Sub-score (Max 30)
        has_critical_attachment = False
        a_score = 0.0
        for att in attachments:
            if att.risk_score > 0:
                a_score += (att.risk_score / 100.0) * 30.0
                for r in att.risk_reasons:
                    if r not in key_findings:
                        key_findings.append(r)
            if att.is_executable or att.is_double_extension or att.has_macros:
                has_critical_attachment = True

        attachment_score = min(30.0, a_score)

        # 4. Content & Urgency Sub-score (Max 15)
        c_score = 0.0
        combined_text = f"{subject} {plain_body}".lower()

        urgency_hits = [k for k in self.CONTENT_URGENCY_KEYWORDS if k in combined_text]
        if urgency_hits:
            c_score += 7.0
            key_findings.append(f"High urgency psychological lures present: '{', '.join(urgency_hits[:3])}'.")

        cred_hits = [k for k in self.CREDENTIAL_KEYWORDS if k in combined_text]
        if cred_hits:
            c_score += 8.0
            key_findings.append(f"Credential harvesting indicators present: '{', '.join(cred_hits[:2])}'.")

        if quishing and quishing.found:
            c_score += 10.0
            for r in quishing.risk_reasons:
                if r not in key_findings:
                    key_findings.append(r)

        content_score = min(15.0, c_score)

        # Total Aggregation
        total_score = round(min(100.0, header_score + url_score + attachment_score + content_score), 1)

        # Critical override: if dangerous executable/double-extension attachment is present
        if has_critical_attachment:
            total_score = max(total_score, 75.0)

        # Verdict Classification
        if total_score >= 60.0:
            verdict = VerdictEnum.MALICIOUS
            severity = SeverityEnum.CRITICAL if total_score >= 80.0 else SeverityEnum.HIGH
        elif total_score >= 26.0:
            verdict = VerdictEnum.SUSPICIOUS
            severity = SeverityEnum.HIGH if total_score >= 45.0 else SeverityEnum.MEDIUM
        else:
            verdict = VerdictEnum.CLEAN
            severity = SeverityEnum.LOW

        # Confidence calculation
        confidence = 98.0 if (header_score > 20 or url_score > 25 or attachment_score > 15) else 90.0

        score_breakdown = ScoreBreakdown(
            header_score=round(header_score, 1),
            url_score=round(url_score, 1),
            attachment_score=round(attachment_score, 1),
            content_score=round(content_score, 1),
            total_score=total_score,
        )

        return score_breakdown, verdict, severity, confidence, key_findings
