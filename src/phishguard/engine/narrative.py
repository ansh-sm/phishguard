"""
Automated SOC Incident Narrative & Remediation Playbook Generator.
"""

from typing import Optional
from phishguard.models.report import ScoreBreakdown, SeverityEnum, VerdictEnum


class NarrativeGenerator:
    """
    Synthesizes forensic findings into plain-English SOC analyst explanations
    and actionable containment playbooks.
    """

    def generate(
        self,
        verdict: VerdictEnum,
        severity: SeverityEnum,
        scores: ScoreBreakdown,
        key_findings: list[str],
        from_email: str,
        originating_ip: Optional[str],
    ) -> tuple[str, list[str]]:
        """
        Generates:
            (written_explanation, remediation_steps)
        """
        # 1. Plain-English SOC Explanation
        explanation_lines = []

        if verdict == VerdictEnum.MALICIOUS:
            explanation_lines.append(
                f"INCIDENT ASSESSMENT: The ingested message is confirmed MALICIOUS ({severity.value} severity, "
                f"Risk Score: {scores.total_score}/100). The email exhibits active phishing, domain impersonation, "
                f"or credential theft indicators."
            )
        elif verdict == VerdictEnum.SUSPICIOUS:
            explanation_lines.append(
                f"INCIDENT ASSESSMENT: The ingested message is classified as SUSPICIOUS ({severity.value} severity, "
                f"Risk Score: {scores.total_score}/100). Several forensic anomalies were detected requiring analyst verification."
            )
        else:
            explanation_lines.append(
                f"INCIDENT ASSESSMENT: The ingested message is classified as CLEAN ({severity.value} severity, "
                f"Risk Score: {scores.total_score}/100). Sender authentication passed and no malicious indicators were discovered."
            )

        if key_findings:
            explanation_lines.append("\nPRIMARY FORENSIC EVIDENCE:")
            for idx, finding in enumerate(key_findings[:5], 1):
                explanation_lines.append(f"  {idx}. {finding}")

        explanation_lines.append(
            f"\nRISK VECTOR BREAKDOWN: Header Security: {scores.header_score}/30 | "
            f"URL & Intel: {scores.url_score}/35 | Attachments: {scores.attachment_score}/20 | "
            f"Content & Social Engineering: {scores.content_score}/15."
        )

        written_explanation = "\n".join(explanation_lines)

        # 2. Actionable Remediation Playbook
        remediation_steps = []
        if verdict == VerdictEnum.MALICIOUS:
            remediation_steps.append("1. [CONTAINMENT] Purge message from all recipient mailboxes via Email Gateway / Microsoft Graph.")
            if from_email:
                remediation_steps.append(f"2. [BORDER BLOCK] Blacklist sender envelope address '{from_email}' on Secure Email Gateway (SEG).")
            if originating_ip:
                remediation_steps.append(f"3. [NETWORK BLOCK] Add originating IP '{originating_ip}' to perimeter firewall drop rules.")
            remediation_steps.append("4. [ENDPOINT CHECK] Query EDR for any process execution spawned by email attachments.")
            remediation_steps.append("5. [IDENTITY] Reset credentials and revoke active session tokens for users who clicked links.")
        elif verdict == VerdictEnum.SUSPICIOUS:
            remediation_steps.append("1. [QUARANTINE] Retain message in administrator quarantine pending secondary review.")
            remediation_steps.append("2. [USER WARNING] Advise recipient not to click links or enter credentials.")
            remediation_steps.append("3. [MONITOR] Watch sender domain for additional incoming volumetric bursts.")
        else:
            remediation_steps.append("1. [NO ACTION REQUIRED] Message passed verification checks. Safe for standard delivery.")

        return written_explanation, remediation_steps
