"""
MITRE ATT&CK Framework Mapping Engine for PhishGuard SOC.
Maps forensic indicators to Enterprise ATT&CK tactics, techniques, and sub-techniques.
"""

from typing import Optional

from phishguard.models.forensics import (
    AttachmentArtifact,
    HeaderAnalysis,
    QuishingResult,
    UrlArtifact,
)
from phishguard.models.report import MitreTechnique, ScoreBreakdown


class MitreAttackMapper:
    """
    Evaluates analysis artifacts against the MITRE ATT&CK Enterprise Matrix.
    """

    TECHNIQUE_CATALOG: dict[str, dict] = {
        "T1566.001": {
            "name": "Spearphishing Attachment",
            "tactic": "Initial Access",
            "description": "Adversaries send spearphishing emails with malicious attachments to gain code execution.",
            "url": "https://attack.mitre.org/techniques/T1566/001/",
        },
        "T1566.002": {
            "name": "Spearphishing Link",
            "tactic": "Initial Access",
            "description": "Adversaries send spearphishing emails with links leading to credential harvesting sites or exploit payloads.",
            "url": "https://attack.mitre.org/techniques/T1566/002/",
        },
        "T1566.003": {
            "name": "Spearphishing via Service",
            "tactic": "Initial Access",
            "description": "Adversaries leverage third-party redirectors or URL shorteners to evade security gateways.",
            "url": "https://attack.mitre.org/techniques/T1566/003/",
        },
        "T1036.005": {
            "name": "Masquerading: Match Legitimate Name or Location",
            "tactic": "Defense Evasion",
            "description": "Adversaries masquerade as legitimate brands or identities using typosquatting, homoglyphs, or display name spoofing.",
            "url": "https://attack.mitre.org/techniques/T1036/005/",
        },
        "T1583.001": {
            "name": "Acquire Infrastructure: Domains",
            "tactic": "Resource Development",
            "description": "Adversaries acquire algorithmically generated or high-risk top-level domains for attack staging.",
            "url": "https://attack.mitre.org/techniques/T1583/001/",
        },
        "T1204.001": {
            "name": "User Execution: Malicious Link",
            "tactic": "Execution",
            "description": "Adversaries rely on social engineering and urgency lures to induce victims into clicking malicious links.",
            "url": "https://attack.mitre.org/techniques/T1204/001/",
        },
        "T1204.002": {
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "description": "Adversaries rely on victims opening weaponized attachments (executables, macros, or scripts).",
            "url": "https://attack.mitre.org/techniques/T1204/002/",
        },
    }

    def map_attack(
        self,
        headers: HeaderAnalysis,
        urls: list[UrlArtifact],
        attachments: list[AttachmentArtifact],
        quishing: Optional[QuishingResult],
        scores: ScoreBreakdown,
    ) -> list[MitreTechnique]:
        """Maps forensic artifacts to observed MITRE ATT&CK techniques."""
        identified_techniques: list[MitreTechnique] = []

        # 1. T1036.005 - Masquerading (Typosquatting, Homoglyphs, Display Name Spoofing)
        masq_evidence = []
        if headers.lookalike_domain and headers.lookalike_target:
            masq_evidence.append(f"Domain typosquatting impersonating '{headers.lookalike_target}'")
        if headers.homoglyph_detected or headers.punycode_detected:
            masq_evidence.append("Internationalized homoglyph or Punycode IDN encoding detected")
        if headers.display_name_spoof:
            masq_evidence.append("Sender display name spoofing detected")
        if headers.reply_to_mismatch:
            masq_evidence.append("Reply-To envelope redirection disparity")

        if masq_evidence:
            spec = self.TECHNIQUE_CATALOG["T1036.005"]
            identified_techniques.append(
                MitreTechnique(
                    technique_id="T1036.005",
                    technique_name=spec["name"],
                    tactic=spec["tactic"],
                    description=spec["description"],
                    confidence="HIGH",
                    evidence=masq_evidence,
                    attack_url=spec["url"],
                )
            )

        # 2. T1566.002 - Spearphishing Link & T1204.001 - User Execution: Malicious Link
        link_evidence = []
        shortener_evidence = []
        for u in urls:
            if u.is_mismatched_anchor:
                link_evidence.append(f"Deceptive hyperlink mismatch pointing to {u.defanged_url}")
            if u.threat_intel_flagged:
                link_evidence.append(f"Malicious URL confirmed by threat intel: {u.defanged_url}")
            if u.is_ip_host:
                link_evidence.append(f"Host destination is a bare IP address ({u.domain})")
            if u.is_shortener:
                shortener_evidence.append(f"URL obfuscated with shortening service '{u.domain}'")

        if link_evidence:
            spec = self.TECHNIQUE_CATALOG["T1566.002"]
            identified_techniques.append(
                MitreTechnique(
                    technique_id="T1566.002",
                    technique_name=spec["name"],
                    tactic=spec["tactic"],
                    description=spec["description"],
                    confidence="HIGH",
                    evidence=link_evidence,
                    attack_url=spec["url"],
                )
            )
            # Add T1204.001 User Execution
            exec_spec = self.TECHNIQUE_CATALOG["T1204.001"]
            identified_techniques.append(
                MitreTechnique(
                    technique_id="T1204.001",
                    technique_name=exec_spec["name"],
                    tactic=exec_spec["tactic"],
                    description=exec_spec["description"],
                    confidence="HIGH",
                    evidence=["Social engineering urgency lure directing user to execute link action"],
                    attack_url=exec_spec["url"],
                )
            )

        # 3. T1566.003 - Spearphishing via Service (Shorteners / QR codes)
        if shortener_evidence or (quishing and quishing.found):
            evidence = list(shortener_evidence)
            if quishing and quishing.found:
                evidence.append("Quishing attack utilizing QR code graphics to bypass URL inspection filters")
            spec = self.TECHNIQUE_CATALOG["T1566.003"]
            identified_techniques.append(
                MitreTechnique(
                    technique_id="T1566.003",
                    technique_name=spec["name"],
                    tactic=spec["tactic"],
                    description=spec["description"],
                    confidence="HIGH" if quishing and quishing.found else "MEDIUM",
                    evidence=evidence,
                    attack_url=spec["url"],
                )
            )

        # 4. T1566.001 - Spearphishing Attachment & T1204.002 - User Execution: File
        att_evidence = []
        for att in attachments:
            if att.is_executable or att.is_double_extension or att.has_macros:
                att_evidence.append(f"Weaponized payload attachment: '{att.filename}' (SHA256: {att.sha256[:12]}...)")
            elif att.is_archive and att.archive_contents:
                att_evidence.append(f"Compressed archive attachment concealing items: '{att.filename}'")

        if att_evidence:
            spec = self.TECHNIQUE_CATALOG["T1566.001"]
            identified_techniques.append(
                MitreTechnique(
                    technique_id="T1566.001",
                    technique_name=spec["name"],
                    tactic=spec["tactic"],
                    description=spec["description"],
                    confidence="HIGH",
                    evidence=att_evidence,
                    attack_url=spec["url"],
                )
            )
            exec_spec = self.TECHNIQUE_CATALOG["T1204.002"]
            identified_techniques.append(
                MitreTechnique(
                    technique_id="T1204.002",
                    technique_name=exec_spec["name"],
                    tactic=exec_spec["tactic"],
                    description=exec_spec["description"],
                    confidence="HIGH",
                    evidence=["Email lures user into executing attached malicious binary or document macro"],
                    attack_url=exec_spec["url"],
                )
            )

        # 5. T1583.001 - Acquire Infrastructure: Domains
        dga_evidence = []
        for u in urls:
            if u.domain_entropy > 4.2:
                dga_evidence.append(f"High-entropy DGA domain: {u.domain} (Entropy: {u.domain_entropy})")
            if u.is_high_risk_tld:
                dga_evidence.append(f"High-risk abuse TLD used: .{u.tld}")

        if dga_evidence:
            spec = self.TECHNIQUE_CATALOG["T1583.001"]
            identified_techniques.append(
                MitreTechnique(
                    technique_id="T1583.001",
                    technique_name=spec["name"],
                    tactic=spec["tactic"],
                    description=spec["description"],
                    confidence="MEDIUM",
                    evidence=dga_evidence,
                    attack_url=spec["url"],
                )
            )

        return identified_techniques
