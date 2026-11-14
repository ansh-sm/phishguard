"""
Spoofing, Impersonation, Homoglyph, and Typosquatting Detection Engine.
"""

import re
from typing import Optional
import unicodedata

from phishguard.models.email import EmailMetadata


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class SpoofingDetector:
    """
    Detects brand impersonation, display name spoofing,
    homoglyph/Punycode attacks, and envelope mismatches.
    """

    # Top targeted enterprise brands & their authoritative domains
    BRAND_CATALOG: dict[str, list[str]] = {
        "paypal": ["paypal.com"],
        "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "office365.com"],
        "google": ["google.com", "gmail.com", "googlemail.com"],
        "apple": ["apple.com", "icloud.com"],
        "amazon": ["amazon.com", "aws.amazon.com"],
        "netflix": ["netflix.com"],
        "docusign": ["docusign.com", "docusign.net"],
        "chase": ["chase.com"],
        "wellsfargo": ["wellsfargo.com"],
        "bankofamerica": ["bankofamerica.com", "bofa.com"],
        "dhl": ["dhl.com", "dhl.de"],
        "fedex": ["fedex.com"],
        "meta": ["meta.com", "facebook.com", "instagram.com"],
    }

    # Common Cyrillic and Greek homoglyphs that visually mimic Latin letters
    HOMOGLYPH_MAP: dict[str, str] = {
        "\u0430": "a",  # Cyrillic small letter a
        "\u0441": "c",  # Cyrillic small letter es
        "\u0435": "e",  # Cyrillic small letter ie
        "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
        "\u0458": "j",  # Cyrillic small letter je
        "\u043e": "o",  # Cyrillic small letter o
        "\u0440": "p",  # Cyrillic small letter er
        "\u0455": "s",  # Cyrillic small letter dze
        "\u0443": "y",  # Cyrillic small letter u
        "\u0445": "x",  # Cyrillic small letter ha
        "\u03bf": "o",  # Greek small letter omicron
        "\u03c1": "p",  # Greek small letter rho
    }

    def analyze(
        self, metadata: EmailMetadata
    ) -> tuple[bool, bool, bool, bool, Optional[str], list[str], float]:
        """
        Analyzes sender metadata for spoofing and impersonation.
        Returns:
            (display_name_spoof, reply_to_mismatch, punycode_detected, homoglyph_detected, lookalike_target, anomalies, risk_score)
        """
        anomalies: list[str] = []
        risk_score: float = 0.0

        display_name_spoof = False
        reply_to_mismatch = False
        punycode_detected = False
        homoglyph_detected = False
        lookalike_target: Optional[str] = None

        from_domain = metadata.from_domain.lower() if metadata.from_domain else ""
        from_name = (metadata.from_name or "").strip()

        # 1. Punycode & Homoglyph detection in sender domain
        if "xn--" in from_domain:
            punycode_detected = True
            anomalies.append(f"Sender domain uses Punycode / IDN encoding ('{from_domain}'). High-risk homograph indicator.")
            risk_score += 20.0

        for char in from_domain:
            if char in self.HOMOGLYPH_MAP:
                homoglyph_detected = True
                norm_char = self.HOMOGLYPH_MAP[char]
                anomalies.append(
                    f"Internationalized homoglyph character detected in sender domain: '{char}' (mimics Latin '{norm_char}')."
                )
                risk_score += 25.0
                break

        # 2. Brand Typosquatting / Lookalike Domain Detection
        # Clean domain of subdomains and TLD for comparison (e.g. "paypa1-update.com" -> "paypa1-update")
        domain_parts = from_domain.split(".")
        main_domain = domain_parts[0] if len(domain_parts) >= 2 else from_domain
        # Also clean common leetspeak substitutions (e.g. '1' -> 'l', '0' -> 'o')
        leetspeak_normalized = (
            main_domain.replace("1", "l")
            .replace("0", "o")
            .replace("3", "e")
            .replace("5", "s")
        )

        for brand, legitimate_domains in self.BRAND_CATALOG.items():
            if from_domain in legitimate_domains:
                # Legitimate brand domain
                continue

            # Check if brand appears in main domain with extra words (e.g. paypa1-update, paypal-security)
            if brand in leetspeak_normalized or brand in main_domain:
                lookalike_target = brand.capitalize()
                anomalies.append(
                    f"Sender domain '{from_domain}' typosquats or incorporates enterprise brand '{lookalike_target}' "
                    f"without authoritative ownership."
                )
                risk_score += 25.0
                break

            # Check Levenshtein distance on base domain name
            dist = levenshtein_distance(main_domain, brand)
            if 0 < dist <= 2 and len(brand) >= 4:
                lookalike_target = brand.capitalize()
                anomalies.append(
                    f"Sender domain '{from_domain}' closely resembles protected brand '{lookalike_target}' "
                    f"(Levenshtein distance = {dist})."
                )
                risk_score += 25.0
                break

        # 3. Display Name Impersonation
        if from_name:
            # Check if display name contains an embedded email address
            embedded_email = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", from_name)
            if embedded_email:
                addr = embedded_email.group(0).lower()
                if addr != metadata.from_email.lower():
                    display_name_spoof = True
                    anomalies.append(
                        f"Display name spoofing: Display name contains address '{addr}' "
                        f"which does not match actual envelope '{metadata.from_email}'."
                    )
                    risk_score += 20.0

            # Check if display name mentions a brand while domain is unaffiliated
            for brand, legitimate_domains in self.BRAND_CATALOG.items():
                if brand in from_name.lower():
                    if not any(from_domain == d or from_domain.endswith("." + d) for d in legitimate_domains):
                        display_name_spoof = True
                        anomalies.append(
                            f"Display name impersonation: From name references '{brand.capitalize()}', "
                            f"but sender domain '{from_domain}' is not an authorized domain."
                        )
                        risk_score += 15.0
                        break

        # 4. Reply-To & Return-Path Disparities
        if metadata.reply_to_domain and from_domain:
            if metadata.reply_to_domain != from_domain:
                reply_to_mismatch = True
                anomalies.append(
                    f"Reply-To address mismatch: Responses will be routed to '{metadata.reply_to_email}' "
                    f"(domain '{metadata.reply_to_domain}'), differing from sender domain '{from_domain}'."
                )
                risk_score += 10.0

        if metadata.return_path_domain and from_domain:
            if metadata.return_path_domain != from_domain:
                anomalies.append(
                    f"Return-Path domain mismatch: Bounces routed to '{metadata.return_path_domain}', "
                    f"differing from sender domain '{from_domain}'."
                )
                risk_score += 5.0

        return (
            display_name_spoof,
            reply_to_mismatch,
            punycode_detected,
            homoglyph_detected,
            lookalike_target,
            anomalies,
            min(30.0, risk_score),
        )
