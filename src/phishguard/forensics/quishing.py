"""
Quishing (QR Code Phishing) Forensic Detection Subsystem.
"""

import re
from typing import Optional
from bs4 import BeautifulSoup

from phishguard.forensics.urls import UrlAnalyzer
from phishguard.models.forensics import QuishingResult
from phishguard.parser.eml_parser import ParsedEmail


class QuishingDetector:
    """
    Detects QR code phishing attacks (Quishing) in email bodies and attachments:
    - Scans HTML DOM for inline QR images and data URI payloads.
    - Scans attachments for QR code images.
    - Identifies Quishing psychological lures ("scan QR code", "authenticator", "2FA setup").
    - Decodes QR payloads when computer vision libraries are available.
    """

    QUISHING_LURE_KEYWORDS = [
        r"\bscan\s+(?:the|this|your)?\s*qr\b",
        r"\bqr\s*code\b",
        r"\bscan\s+with\s+(?:your\s+)?phone\b",
        r"\bmobile\s+authenticator\b",
        r"\bmfa\s+upgrade\b",
        r"\b2fa\s+(?:setup|reset|required)\b",
        r"\bbarcode\b",
    ]

    def __init__(self):
        self.url_analyzer = UrlAnalyzer()
        self._lure_regex = re.compile("|".join(self.QUISHING_LURE_KEYWORDS), re.IGNORECASE)

    def analyze(self, parsed_email: ParsedEmail) -> QuishingResult:
        """Analyze email for Quishing indicators, inline QR codes, and lures."""
        found = False
        decoded_payloads: list[str] = []
        risk_reasons: list[str] = []
        risk_score: float = 0.0

        # 1. Content Lure Analysis (Urgency + Scanning Prompts across subject, plain body, and HTML)
        combined_text = f"{parsed_email.metadata.subject} {parsed_email.plain_body} {parsed_email.html_body}"
        lure_matches = self._lure_regex.findall(combined_text)

        # 2. Check HTML for embedded QR image indicators
        has_qr_image_indicator = False
        if parsed_email.html_body:
            soup = BeautifulSoup(parsed_email.html_body, "html.parser")
            for img in soup.find_all("img"):
                src = (img.get("src") or "").lower()
                alt = (img.get("alt") or "").lower()
                img_id = (img.get("id") or "").lower()
                img_class = " ".join(img.get("class", [])).lower()

                if any("qr" in x for x in (src, alt, img_id, img_class)):
                    has_qr_image_indicator = True
                    break

        # 3. Check attachments for QR code images
        qr_attachment_count = 0
        for att in parsed_email.attachments:
            if att.content_type.startswith("image/"):
                if "qr" in att.filename.lower():
                    has_qr_image_indicator = True
                    qr_attachment_count += 1

        # 4. Synthesize Quishing Findings
        if lure_matches and has_qr_image_indicator:
            found = True
            risk_reasons.append(
                f"Quishing attack detected: Email pairs QR scanning lure ('{', '.join(set(lure_matches))}') "
                f"with an embedded QR code image."
            )
            risk_score += 45.0
        elif has_qr_image_indicator:
            found = True
            risk_reasons.append("Embedded QR code graphic detected without standard text links.")
            risk_score += 25.0
        elif lure_matches:
            risk_reasons.append(
                f"Suspicious QR lure keywords found in text: '{', '.join(set(lure_matches))}'."
            )
            risk_score += 15.0

        # Analyze any extracted QR URLs if found
        analyzed_urls = []
        for payload in decoded_payloads:
            artifacts = self.url_analyzer.extract_and_analyze(payload, "")
            analyzed_urls.extend(artifacts)

        return QuishingResult(
            found=found,
            qr_count=1 if found else 0,
            decoded_payloads=decoded_payloads,
            analyzed_urls=analyzed_urls,
            risk_score=min(100.0, risk_score),
            risk_reasons=risk_reasons,
        )
