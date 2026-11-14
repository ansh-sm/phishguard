"""
URL Extraction, Defanging, De-obfuscation, and Deception Analysis.
"""

from collections import Counter
import ipaddress
import math
import re
from typing import Optional
from urllib.parse import unquote, urlparse
from bs4 import BeautifulSoup

from phishguard.models.forensics import UrlArtifact


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (higher entropy indicates randomness / DGA)."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = Counter(text)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def defang_url(url: str) -> str:
    """
    Safely defang a URL to prevent accidental clicks or detonations.
    http -> hxxp, https -> hxxps, . -> [.]
    """
    if not url:
        return ""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]")
    return defanged


def refang_url(defanged_url: str) -> str:
    """Reverse defanging back to a functional URL for threat intelligence lookups."""
    if not defanged_url:
        return ""
    refanged = defanged_url.replace("hxxp://", "http://").replace("hxxps://", "https://")
    refanged = refanged.replace("[.]", ".").replace("[@]", "@")
    return refanged


class UrlAnalyzer:
    """
    Extracts, decodes, and forensically inspects URLs from email bodies.
    """

    URL_REGEX = re.compile(
        r"https?://(?:[a-zA-Z0-9-._~%!$&'()*+,;=:@]+|\[[a-fA-F0-9:.]+\])(?::\d+)?(?:/[^\s<>'\"`]*)?",
        re.IGNORECASE,
    )

    HIGH_RISK_TLDS = {
        "xyz", "top", "click", "link", "work", "live", "loan", "country",
        "bid", "date", "trade", "racing", "download", "stream", "icu", "surf"
    }

    SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "cutt.ly",
        "buff.ly", "rebrand.ly", "tiny.cc", "goo.gl", "qr.ae"
    }

    def extract_and_analyze(self, plain_body: str, html_body: str) -> list[UrlArtifact]:
        """
        Extracts URLs from plaintext and HTML bodies, performs deception checks,
        and returns normalized UrlArtifact list.
        """
        extracted_map: dict[str, dict] = {}

        # 1. Extract from plaintext body
        if plain_body:
            for match in self.URL_REGEX.finditer(plain_body):
                url = match.group(0).rstrip(".,;!)]}\"'>")
                if url not in extracted_map:
                    extracted_map[url] = {"raw_url": url, "anchor_text": None}

        # 2. Extract from HTML body using BeautifulSoup
        if html_body:
            soup = BeautifulSoup(html_body, "html.parser")

            # Extract <a> tags with anchor text
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if href.startswith(("http://", "https://")):
                    anchor_text = a_tag.get_text(strip=True)
                    clean_url = href.rstrip(".,;!)]}\"'>")
                    if clean_url not in extracted_map:
                        extracted_map[clean_url] = {"raw_url": clean_url, "anchor_text": anchor_text}
                    elif not extracted_map[clean_url]["anchor_text"] and anchor_text:
                        extracted_map[clean_url]["anchor_text"] = anchor_text

            # Extract form actions, iframe src, and image links
            for tag, attr in [("form", "action"), ("iframe", "src"), ("embed", "src")]:
                for elem in soup.find_all(tag, attrs={attr: True}):
                    target = elem[attr].strip()
                    if target.startswith(("http://", "https://")):
                        clean_url = target.rstrip(".,;!)]}\"'>")
                        if clean_url not in extracted_map:
                            extracted_map[clean_url] = {"raw_url": clean_url, "anchor_text": f"<{tag} {attr}>"}

        # 3. Analyze each extracted URL
        artifacts: list[UrlArtifact] = []
        for url_info in extracted_map.values():
            artifact = self._inspect_url(url_info["raw_url"], url_info["anchor_text"])
            artifacts.append(artifact)

        return artifacts

    def _inspect_url(self, raw_url: str, anchor_text: Optional[str]) -> UrlArtifact:
        """Deep forensic inspection of an individual URL."""
        # Normalize and unquote
        decoded_url = unquote(raw_url)
        parsed = urlparse(decoded_url)

        host = (parsed.hostname or "").lower()
        scheme = parsed.scheme.lower()
        path = parsed.path or ""

        # Extract TLD
        tld = host.split(".")[-1] if "." in host else ""

        # Deception Indicators
        is_ip = self._check_is_ip(host)
        is_shortener = host in self.SHORTENERS
        is_cred_embedded = bool(parsed.username or parsed.password)
        entropy = calculate_entropy(host)
        is_high_risk = tld in self.HIGH_RISK_TLDS

        # Mismatched anchor check
        is_mismatched = False
        risk_reasons: list[str] = []
        risk_score: float = 0.0

        if anchor_text:
            clean_anchor = anchor_text.strip().lower()
            # If anchor text displays a URL scheme or domain
            if "http://" in clean_anchor or "https://" in clean_anchor or "www." in clean_anchor:
                # Extract displayed host
                displayed_match = re.search(r"(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+)", clean_anchor)
                if displayed_match:
                    displayed_host = displayed_match.group(1).lower()
                    if displayed_host != host and not host.endswith("." + displayed_host):
                        is_mismatched = True
                        risk_reasons.append(
                            f"Hyperlink deception: Anchor text visually claims '{displayed_host}', "
                            f"but actual destination points to '{host}'."
                        )
                        risk_score += 35.0

        if is_ip:
            risk_reasons.append(f"Host uses bare IP literal '{host}' rather than a domain name.")
            risk_score += 25.0

        if is_cred_embedded:
            risk_reasons.append("URL contains embedded credentials/userinfo syntax.")
            risk_score += 20.0

        if is_shortener:
            risk_reasons.append(f"URL uses known shortening service '{host}' to conceal final destination.")
            risk_score += 15.0

        if is_high_risk:
            risk_reasons.append(f"Domain uses high-abuse top-level domain '.{tld}'.")
            risk_score += 15.0

        if entropy > 4.2 and len(host) > 12:
            risk_reasons.append(f"High domain entropy ({entropy}) indicates algorithmically generated domain (DGA).")
            risk_score += 15.0

        return UrlArtifact(
            raw_url=raw_url,
            defanged_url=defang_url(raw_url),
            domain=host,
            tld=tld,
            scheme=scheme,
            path=path,
            anchor_text=anchor_text,
            is_mismatched_anchor=is_mismatched,
            is_ip_host=is_ip,
            is_shortener=is_shortener,
            is_credential_embedded=is_cred_embedded,
            domain_entropy=entropy,
            is_high_risk_tld=is_high_risk,
            risk_score=min(100.0, risk_score),
            risk_reasons=risk_reasons,
        )

    @staticmethod
    def _check_is_ip(host: str) -> bool:
        """Check if hostname is an IPv4 or IPv6 literal."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
