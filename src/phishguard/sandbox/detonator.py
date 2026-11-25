"""Dynamic URL detonation and headless DOM analysis engine."""

from __future__ import annotations

import re
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from phishguard.sandbox.models import (
    BrandImpersonationDetection,
    DetonationVerdict,
    FormTarget,
    RedirectHop,
    UrlDetonationResult,
)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

KNOWN_BRANDS: dict[str, dict[str, list[str]]] = {
    "Microsoft": {
        "legit_domains": [
            "microsoft.com", "live.com", "office.com", "azure.com",
            "office365.com", "sharepoint.com", "outlook.com", "msft.net"
        ],
        "title_keywords": [
            "microsoft", "office 365", "sign in to your account",
            "outlook web app", "azure portal", "microsoft online"
        ],
        "body_keywords": [
            "microsoft corporation", "sign in to access your microsoft",
            "keep me signed in", "work or school account", "cant access your account"
        ],
    },
    "Google": {
        "legit_domains": ["google.com", "accounts.google.com", "gmail.com", "google.co.uk"],
        "title_keywords": ["sign in - google accounts", "google login", "gmail sign in"],
        "body_keywords": ["sign in with your google account", "one google account for everything"],
    },
    "PayPal": {
        "legit_domains": ["paypal.com", "paypal-communication.com"],
        "title_keywords": ["log in to your paypal account", "paypal checkout", "paypal"],
        "body_keywords": ["pay with paypal", "paypal credit", "security challenge", "paypal service"],
    },
    "Apple": {
        "legit_domains": ["apple.com", "icloud.com"],
        "title_keywords": ["sign in to icloud", "apple id", "apple support"],
        "body_keywords": ["manage your apple id", "icloud storage", "sign in to icloud"],
    },
    "DocuSign": {
        "legit_domains": ["docusign.net", "docusign.com"],
        "title_keywords": ["docusign", "review document", "sign document"],
        "body_keywords": ["please docusign", "document requires your signature", "view completed document"],
    },
}


class UrlDetonator:
    """Detonates suspicious URLs within a controlled sandbox environment."""

    def __init__(
        self,
        timeout_seconds: float = 8.0,
        max_redirects: int = 8,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        self.timeout = timeout_seconds
        self.max_redirects = max_redirects
        self.user_agent = user_agent

    def detonate(
        self,
        target_url: str,
        client: Optional[httpx.Client] = None,
        html_override: Optional[str] = None,
        status_override: Optional[int] = None,
        final_url_override: Optional[str] = None,
    ) -> UrlDetonationResult:
        """
        Detonates target URL by tracing redirects, executing simulated DOM parsing,
        and extracting credential harvesting indicators and brand impersonations.
        """
        # Ensure scheme is present
        if not re.match(r"^https?://", target_url, re.IGNORECASE):
            target_url = "http://" + target_url

        redirect_chain: list[RedirectHop] = []
        suspicious_indicators: list[str] = []
        html_content = html_override or ""
        status_code = status_override or 200
        server_banner = None
        current_url = target_url

        # Check for IP literal host
        parsed_target = urlparse(target_url)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_target.hostname or ""):
            suspicious_indicators.append(f"Direct IP address host used: {parsed_target.hostname}")

        if html_override is None:
            # Active network detonation
            custom_headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            should_close = False
            http_client = client
            if http_client is None:
                http_client = httpx.Client(
                    headers=custom_headers,
                    follow_redirects=False,
                    timeout=self.timeout,
                    verify=False,
                )
                should_close = True

            try:
                visited = set()
                hop_num = 1
                while hop_num <= self.max_redirects:
                    if current_url in visited:
                        suspicious_indicators.append("Circular redirect loop detected in HTTP chain")
                        break
                    visited.add(current_url)

                    start_t = time.perf_counter()
                    resp = http_client.get(current_url)
                    elapsed = (time.perf_counter() - start_t) * 1000.0

                    headers_dict = dict(resp.headers)
                    if not server_banner and "server" in headers_dict:
                        server_banner = headers_dict["server"]

                    redirect_chain.append(
                        RedirectHop(
                            hop_number=hop_num,
                            url=current_url,
                            status_code=resp.status_code,
                            reason_phrase=resp.reason_phrase,
                            headers=headers_dict,
                            elapsed_ms=round(elapsed, 1),
                        )
                    )

                    if resp.is_redirect and "location" in resp.headers:
                        loc = resp.headers["location"]
                        current_url = urljoin(current_url, loc)
                        hop_num += 1
                        continue
                    else:
                        status_code = resp.status_code
                        html_content = resp.text
                        break
            except Exception as exc:
                suspicious_indicators.append(f"Network detonation encountered error: {exc.__class__.__name__}")
                status_code = status_code or 0
            finally:
                if should_close:
                    http_client.close()

        final_url = final_url_override or current_url
        final_domain = (urlparse(final_url).hostname or "").lower()

        # Check for client-side meta-refresh redirect
        meta_match = re.search(
            r"""<meta\s+http-equiv=["']?refresh["']?\s+content=["']?\d+;\s*url=([^"'>\s]+)""",
            html_content,
            re.IGNORECASE,
        )
        if meta_match:
            meta_dest = urljoin(final_url, meta_match.group(1))
            suspicious_indicators.append(f"Client-side HTML meta-refresh redirect: {meta_dest}")
            redirect_chain.append(
                RedirectHop(
                    hop_number=len(redirect_chain) + 1,
                    url=meta_dest,
                    status_code=200,
                    reason_phrase="Meta Refresh Redirect",
                    headers={"Content-Type": "text/html"},
                    elapsed_ms=0.0,
                )
            )
            final_url = meta_dest
            final_domain = (urlparse(final_url).hostname or "").lower()

        # 2. DOM Inspection
        page_title = None
        forms_detected: list[FormTarget] = []
        has_cred_form = False

        if html_content:
            soup = BeautifulSoup(html_content, "html.parser")
            if soup.title and soup.title.string:
                page_title = soup.title.string.strip()

            # Parse Form Elements
            forms = soup.find_all("form")
            for form in forms:
                raw_action = form.get("action", "")
                method = (form.get("method", "POST") or "POST").upper()
                resolved_action = urljoin(final_url, raw_action)
                action_domain = (urlparse(resolved_action).hostname or "").lower()

                inputs = form.find_all("input")
                field_names = [inp.get("name", "") for inp in inputs if inp.get("name")]
                input_types = [(inp.get("type") or "text").lower() for inp in inputs]

                has_password = "password" in input_types or any(
                    "pass" in name.lower() or "pwd" in name.lower() for name in field_names
                )
                has_email = "email" in input_types or any(
                    "email" in name.lower() or "login" in name.lower() or "user" in name.lower() for name in field_names
                )
                is_external = bool(action_domain and action_domain != final_domain)

                if has_password:
                    has_cred_form = True

                form_obj = FormTarget(
                    action=resolved_action,
                    method=method,
                    has_password_field=has_password,
                    has_email_field=has_email,
                    field_names=field_names,
                    is_external_post=is_external,
                )
                forms_detected.append(form_obj)

                if has_password and is_external:
                    suspicious_indicators.append(
                        f"Credential form submits password to external host: {action_domain}"
                    )
                elif has_password:
                    suspicious_indicators.append("Interactive credential harvesting password input discovered")

            # Check for hidden/zero-size iframes
            iframes = soup.find_all("iframe")
            for iframe in iframes:
                w = iframe.get("width", "")
                h = iframe.get("height", "")
                style = (iframe.get("style") or "").lower()
                if w in ("0", "1") or h in ("0", "1") or "display:none" in style or "visibility:hidden" in style:
                    suspicious_indicators.append("Stealth concealed iframe detected in landing DOM")

            # Check for script obfuscation
            scripts = soup.find_all("script")
            script_text = "\n".join(s.get_text() for s in scripts if s.get_text())
            if any(p in script_text for p in ("eval(", "unescape(", "String.fromCharCode(", "window.atob(")):
                suspicious_indicators.append("JavaScript dynamic code execution / obfuscation detected")

        # 3. Brand Impersonation Analysis
        brand_result = self._check_brand_impersonation(page_title or "", html_content, final_domain)
        if brand_result.detected:
            suspicious_indicators.append(
                f"Unauthorized brand clone detected: {brand_result.impersonated_brand} "
                f"hosted on non-authoritative domain '{final_domain}'"
            )

        # 4. Score & Verdict Calculation
        score = 0.0
        if has_cred_form:
            score += 45.0
        if brand_result.detected:
            score += 40.0
        if any("external host" in ind for ind in suspicious_indicators):
            score += 25.0
        if len(redirect_chain) >= 3:
            score += 15.0
            suspicious_indicators.append(f"Excessive redirect traversal ({len(redirect_chain)} hops)")
        if any("obfuscation" in ind for ind in suspicious_indicators):
            score += 20.0
        if any("Stealth concealed iframe" in ind for ind in suspicious_indicators):
            score += 20.0
        if any("Direct IP address host" in ind for ind in suspicious_indicators):
            score += 20.0

        risk_score = min(100.0, round(score, 1))

        if risk_score >= 60.0 or (has_cred_form and brand_result.detected):
            verdict = DetonationVerdict.MALICIOUS
        elif risk_score >= 25.0 or len(redirect_chain) >= 2 or has_cred_form:
            verdict = DetonationVerdict.SUSPICIOUS
        else:
            verdict = DetonationVerdict.BENIGN

        return UrlDetonationResult(
            target_url=target_url,
            final_url=final_url,
            status_code=status_code,
            redirect_chain=redirect_chain,
            total_redirects=len(redirect_chain),
            page_title=page_title,
            server_banner=server_banner,
            forms_detected=forms_detected,
            has_credential_harvesting_form=has_cred_form,
            brand_impersonation=brand_result,
            suspicious_indicators=suspicious_indicators,
            verdict=verdict,
            risk_score=risk_score,
            simulated_screenshot_base64=None,
        )

    def _check_brand_impersonation(
        self,
        title: str,
        html_body: str,
        landing_domain: str,
    ) -> BrandImpersonationDetection:
        """Correlates page brand signatures against landing domain whitelists."""
        title_lower = title.lower()
        body_lower = html_body.lower()
        matched_indicators = []

        for brand_name, spec in KNOWN_BRANDS.items():
            legit_domains = spec["legit_domains"]
            # If the landing domain is legitimate for this brand, it is authorized
            if any(landing_domain == d or landing_domain.endswith("." + d) for d in legit_domains):
                continue

            # Check title matches
            title_hits = [k for k in spec["title_keywords"] if k in title_lower]
            body_hits = [k for k in spec["body_keywords"] if k in body_lower]

            if title_hits or len(body_hits) >= 2:
                matched_indicators.extend([f"Title: '{h}'" for h in title_hits])
                matched_indicators.extend([f"Body: '{h}'" for h in body_hits])
                confidence = 0.95 if title_hits and body_hits else 0.80

                return BrandImpersonationDetection(
                    detected=True,
                    impersonated_brand=brand_name,
                    confidence=confidence,
                    matched_indicators=matched_indicators,
                )

        return BrandImpersonationDetection(detected=False)
