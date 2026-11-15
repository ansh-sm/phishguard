"""
VirusTotal API v3 Client for URL and File Hash Threat Intelligence.
"""

import base64
import os
from typing import Any, Optional
import httpx

from phishguard.intel.cache import IntelCache


class VirusTotalClient:
    """
    Asynchronous client for VirusTotal API v3.
    Enriches URLs and file attachment hashes with multi-engine antivirus verdicts.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache: Optional[IntelCache] = None,
        timeout_seconds: float = 6.0,
    ):
        self.api_key = api_key or os.environ.get("VT_API_KEY")
        self.cache = cache or IntelCache()
        self.timeout = timeout_seconds

    @staticmethod
    def url_to_vt_id(url: str) -> str:
        """Convert URL to base64url-encoded string without padding per VirusTotal API v3 spec."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def check_url(self, url: str) -> dict[str, Any]:
        """
        Query VirusTotal API v3 for URL reputation.
        Returns standardized intel dictionary.
        """
        # 1. Check local cache first
        cached = self.cache.get("virustotal", url)
        if cached:
            return {
                "provider": "VirusTotal",
                "is_flagged": cached["is_flagged"],
                "threat_type": "phishing/malware" if cached["is_flagged"] else None,
                "tags": cached["tags"],
                "details": cached["details"],
                "cached": True,
            }

        # If no API key configured, return unconfigured state without error
        if not self.api_key:
            return {
                "provider": "VirusTotal",
                "is_flagged": False,
                "threat_type": None,
                "tags": [],
                "details": {"status": "api_key_not_configured"},
                "cached": False,
            }

        vt_id = self.url_to_vt_id(url)
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.BASE_URL}/urls/{vt_id}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0

                    is_flagged = (malicious >= 2) or (malicious + suspicious >= 3)
                    tags = [f"vt_malicious:{malicious}/{total}"] if is_flagged else []
                    details = {
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "harmless_count": stats.get("harmless", 0),
                        "total_engines": total,
                        "categories": data.get("categories", {}),
                    }

                    self.cache.set("virustotal", url, is_flagged, tags, details, ttl_hours=24 if is_flagged else 12)
                    return {
                        "provider": "VirusTotal",
                        "is_flagged": is_flagged,
                        "threat_type": "phishing/malware" if is_flagged else None,
                        "tags": tags,
                        "details": details,
                        "cached": False,
                    }
        except Exception as e:
            return {
                "provider": "VirusTotal",
                "is_flagged": False,
                "threat_type": None,
                "tags": [],
                "details": {"error": str(e)},
                "cached": False,
            }

        return {
            "provider": "VirusTotal",
            "is_flagged": False,
            "threat_type": None,
            "tags": [],
            "details": {},
            "cached": False,
        }

    async def check_file_hash(self, sha256_hash: str) -> dict[str, Any]:
        """
        Query VirusTotal API v3 for file hash reputation.
        """
        cached = self.cache.get("virustotal_file", sha256_hash)
        if cached:
            return {
                "provider": "VirusTotal",
                "is_flagged": cached["is_flagged"],
                "threat_type": "malicious_file" if cached["is_flagged"] else None,
                "tags": cached["tags"],
                "details": cached["details"],
                "cached": True,
            }

        if not self.api_key:
            return {
                "provider": "VirusTotal",
                "is_flagged": False,
                "threat_type": None,
                "tags": [],
                "details": {"status": "api_key_not_configured"},
                "cached": False,
            }

        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.BASE_URL}/files/{sha256_hash}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 0

                    is_flagged = malicious >= 2
                    tags = [f"vt_malicious:{malicious}/{total}"] if is_flagged else []
                    details = {
                        "malicious_count": malicious,
                        "meaningful_name": data.get("meaningful_name"),
                        "popular_threat_classification": data.get("popular_threat_classification", {}),
                    }

                    self.cache.set("virustotal_file", sha256_hash, is_flagged, tags, details, ttl_hours=48 if is_flagged else 12)
                    return {
                        "provider": "VirusTotal",
                        "is_flagged": is_flagged,
                        "threat_type": "malicious_file" if is_flagged else None,
                        "tags": tags,
                        "details": details,
                        "cached": False,
                    }
        except Exception as e:
            return {
                "provider": "VirusTotal",
                "is_flagged": False,
                "threat_type": None,
                "tags": [],
                "details": {"error": str(e)},
                "cached": False,
            }

        return {
            "provider": "VirusTotal",
            "is_flagged": False,
            "threat_type": None,
            "tags": [],
            "details": {},
            "cached": False,
        }
