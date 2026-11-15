"""
AlienVault Open Threat Exchange (OTX) Client.
"""

import os
from typing import Any, Optional
import httpx

from phishguard.intel.cache import IntelCache


class OTXClient:
    """
    Asynchronous client for AlienVault OTX (Open Threat Exchange) v1 API.
    Queries pulse indicators and threat reputation for IPs, domains, and URLs.
    """

    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache: Optional[IntelCache] = None,
        timeout_seconds: float = 6.0,
    ):
        self.api_key = api_key or os.environ.get("OTX_API_KEY")
        self.cache = cache or IntelCache()
        self.timeout = timeout_seconds

    async def check_ip(self, ip_address: str) -> dict[str, Any]:
        """Query OTX for IP threat reputation and pulse count."""
        cached = self.cache.get("otx_ip", ip_address)
        if cached:
            return {
                "provider": "AlienVault OTX",
                "is_flagged": cached["is_flagged"],
                "threat_type": "malicious_ip" if cached["is_flagged"] else None,
                "tags": cached["tags"],
                "details": cached["details"],
                "cached": True,
            }

        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.BASE_URL}/IPv4/{ip_address}/general", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    pulse_info = data.get("pulse_info", {})
                    pulse_count = pulse_info.get("count", 0)

                    is_flagged = pulse_count >= 1
                    tags = [f"otx_pulses:{pulse_count}"] if is_flagged else []
                    pulse_names = [p.get("name") for p in pulse_info.get("pulses", [])[:3]]
                    details = {
                        "pulse_count": pulse_count,
                        "recent_pulses": pulse_names,
                        "country_name": data.get("country_name"),
                        "asn": data.get("asn"),
                    }

                    self.cache.set("otx_ip", ip_address, is_flagged, tags, details, ttl_hours=24 if is_flagged else 12)
                    return {
                        "provider": "AlienVault OTX",
                        "is_flagged": is_flagged,
                        "threat_type": "malicious_ip" if is_flagged else None,
                        "tags": tags,
                        "details": details,
                        "cached": False,
                    }
        except Exception as e:
            return {
                "provider": "AlienVault OTX",
                "is_flagged": False,
                "threat_type": None,
                "tags": [],
                "details": {"error": str(e)},
                "cached": False,
            }

        return {
            "provider": "AlienVault OTX",
            "is_flagged": False,
            "threat_type": None,
            "tags": [],
            "details": {},
            "cached": False,
        }

    async def check_domain(self, domain: str) -> dict[str, Any]:
        """Query OTX for domain reputation."""
        cached = self.cache.get("otx_domain", domain)
        if cached:
            return {
                "provider": "AlienVault OTX",
                "is_flagged": cached["is_flagged"],
                "threat_type": "phishing_domain" if cached["is_flagged"] else None,
                "tags": cached["tags"],
                "details": cached["details"],
                "cached": True,
            }

        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.BASE_URL}/domain/{domain}/general", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    pulse_info = data.get("pulse_info", {})
                    pulse_count = pulse_info.get("count", 0)

                    is_flagged = pulse_count >= 1
                    tags = [f"otx_pulses:{pulse_count}"] if is_flagged else []
                    details = {
                        "pulse_count": pulse_count,
                        "recent_pulses": [p.get("name") for p in pulse_info.get("pulses", [])[:3]],
                    }

                    self.cache.set("otx_domain", domain, is_flagged, tags, details, ttl_hours=24 if is_flagged else 12)
                    return {
                        "provider": "AlienVault OTX",
                        "is_flagged": is_flagged,
                        "threat_type": "phishing_domain" if is_flagged else None,
                        "tags": tags,
                        "details": details,
                        "cached": False,
                    }
        except Exception as e:
            return {
                "provider": "AlienVault OTX",
                "is_flagged": False,
                "threat_type": None,
                "tags": [],
                "details": {"error": str(e)},
                "cached": False,
            }

        return {
            "provider": "AlienVault OTX",
            "is_flagged": False,
            "threat_type": None,
            "tags": [],
            "details": {},
            "cached": False,
        }
