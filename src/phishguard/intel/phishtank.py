"""
PhishTank Threat Intelligence Client.
"""

from typing import Any, Optional
import httpx

from phishguard.intel.cache import IntelCache


class PhishTankClient:
    """
    Asynchronous client for querying PhishTank database.
    Supports free queries and optional application key.
    """

    API_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache: Optional[IntelCache] = None,
        timeout_seconds: float = 5.0,
    ):
        self.api_key = api_key
        self.cache = cache or IntelCache()
        self.timeout = timeout_seconds

    async def check_url(self, url: str) -> dict[str, Any]:
        """
        Check URL against PhishTank database.
        Returns:
            {
                "provider": "PhishTank",
                "is_flagged": bool,
                "threat_type": "phishing" | None,
                "tags": list[str],
                "details": dict,
                "cached": bool
            }
        """
        # 1. Check local cache
        cached = self.cache.get("phishtank", url)
        if cached:
            return {
                "provider": "PhishTank",
                "is_flagged": cached["is_flagged"],
                "threat_type": "phishing" if cached["is_flagged"] else None,
                "tags": cached["tags"],
                "details": cached["details"],
                "cached": True,
            }

        # 2. Async HTTP query
        payload = {"url": url, "format": "json"}
        if self.api_key:
            payload["app_key"] = self.api_key

        headers = {
            "User-Agent": "phishguard-soc/0.1.0 (threat-intelligence-scanner)"
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.API_ENDPOINT, data=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    results = data.get("results", {})
                    in_db = results.get("in_database", False)
                    verified = results.get("verified", False)
                    valid = results.get("valid", False)

                    is_flagged = bool(in_db and (verified or valid))
                    tags = ["phishing", "verified"] if (in_db and verified) else (["phishing"] if in_db else [])
                    details = {
                        "in_database": in_db,
                        "verified": verified,
                        "valid": valid,
                        "phish_detail_page": results.get("phish_detail_page"),
                    }

                    # Cache result
                    self.cache.set("phishtank", url, is_flagged, tags, details, ttl_hours=24 if is_flagged else 12)

                    return {
                        "provider": "PhishTank",
                        "is_flagged": is_flagged,
                        "threat_type": "phishing" if is_flagged else None,
                        "tags": tags,
                        "details": details,
                        "cached": False,
                    }
        except Exception as e:
            return {
                "provider": "PhishTank",
                "is_flagged": False,
                "threat_type": None,
                "tags": [],
                "details": {"error": str(e)},
                "cached": False,
            }

        return {
            "provider": "PhishTank",
            "is_flagged": False,
            "threat_type": None,
            "tags": [],
            "details": {},
            "cached": False,
        }
