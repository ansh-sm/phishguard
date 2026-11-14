"""
Abuse.ch URLhaus Threat Intelligence Client.
"""

from typing import Any, Optional
import httpx

from phishguard.intel.cache import IntelCache


class UrlhausClient:
    """
    Asynchronous client for querying Abuse.ch URLhaus malware and phishing API.
    URLhaus is free and requires no API key.
    """

    API_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, cache: Optional[IntelCache] = None, timeout_seconds: float = 5.0):
        self.cache = cache or IntelCache()
        self.timeout = timeout_seconds

    async def check_url(self, url: str) -> dict[str, Any]:
        """
        Check URL against URLhaus database.
        Returns:
            {
                "provider": "URLhaus",
                "is_flagged": bool,
                "threat_type": Optional[str],
                "tags": list[str],
                "details": dict,
                "cached": bool
            }
        """
        # 1. Check local cache first
        cached = self.cache.get("urlhaus", url)
        if cached:
            return {
                "provider": "URLhaus",
                "is_flagged": cached["is_flagged"],
                "threat_type": cached["details"].get("threat"),
                "tags": cached["tags"],
                "details": cached["details"],
                "cached": True,
            }

        # 2. Make non-blocking async HTTP POST
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.API_ENDPOINT, data={"url": url})
                if response.status_code == 200:
                    data = response.json()
                    status = data.get("query_status")

                    is_flagged = status == "ok"
                    threat_type = data.get("threat")
                    tags = data.get("tags") or []
                    details = {
                        "query_status": status,
                        "url_status": data.get("url_status"),
                        "threat": threat_type,
                        "reporter": data.get("reporter"),
                        "date_added": data.get("date_added"),
                    }

                    # Cache result (positive hits for 24h, negative for 12h)
                    self.cache.set("urlhaus", url, is_flagged, tags, details, ttl_hours=24 if is_flagged else 12)

                    return {
                        "provider": "URLhaus",
                        "is_flagged": is_flagged,
                        "threat_type": threat_type,
                        "tags": tags,
                        "details": details,
                        "cached": False,
                    }
        except Exception as e:
            # Resilient fallback on timeout or connection error
            return {
                "provider": "URLhaus",
                "is_flagged": False,
                "threat_type": None,
                "tags": [],
                "details": {"error": str(e)},
                "cached": False,
            }

        return {
            "provider": "URLhaus",
            "is_flagged": False,
            "threat_type": None,
            "tags": [],
            "details": {},
            "cached": False,
        }
