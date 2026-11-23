"""Enterprise SIEM Event Forwarder for Splunk HEC, Elastic ECS, and Azure Sentinel."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Optional, Any
import httpx

from phishguard.models.report import ScanResult
from phishguard.siem.models import SiemConfig, SiemForwardResult, SiemTargetType


class SiemForwarder:
    """Dispatches high-fidelity threat incidents to enterprise SIEM platforms."""

    @staticmethod
    def build_splunk_payload(result: ScanResult, index: str = "main") -> dict[str, Any]:
        """Format scan event for Splunk HTTP Event Collector (HEC)."""
        epoch_now = time.time()
        total_score_val = result.score.total_score if hasattr(result.score, "total_score") else float(result.score)
        spf_val = result.headers.auth.spf_status.value if result.headers and result.headers.auth else None
        dkim_val = result.headers.auth.dkim_status.value if result.headers and result.headers.auth else None
        dmarc_val = result.headers.auth.dmarc_status.value if result.headers and result.headers.auth else None

        event_body = {
            "scan_id": result.scan_id,
            "verdict": result.verdict.value,
            "score": total_score_val,
            "confidence": result.confidence,
            "subject": result.metadata.subject,
            "sender": result.metadata.from_email,
            "recipients": result.metadata.to,
            "originating_ip": result.headers.originating_ip if result.headers else None,
            "auth_spf": spf_val,
            "auth_dkim": dkim_val,
            "auth_dmarc": dmarc_val,
            "urls_count": len(result.urls),
            "attachments_count": len(result.attachments),
            "mitre_techniques": [m.technique_id for m in result.mitre_techniques],
            "rules_matched": [r.rule_id for r in result.rules_matched],
            "score_breakdown": result.score_breakdown.model_dump(),
            "flags": result.flags,
        }
        return {
            "time": epoch_now,
            "host": "phishguard-soc",
            "source": "phishguard:engine",
            "sourcetype": "phishguard:threat",
            "index": index,
            "event": event_body,
        }

    @staticmethod
    def build_elastic_payload(result: ScanResult, dataset: str = "phishguard.email") -> dict[str, Any]:
        """Format scan event conforming to Elastic Common Schema (ECS 8.x)."""
        now_iso = datetime.now(timezone.utc).isoformat()
        techniques_ids = [m.technique_id for m in result.mitre_techniques]
        technique_names = [m.name for m in result.mitre_techniques]
        rules_matched = [r.name for r in result.rules_matched]

        total_score_val = result.score.total_score if hasattr(result.score, "total_score") else float(result.score)

        return {
            "@timestamp": now_iso,
            "event": {
                "kind": "alert",
                "category": ["email", "threat"],
                "type": ["info"] if total_score_val < 25 else ["anomaly"],
                "severity": total_score_val,
                "outcome": "success",
                "dataset": dataset,
                "id": result.scan_id,
            },
            "threat": {
                "indicator": {
                    "type": "email",
                    "confidence": result.confidence,
                },
                "technique": {
                    "id": techniques_ids,
                    "name": technique_names,
                },
            },
            "email": {
                "from": {"address": [result.metadata.from_email]},
                "to": {"address": result.metadata.to},
                "subject": result.metadata.subject,
                "message_id": result.metadata.message_id,
            },
            "source": {
                "ip": result.headers.originating_ip if result.headers else None,
            },
            "rule": {
                "name": rules_matched,
            },
            "phishguard": {
                "scan_id": result.scan_id,
                "verdict": result.verdict.value,
                "score": total_score_val,
                "confidence": result.confidence,
                "urls_count": len(result.urls),
                "attachments_count": len(result.attachments),
                "score_breakdown": result.score_breakdown.model_dump(),
                "flags": result.flags,
            },
        }

    @staticmethod
    def build_sentinel_signature(
        workspace_id: str,
        workspace_key: str,
        content_length: int,
        rfc1123_date: str,
    ) -> str:
        """Compute HMAC-SHA256 SharedKey signature for Azure Log Analytics Data Collector."""
        string_to_sign = f"POST\n{content_length}\napplication/json\nx-ms-date:{rfc1123_date}\n/api/logs"
        try:
            key_bytes = base64.b64decode(workspace_key)
            hashed = hmac.new(key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
            signature = base64.b64encode(hashed).decode("utf-8")
            return f"SharedKey {workspace_id}:{signature}"
        except Exception:
            return f"SharedKey {workspace_id}:invalid_key"

    @classmethod
    def build_sentinel_payload(cls, result: ScanResult) -> list[dict[str, Any]]:
        """Format flat JSON array for Microsoft Sentinel / Azure Log Analytics."""
        now_iso = datetime.now(timezone.utc).isoformat()
        total_score_val = result.score.total_score if hasattr(result.score, "total_score") else float(result.score)
        return [
            {
                "TimeGenerated": now_iso,
                "ScanId": result.scan_id,
                "Verdict": result.verdict.value,
                "Score": total_score_val,
                "Confidence": result.confidence,
                "Sender": result.metadata.from_email,
                "Subject": result.metadata.subject,
                "OriginatingIP": result.headers.originating_ip if result.headers else "",
                "Techniques": ",".join(m.technique_id for m in result.mitre_techniques),
                "RulesMatched": ",".join(r.rule_id for r in result.rules_matched),
                "UrlsCount": len(result.urls),
                "AttachmentsCount": len(result.attachments),
                "ScoreHeaders": result.score_breakdown.headers,
                "ScoreUrls": result.score_breakdown.urls,
                "ScoreContent": result.score_breakdown.content,
                "ScoreAttachments": result.score_breakdown.attachments,
            }
        ]

    @classmethod
    def forward_scan_result(
        cls,
        config: SiemConfig,
        result: ScanResult,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> SiemForwardResult:
        """Send a single scan result event to the configured SIEM."""
        headers = dict(config.headers)

        if config.target_type == SiemTargetType.SPLUNK_HEC:
            payload = cls.build_splunk_payload(result, index=config.index_name)
            headers["Content-Type"] = "application/json"
            if config.auth_token:
                headers["Authorization"] = f"Splunk {config.auth_token}"

        elif config.target_type == SiemTargetType.ELASTIC_ECS:
            payload = cls.build_elastic_payload(result, dataset=config.index_name)
            headers["Content-Type"] = "application/json"
            if config.api_key:
                headers["Authorization"] = f"ApiKey {config.api_key}"
            elif config.auth_token:
                headers["Authorization"] = f"Bearer {config.auth_token}"

        elif config.target_type == SiemTargetType.AZURE_SENTINEL:
            payload = cls.build_sentinel_payload(result)
            body_bytes = json.dumps(payload).encode("utf-8")
            rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            headers["Content-Type"] = "application/json"
            headers["Log-Type"] = "PhishGuard_CL"
            headers["x-ms-date"] = rfc1123_date
            if config.workspace_id and config.workspace_key:
                auth_header = cls.build_sentinel_signature(
                    config.workspace_id, config.workspace_key, len(body_bytes), rfc1123_date
                )
                headers["Authorization"] = auth_header

        else:  # GENERIC_WEBHOOK
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "phishguard.incident",
                "data": result.model_dump(),
            }
            headers["Content-Type"] = "application/json"
            if config.auth_token:
                headers["Authorization"] = f"Bearer {config.auth_token}"

        body_str = json.dumps(payload)

        try:
            with httpx.Client(
                verify=config.verify_ssl,
                timeout=config.timeout_sec,
                transport=transport,
            ) as client:
                resp = client.post(config.endpoint_url, content=body_str, headers=headers)
                success = 200 <= resp.status_code < 300
                return SiemForwardResult(
                    success=success,
                    target_type=config.target_type,
                    status_code=resp.status_code,
                    response_body=resp.text[:500],
                    events_forwarded=1 if success else 0,
                    error_message=None if success else f"HTTP {resp.status_code}: {resp.text[:200]}",
                )
        except Exception as exc:
            return SiemForwardResult(
                success=False,
                target_type=config.target_type,
                status_code=0,
                response_body="",
                events_forwarded=0,
                error_message=str(exc),
            )

    @classmethod
    def test_connection(
        cls,
        config: SiemConfig,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> SiemForwardResult:
        """Send a lightweight ping/diagnostic payload to verify SIEM authentication and reachability."""
        headers = dict(config.headers)
        test_payload = {
            "source": "phishguard-soc-healthcheck",
            "test_event": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "PhishGuard SIEM pipeline test event",
        }

        if config.target_type == SiemTargetType.SPLUNK_HEC:
            payload = {
                "time": time.time(),
                "host": "phishguard-soc",
                "source": "phishguard:healthcheck",
                "sourcetype": "phishguard:diagnostic",
                "index": config.index_name,
                "event": test_payload,
            }
            headers["Content-Type"] = "application/json"
            if config.auth_token:
                headers["Authorization"] = f"Splunk {config.auth_token}"
        elif config.target_type == SiemTargetType.ELASTIC_ECS:
            payload = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "event": {"kind": "diagnostic", "dataset": config.index_name},
                "phishguard": test_payload,
            }
            headers["Content-Type"] = "application/json"
            if config.api_key:
                headers["Authorization"] = f"ApiKey {config.api_key}"
            elif config.auth_token:
                headers["Authorization"] = f"Bearer {config.auth_token}"
        elif config.target_type == SiemTargetType.AZURE_SENTINEL:
            payload = [test_payload]
            body_bytes = json.dumps(payload).encode("utf-8")
            rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
            headers["Content-Type"] = "application/json"
            headers["Log-Type"] = "PhishGuard_Health_CL"
            headers["x-ms-date"] = rfc1123_date
            if config.workspace_id and config.workspace_key:
                headers["Authorization"] = cls.build_sentinel_signature(
                    config.workspace_id, config.workspace_key, len(body_bytes), rfc1123_date
                )
        else:
            payload = test_payload
            headers["Content-Type"] = "application/json"
            if config.auth_token:
                headers["Authorization"] = f"Bearer {config.auth_token}"

        body_str = json.dumps(payload)
        try:
            with httpx.Client(
                verify=config.verify_ssl,
                timeout=config.timeout_sec,
                transport=transport,
            ) as client:
                resp = client.post(config.endpoint_url, content=body_str, headers=headers)
                success = 200 <= resp.status_code < 300
                return SiemForwardResult(
                    success=success,
                    target_type=config.target_type,
                    status_code=resp.status_code,
                    response_body=resp.text[:500],
                    events_forwarded=1 if success else 0,
                    error_message=None if success else f"HTTP {resp.status_code}: {resp.text[:200]}",
                )
        except Exception as exc:
            return SiemForwardResult(
                success=False,
                target_type=config.target_type,
                status_code=0,
                response_body="",
                events_forwarded=0,
                error_message=str(exc),
            )
