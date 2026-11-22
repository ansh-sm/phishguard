"""
Multi-Channel Alert Dispatcher for PhishGuard SOC.
Supports Slack, Discord, Microsoft Teams, and Generic HMAC-signed SIEM/SOAR webhooks.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
from typing import Any, Optional
import httpx

from phishguard import __version__
from phishguard.alerts.models import AlertConfig, AlertWebhookType
from phishguard.models.report import ScanResult, VerdictEnum

logger = logging.getLogger("phishguard.alerts")


class AlertDispatcher:
    """
    Formats and dispatches incident alerts to chat and SIEM webhooks.
    """

    def __init__(self, config: AlertConfig):
        self.config = config

    def should_alert(self, result: ScanResult) -> bool:
        """Determines whether a scan result qualifies for an alert."""
        if not self.config.enabled:
            return False
        if result.score.total_score >= self.config.min_score:
            return True
        if result.verdict == VerdictEnum.MALICIOUS:
            return True
        return False

    def build_slack_payload(self, result: ScanResult) -> dict[str, Any]:
        """Constructs Slack Block Kit message payload."""
        verdict_emoji = "🚨" if result.verdict == VerdictEnum.MALICIOUS else ("⚠️" if result.verdict == VerdictEnum.SUSPICIOUS else "🛡️")
        headline = f"{verdict_emoji} *PhishGuard Incident Alert: {result.verdict.value} ({result.severity.value})*"

        findings_text = "\n".join([f"• {f}" for f in result.key_findings[:4]]) or "None noted."
        mitre_text = ", ".join([t.technique_id for t in result.mitre_attack]) or "None"
        rules_text = ", ".join([r.rule_id for r in result.matched_rules]) or "None"

        return {
            "text": f"{verdict_emoji} PhishGuard Alert: {result.verdict.value} ({result.score.total_score}/100)",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": headline,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Scan ID:*\n`{result.scan_id}`"},
                        {"type": "mrkdwn", "text": f"*PhishScore:*\n`{result.score.total_score}/100` ({result.severity.value})"},
                        {"type": "mrkdwn", "text": f"*Sender:*\n{result.metadata.from_raw[:60]}"},
                        {"type": "mrkdwn", "text": f"*Subject:*\n{result.metadata.subject[:60]}"},
                        {"type": "mrkdwn", "text": f"*Originating IP:*\n`{result.headers.originating_ip or 'Unknown'}`"},
                        {"type": "mrkdwn", "text": f"*Triggered Rules:*\n{rules_text}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Key Findings:*\n{findings_text}\n*MITRE ATT&CK:* `{mitre_text}`",
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"PhishGuard SOC Engine v{__version__} | Timestamp: {result.timestamp.isoformat()}",
                        }
                    ],
                },
            ],
        }

    def build_discord_payload(self, result: ScanResult) -> dict[str, Any]:
        """Constructs Discord rich embed payload."""
        color = 0xEF4444 if result.verdict == VerdictEnum.MALICIOUS else (0xF59E0B if result.verdict == VerdictEnum.SUSPICIOUS else 0x10B981)

        findings_text = "\n".join([f"• {f}" for f in result.key_findings[:3]]) or "None noted."
        mitre_text = ", ".join([f"`{t.technique_id}`" for t in result.mitre_attack]) or "None"
        rules_text = ", ".join([f"`{r.rule_id}`" for r in result.matched_rules]) or "None"

        return {
            "embeds": [
                {
                    "title": f"🚨 PhishGuard Incident Alert: {result.verdict.value}",
                    "description": result.written_explanation.splitlines()[0],
                    "color": color,
                    "fields": [
                        {"name": "PhishScore", "value": f"**{result.score.total_score}/100** ({result.severity.value})", "inline": True},
                        {"name": "Scan ID", "value": f"`{result.scan_id}`", "inline": True},
                        {"name": "Originating IP", "value": f"`{result.headers.originating_ip or 'Unknown'}`", "inline": True},
                        {"name": "Sender", "value": result.metadata.from_raw[:80], "inline": False},
                        {"name": "Subject", "value": result.metadata.subject[:80], "inline": False},
                        {"name": "Triggered Rules", "value": rules_text, "inline": True},
                        {"name": "MITRE ATT&CK", "value": mitre_text, "inline": True},
                        {"name": "Key Findings", "value": findings_text[:1000], "inline": False},
                    ],
                    "footer": {"text": f"PhishGuard SOC Engine v{__version__}"},
                    "timestamp": result.timestamp.isoformat(),
                }
            ]
        }

    def build_teams_payload(self, result: ScanResult) -> dict[str, Any]:
        """Constructs Microsoft Teams message card payload."""
        theme_color = "EF4444" if result.verdict == VerdictEnum.MALICIOUS else ("F59E0B" if result.verdict == VerdictEnum.SUSPICIOUS else "10B981")

        facts = [
            {"name": "Scan ID", "value": result.scan_id},
            {"name": "PhishScore", "value": f"{result.score.total_score}/100 ({result.severity.value})"},
            {"name": "From", "value": result.metadata.from_raw},
            {"name": "Subject", "value": result.metadata.subject},
            {"name": "Originating IP", "value": result.headers.originating_ip or "Unknown"},
            {"name": "Rules Triggered", "value": ", ".join([r.rule_id for r in result.matched_rules]) or "None"},
            {"name": "MITRE ATT&CK", "value": ", ".join([t.technique_id for t in result.mitre_attack]) or "None"},
        ]

        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"PhishGuard Alert: {result.verdict.value}",
            "themeColor": theme_color,
            "title": f"🚨 PhishGuard Incident Alert: {result.verdict.value} ({result.severity.value})",
            "sections": [
                {
                    "activityTitle": result.written_explanation.splitlines()[0],
                    "facts": facts,
                    "text": "### Key Findings:\n" + "\n".join([f"- {f}" for f in result.key_findings[:4]]),
                }
            ],
        }

    def build_generic_payload(self, result: ScanResult) -> dict[str, Any]:
        """Constructs full SIEM/SOAR incident JSON payload."""
        return {
            "event_type": "phishguard.incident.alert",
            "engine_version": __version__,
            "scan_id": result.scan_id,
            "timestamp": result.timestamp.isoformat(),
            "verdict": result.verdict.value,
            "severity": result.severity.value,
            "score": result.score.model_dump(),
            "summary": result.written_explanation,
            "email_metadata": {
                "subject": result.metadata.subject,
                "from": result.metadata.from_address,
                "reply_to": result.metadata.reply_to,
                "date": result.metadata.date,
                "message_id": result.metadata.message_id,
            },
            "routing": {
                "originating_ip": result.headers.originating_ip,
                "hops_count": len(result.headers.hops),
                "auth": result.headers.auth.model_dump(),
            },
            "iocs": {
                "defanged_urls": [u.defanged_url for u in result.urls],
                "attachment_hashes": [a.sha256 for a in result.attachments if a.sha256],
                "originating_ip": result.headers.originating_ip,
            },
            "matched_rules": [r.model_dump() for r in result.matched_rules],
            "mitre_attack": [t.model_dump() for t in result.mitre_attack],
            "remediation_steps": result.remediation_steps,
        }

    async def send_alert(self, result: ScanResult, client: Optional[httpx.AsyncClient] = None) -> bool:
        """
        Dispatches alert to the configured webhook endpoint.
        """
        if not self.should_alert(result):
            return False

        # Select payload builder based on webhook type
        if self.config.webhook_type == AlertWebhookType.SLACK:
            payload = self.build_slack_payload(result)
        elif self.config.webhook_type == AlertWebhookType.DISCORD:
            payload = self.build_discord_payload(result)
        elif self.config.webhook_type == AlertWebhookType.TEAMS:
            payload = self.build_teams_payload(result)
        else:
            payload = self.build_generic_payload(result)

        payload_bytes = json.dumps(payload, default=str).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"PhishGuard-SOC-AlertDispatcher/{__version__}",
        }

        # Optional HMAC signature for SIEM webhook integrity verification
        if self.config.hmac_secret:
            timestamp_str = str(int(datetime.now(timezone.utc).timestamp()))
            mac = hmac.new(
                self.config.hmac_secret.encode("utf-8"),
                msg=payload_bytes,
                digestmod=hashlib.sha256,
            ).hexdigest()
            headers["X-PhishGuard-Signature"] = f"sha256={mac}"
            headers["X-PhishGuard-Timestamp"] = timestamp_str

        # Send HTTP POST
        try:
            if client:
                resp = await client.post(self.config.webhook_url, content=payload_bytes, headers=headers, timeout=10.0)
                return resp.status_code in (200, 201, 202, 204)
            else:
                async with httpx.AsyncClient(timeout=10.0) as default_client:
                    resp = await default_client.post(self.config.webhook_url, content=payload_bytes, headers=headers)
                    return resp.status_code in (200, 201, 202, 204)
        except Exception as e:
            logger.error(f"Failed to dispatch alert to {self.config.webhook_url}: {e}")
            return False
