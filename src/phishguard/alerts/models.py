"""
Alerting data models and webhook configurations for SOC integrations.
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class AlertWebhookType(str, Enum):
    SLACK = "slack"
    DISCORD = "discord"
    TEAMS = "teams"
    GENERIC = "generic"


class AlertConfig(BaseModel):
    """Configuration for real-time SOC alerting."""
    webhook_url: str = Field(description="Target incoming webhook URL")
    webhook_type: AlertWebhookType = Field(default=AlertWebhookType.GENERIC, description="Webhook formatting adapter")
    min_score: float = Field(default=60.0, description="Minimum PhishScore to trigger outbound alert (0-100)")
    hmac_secret: Optional[str] = Field(default=None, description="Shared secret for HMAC-SHA256 signature header")
    enabled: bool = Field(default=True, description="Enable or disable alerting dispatcher")
