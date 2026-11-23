"""Data models for SIEM streaming forwarders."""

from __future__ import annotations

from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field


class SiemTargetType(str, Enum):
    """Supported SIEM destination platforms."""
    SPLUNK_HEC = "splunk"
    ELASTIC_ECS = "elastic"
    AZURE_SENTINEL = "sentinel"
    GENERIC_WEBHOOK = "webhook"


class SiemConfig(BaseModel):
    """Configuration for SIEM event ingestion pipeline."""
    target_type: SiemTargetType = SiemTargetType.SPLUNK_HEC
    endpoint_url: str
    auth_token: Optional[str] = None
    api_key: Optional[str] = None
    workspace_id: Optional[str] = None
    workspace_key: Optional[str] = None
    index_name: str = "phishguard_threats"
    verify_ssl: bool = True
    timeout_sec: float = 10.0
    headers: dict[str, str] = Field(default_factory=dict)


class SiemForwardResult(BaseModel):
    """Execution telemetry from a SIEM forwarding operation."""
    success: bool
    target_type: SiemTargetType
    status_code: int
    response_body: str = ""
    events_forwarded: int = 0
    error_message: Optional[str] = None
