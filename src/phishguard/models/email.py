"""
Email data models representing RFC 5322 structure, headers, and metadata.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, model_validator


class AuthStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


class ReceivedHop(BaseModel):
    """Represents a single routing hop parsed from Received headers."""
    hop_index: int = Field(description="Order index of hop from origin (0 = closest to origin)")
    from_host: Optional[str] = Field(default=None, description="Host reported in 'from' clause")
    by_host: Optional[str] = Field(default=None, description="Host reported in 'by' clause")
    client_ip: Optional[str] = Field(default=None, description="Extracted IP address of transmitting agent")
    is_private_ip: bool = Field(default=False, description="Whether the IP is an RFC 1918/Loopback IP")
    protocol: Optional[str] = Field(default=None, description="Transfer protocol (e.g. ESMTP, ESMTPS, HTTP)")
    timestamp: Optional[datetime] = Field(default=None, description="Parsed hop timestamp")
    raw_date: Optional[str] = Field(default=None, description="Original raw date string from header")
    delay_from_previous_seconds: Optional[float] = Field(default=None, description="Latency delta from preceding hop")


class AuthenticationResults(BaseModel):
    """Results of email authentication mechanisms (SPF, DKIM, DMARC)."""
    spf_status: AuthStatus = Field(default=AuthStatus.UNKNOWN)
    spf_domain: Optional[str] = None
    spf_sender_ip: Optional[str] = None

    dkim_status: AuthStatus = Field(default=AuthStatus.UNKNOWN)
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None

    dmarc_status: AuthStatus = Field(default=AuthStatus.UNKNOWN)
    dmarc_action: Optional[str] = Field(default=None, description="Policy action (none, quarantine, reject)")

    raw_header: Optional[str] = Field(default=None, description="Original Authentication-Results header text")


class MimePart(BaseModel):
    """MIME component structure inside the email."""
    part_index: int
    content_type: str
    charset: Optional[str] = None
    filename: Optional[str] = None
    size_bytes: int = 0
    content_id: Optional[str] = None
    is_attachment: bool = False


class EmailMetadata(BaseModel):
    """Extracted top-level metadata and envelope addresses."""
    message_id: Optional[str] = None
    subject: str = Field(default="(No Subject)")
    date: Optional[str] = None
    date_parsed: Optional[datetime] = None

    # Sender identities
    from_raw: str = Field(default="")
    from_name: Optional[str] = None
    from_email: str = Field(default="")
    from_domain: str = Field(default="")

    # Reply-to addresses
    reply_to_raw: Optional[str] = None
    reply_to_email: Optional[str] = None
    reply_to_domain: Optional[str] = None

    # Return-Path
    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None

    # Recipients
    to_emails: list[str] = Field(default_factory=list)
    cc_emails: list[str] = Field(default_factory=list)

    # Client signature / agent
    user_agent: Optional[str] = None
    x_mailer: Optional[str] = None

    # Custom or suspicious X-headers
    x_headers: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def handle_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "from_address" in data and not data.get("from_email"):
                data["from_email"] = data["from_address"]
            if "reply_to" in data and not data.get("reply_to_email"):
                data["reply_to_email"] = data["reply_to"]
            if "to" in data and not data.get("to_emails"):
                data["to_emails"] = data["to"] if isinstance(data["to"], list) else [data["to"]]
        return data

    @property
    def from_address(self) -> str:
        return self.from_email or self.from_raw

    @property
    def reply_to(self) -> Optional[str]:
        return self.reply_to_email or self.reply_to_raw

    @property
    def to(self) -> list[str]:
        return self.to_emails
