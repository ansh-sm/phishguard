"""
RFC 5322 & RFC 2045 compliant EML and MIME parser.
"""

from dataclasses import dataclass, field
import email
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
import hashlib
from pathlib import Path
from typing import Optional, Union
import dateutil.parser

from phishguard.models.email import EmailMetadata, MimePart


@dataclass
class RawAttachment:
    """Represents an extracted attachment payload before deep inspection."""
    filename: str
    content_type: str
    payload_bytes: bytes
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    content_id: Optional[str] = None
    is_inline: bool = False


@dataclass
class ParsedEmail:
    """Container holding all parsed components of an ingested EML file."""
    file_path: str
    file_sha256: str
    raw_message: EmailMessage
    metadata: EmailMetadata
    headers: list[tuple[str, str]]
    received_headers: list[str]
    auth_results_headers: list[str]
    plain_body: str
    html_body: str
    mime_parts: list[MimePart] = field(default_factory=list)
    attachments: list[RawAttachment] = field(default_factory=list)
    nested_messages: list["ParsedEmail"] = field(default_factory=list)


class EmlParser:
    """
    Enterprise-grade parser for RFC 5322 / RFC 2045 .eml email messages.
    Supports recursive multipart unpacking, encoding normalization, and nested messages.
    """

    def __init__(self, eml_policy: policy.Policy = policy.default):
        self.policy = eml_policy

    def parse_file(self, file_path: Union[str, Path]) -> ParsedEmail:
        """Parse an .eml file from the filesystem."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"EML file not found at: {path}")

        raw_bytes = path.read_bytes()
        return self.parse_bytes(raw_bytes, file_path=str(path))

    def parse_bytes(self, raw_bytes: bytes, file_path: str = "<in-memory>") -> ParsedEmail:
        """Parse raw RFC 5322 bytes into a structured ParsedEmail object."""
        file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        
        # Parse using Python's modern email policy
        msg: EmailMessage = email.message_from_bytes(raw_bytes, policy=self.policy)

        # 1. Extract raw headers and categorized headers
        headers_list: list[tuple[str, str]] = []
        received_headers: list[str] = []
        auth_results_headers: list[str] = []
        x_headers: dict[str, str] = {}

        for k, v in msg.items():
            val_str = str(v)
            headers_list.append((k, val_str))
            k_lower = k.lower()
            if k_lower == "received":
                received_headers.append(val_str)
            elif k_lower in ("authentication-results", "received-spf"):
                auth_results_headers.append(val_str)
            elif k_lower.startswith("x-"):
                x_headers[k] = val_str

        # 2. Extract and sanitize sender & recipient metadata
        from_raw = str(msg.get("From", ""))
        from_name, from_email = parseaddr(from_raw)
        from_domain = from_email.split("@")[1].lower() if "@" in from_email else ""

        reply_to_raw = msg.get("Reply-To")
        reply_to_email, reply_to_domain = None, None
        if reply_to_raw:
            _, reply_to_email = parseaddr(str(reply_to_raw))
            if reply_to_email and "@" in reply_to_email:
                reply_to_domain = reply_to_email.split("@")[1].lower()

        return_path = msg.get("Return-Path")
        return_path_clean, return_path_domain = None, None
        if return_path:
            _, return_path_clean = parseaddr(str(return_path))
            if return_path_clean and "@" in return_path_clean:
                return_path_domain = return_path_clean.split("@")[1].lower()

        # Extract To and CC lists
        to_raw = msg.get_all("To", [])
        to_addresses = [addr for _, addr in getaddresses([str(x) for x in to_raw]) if addr]

        cc_raw = msg.get_all("Cc", [])
        cc_addresses = [addr for _, addr in getaddresses([str(x) for x in cc_raw]) if addr]

        # Parse Date header safely
        date_raw = msg.get("Date")
        date_parsed = None
        if date_raw:
            try:
                date_parsed = dateutil.parser.parse(str(date_raw))
            except Exception:
                date_parsed = None

        metadata = EmailMetadata(
            message_id=msg.get("Message-ID"),
            subject=str(msg.get("Subject", "(No Subject)")),
            date=str(date_raw) if date_raw else None,
            date_parsed=date_parsed,
            from_raw=from_raw,
            from_name=from_name if from_name else None,
            from_email=from_email,
            from_domain=from_domain,
            reply_to_raw=str(reply_to_raw) if reply_to_raw else None,
            reply_to_email=reply_to_email,
            reply_to_domain=reply_to_domain,
            return_path=return_path_clean,
            return_path_domain=return_path_domain,
            to_emails=to_addresses,
            cc_emails=cc_addresses,
            user_agent=msg.get("User-Agent"),
            x_mailer=msg.get("X-Mailer"),
            x_headers=x_headers,
        )

        # 3. Recursive MIME unpacking
        plain_parts: list[str] = []
        html_parts: list[str] = []
        mime_parts: list[MimePart] = []
        attachments: list[RawAttachment] = []
        nested_messages: list[ParsedEmail] = []

        self._walk_parts(
            msg=msg,
            plain_parts=plain_parts,
            html_parts=html_parts,
            mime_parts=mime_parts,
            attachments=attachments,
            nested_messages=nested_messages,
        )

        plain_body = "\n\n".join(plain_parts).strip()
        html_body = "\n\n".join(html_parts).strip()

        return ParsedEmail(
            file_path=file_path,
            file_sha256=file_sha256,
            raw_message=msg,
            metadata=metadata,
            headers=headers_list,
            received_headers=received_headers,
            auth_results_headers=auth_results_headers,
            plain_body=plain_body,
            html_body=html_body,
            mime_parts=mime_parts,
            attachments=attachments,
            nested_messages=nested_messages,
        )

    def _walk_parts(
        self,
        msg: EmailMessage,
        plain_parts: list[str],
        html_parts: list[str],
        mime_parts: list[MimePart],
        attachments: list[RawAttachment],
        nested_messages: list[ParsedEmail],
        part_counter: Optional[list[int]] = None,
    ) -> None:
        """Recursively walk through message MIME tree."""
        if part_counter is None:
            part_counter = [0]

        for part in msg.walk():
            part_index = part_counter[0]
            part_counter[0] += 1

            content_type = part.get_content_type().lower()
            disposition = str(part.get_content_disposition() or "").lower()
            filename = part.get_filename()
            charset = part.get_content_charset() or "utf-8"
            content_id = part.get("Content-ID")

            is_attachment = (
                disposition in ("attachment", "inline") and filename is not None
            ) or (disposition == "attachment")

            # Check if this is a nested email
            if content_type == "message/rfc822":
                payload = part.get_payload()
                if isinstance(payload, list) and len(payload) > 0:
                    for sub_msg in payload:
                        if isinstance(sub_msg, EmailMessage):
                            nested = self.parse_bytes(sub_msg.as_bytes(), file_path="<nested-rfc822>")
                            nested_messages.append(nested)
                continue

            # Record MIME part metadata
            try:
                raw_payload = part.get_payload(decode=True)
            except Exception:
                raw_payload = None

            size_bytes = len(raw_payload) if raw_payload else 0

            mime_parts.append(
                MimePart(
                    part_index=part_index,
                    content_type=content_type,
                    charset=charset,
                    filename=filename,
                    size_bytes=size_bytes,
                    content_id=content_id,
                    is_attachment=is_attachment,
                )
            )

            # Extract body text or attachment
            if is_attachment and raw_payload:
                safe_filename = filename if filename else f"attachment_{part_index}.bin"
                attachments.append(
                    RawAttachment(
                        filename=safe_filename,
                        content_type=content_type,
                        payload_bytes=raw_payload,
                        size_bytes=size_bytes,
                        md5=hashlib.md5(raw_payload).hexdigest(),
                        sha1=hashlib.sha1(raw_payload).hexdigest(),
                        sha256=hashlib.sha256(raw_payload).hexdigest(),
                        content_id=content_id,
                        is_inline=(disposition == "inline"),
                    )
                )
            elif content_type == "text/plain" and raw_payload:
                try:
                    text = raw_payload.decode(charset, errors="replace")
                    plain_parts.append(text)
                except Exception:
                    plain_parts.append(raw_payload.decode("utf-8", errors="ignore"))
            elif content_type == "text/html" and raw_payload:
                try:
                    html = raw_payload.decode(charset, errors="replace")
                    html_parts.append(html)
                except Exception:
                    html_parts.append(raw_payload.decode("utf-8", errors="ignore"))
