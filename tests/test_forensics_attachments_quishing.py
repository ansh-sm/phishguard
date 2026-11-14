"""
Unit tests for Attachment Forensics and Quishing Detection.
"""

import io
from pathlib import Path
import zipfile
import pytest

from phishguard.forensics.attachments import AttachmentForensicsEngine
from phishguard.forensics.quishing import QuishingDetector
from phishguard.parser.eml_parser import EmlParser, RawAttachment


@pytest.fixture
def attachment_engine() -> AttachmentForensicsEngine:
    return AttachmentForensicsEngine()


@pytest.fixture
def quishing_detector() -> QuishingDetector:
    return QuishingDetector()


def test_mime_spoofing_detection(attachment_engine: AttachmentForensicsEngine):
    # File named invoice.pdf, but starts with MZ (Windows PE executable)
    fake_pdf = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
    raw_att = RawAttachment(
        filename="invoice.pdf",
        content_type="application/pdf",
        payload_bytes=fake_pdf,
        size_bytes=len(fake_pdf),
        md5="testmd5",
        sha1="testsha1",
        sha256="testsha256",
    )

    artifact = attachment_engine.inspect_attachment(raw_att)

    assert artifact.is_executable is True
    assert artifact.detected_mime == "application/x-dosexec"
    assert any("Severe MIME Spoofing" in r for r in artifact.risk_reasons)
    assert artifact.risk_score >= 50.0


def test_double_extension_detection(attachment_engine: AttachmentForensicsEngine):
    script_payload = b"MsgBox 'You are hacked'"
    raw_att = RawAttachment(
        filename="bonus_payout.xlsx.vbs",
        content_type="application/octet-stream",
        payload_bytes=script_payload,
        size_bytes=len(script_payload),
        md5="testmd5",
        sha1="testsha1",
        sha256="testsha256",
    )

    artifact = attachment_engine.inspect_attachment(raw_att)

    assert artifact.is_double_extension is True
    assert artifact.is_script is True
    assert any("Deceptive double extension" in r for r in artifact.risk_reasons)
    assert artifact.risk_score >= 35.0


def test_archive_inspection_concealed_payload(attachment_engine: AttachmentForensicsEngine):
    # Create in-memory zip file containing a hidden .bat file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as z:
        z.writestr("benign_readme.txt", "Please read this.")
        z.writestr("urgent_setup.bat", "@echo off\r\nstart calc.exe")

    zip_bytes = zip_buffer.getvalue()
    raw_att = RawAttachment(
        filename="documents.zip",
        content_type="application/zip",
        payload_bytes=zip_bytes,
        size_bytes=len(zip_bytes),
        md5="testmd5",
        sha1="testsha1",
        sha256="testsha256",
    )

    artifact = attachment_engine.inspect_attachment(raw_att)

    assert artifact.is_archive is True
    assert "urgent_setup.bat" in artifact.archive_contents
    assert any("Archive contains hidden executable or script payload" in r for r in artifact.risk_reasons)
    assert artifact.risk_score >= 40.0


def test_quishing_detection(quishing_detector: QuishingDetector):
    raw_quish_eml = (
        b"From: IT Helpdesk <it@enterprise.corp>\r\n"
        b"To: victim@enterprise.corp\r\n"
        b"Subject: Mandatory MFA Upgrade - Scan QR Code\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><body>"
        b"<p>Please scan this QR code with your mobile authenticator to verify your token:</p>"
        b"<img src='cid:qr_image.png' id='auth-qr-code' alt='Scan QR Code' />"
        b"</body></html>"
    )

    parser = EmlParser()
    parsed = parser.parse_bytes(raw_quish_eml)

    result = quishing_detector.analyze(parsed)

    assert result.found is True
    assert any("Quishing attack detected" in r for r in result.risk_reasons)
    assert result.risk_score >= 40.0
