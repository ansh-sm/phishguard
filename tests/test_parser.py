"""
Unit tests for EmlParser and Email Models.
"""

from pathlib import Path
import pytest
from phishguard.parser.eml_parser import EmlParser
from phishguard.models.email import EmailMetadata


@pytest.fixture
def parser() -> EmlParser:
    return EmlParser()


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent.parent / "samples"


def test_parse_phishing_account_alert(parser: EmlParser, samples_dir: Path):
    eml_file = samples_dir / "phishing_account_alert.eml"
    assert eml_file.exists()

    parsed = parser.parse_file(eml_file)

    # Check top-level metadata
    assert "PayPal Security Support" in parsed.metadata.from_name
    assert parsed.metadata.from_email == "security-alerts@paypa1-update.com"
    assert parsed.metadata.from_domain == "paypa1-update.com"
    assert parsed.metadata.reply_to_email == "credential-collector@stealer-domain.xyz"
    assert parsed.metadata.reply_to_domain == "stealer-domain.xyz"
    assert "URGENT" in parsed.metadata.subject

    # Check authentication and received headers
    assert len(parsed.received_headers) == 2
    assert len(parsed.auth_results_headers) >= 1

    # Check body parts
    assert "PayPal" in parsed.plain_body
    assert "verify-identity" in parsed.plain_body
    assert "<!DOCTYPE html>" in parsed.html_body
    assert "paypa1-update.com" in parsed.file_sha256 or len(parsed.file_sha256) == 64


def test_parse_benign_newsletter(parser: EmlParser, samples_dir: Path):
    eml_file = samples_dir / "benign_newsletter.eml"
    assert eml_file.exists()

    parsed = parser.parse_file(eml_file)

    assert parsed.metadata.from_domain == "techdigest.com"
    assert parsed.metadata.reply_to_domain == "techdigest.com"
    assert "Issue #142" in parsed.metadata.subject
    assert len(parsed.received_headers) == 1
    assert "unsubscribe" in parsed.plain_body.lower()
