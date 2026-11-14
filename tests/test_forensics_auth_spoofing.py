"""
Unit tests for Email Authentication and Spoofing/Impersonation Detection.
"""

from pathlib import Path
import pytest
from phishguard.forensics.auth import AuthResultsParser
from phishguard.forensics.spoofing import SpoofingDetector
from phishguard.models.email import AuthStatus, EmailMetadata
from phishguard.parser.eml_parser import EmlParser


@pytest.fixture
def auth_parser() -> AuthResultsParser:
    return AuthResultsParser()


@pytest.fixture
def spoof_detector() -> SpoofingDetector:
    return SpoofingDetector()


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent.parent / "samples"


def test_auth_parser_phishing_sample(auth_parser: AuthResultsParser, samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "phishing_account_alert.eml")

    auth = auth_parser.parse(parsed.auth_results_headers)

    assert auth.spf_status == AuthStatus.FAIL
    assert auth.spf_sender_ip == "185.220.101.5"
    assert auth.dkim_status == AuthStatus.NEUTRAL
    assert auth.dmarc_status == AuthStatus.FAIL
    assert auth.dmarc_action == "none"


def test_auth_parser_benign_sample(auth_parser: AuthResultsParser, samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "benign_newsletter.eml")

    auth = auth_parser.parse(parsed.auth_results_headers)

    assert auth.spf_status == AuthStatus.PASS
    assert auth.dkim_status == AuthStatus.PASS
    assert auth.dmarc_status == AuthStatus.PASS


def test_spoof_detection_typosquatting(spoof_detector: SpoofingDetector):
    meta = EmailMetadata(
        from_name="PayPal Security Support",
        from_email="support@paypa1-update.com",
        from_domain="paypa1-update.com",
        reply_to_email="attacker@stealer-domain.xyz",
        reply_to_domain="stealer-domain.xyz",
    )

    (
        disp_spoof,
        reply_mismatch,
        punycode,
        homoglyph,
        lookalike,
        anomalies,
        score,
    ) = spoof_detector.analyze(meta)

    assert disp_spoof is True
    assert reply_mismatch is True
    assert lookalike == "Paypal"
    assert any("typosquats" in a or "incorporates" in a for a in anomalies)
    assert any("Reply-To address mismatch" in a for a in anomalies)
    assert score >= 25.0


def test_spoof_detection_homoglyph_and_punycode(spoof_detector: SpoofingDetector):
    # Domain with Cyrillic 'a' (\u0430) instead of Latin 'a'
    homoglyph_domain = "p\u0430ypal.com"
    meta = EmailMetadata(
        from_name="Security Notice",
        from_email=f"service@{homoglyph_domain}",
        from_domain=homoglyph_domain,
    )

    _, _, _, homoglyph, _, anomalies, score = spoof_detector.analyze(meta)
    assert homoglyph is True
    assert any("homoglyph" in a.lower() for a in anomalies)
    assert score >= 20.0
