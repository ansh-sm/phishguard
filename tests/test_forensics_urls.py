"""
Unit tests for URL Extraction, Defanging, and Deception Analysis.
"""

from pathlib import Path
import pytest
from phishguard.forensics.urls import UrlAnalyzer, calculate_entropy, defang_url, refang_url
from phishguard.parser.eml_parser import EmlParser


@pytest.fixture
def url_analyzer() -> UrlAnalyzer:
    return UrlAnalyzer()


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent.parent / "samples"


def test_defang_and_refang():
    original = "https://malicious-domain.xyz/login.php?user=admin"
    defanged = defang_url(original)

    assert defanged == "hxxps://malicious-domain[.]xyz/login[.]php?user=admin"
    refanged = refang_url(defanged)
    assert refanged == original


def test_entropy_calculation():
    # Regular domain should have moderate entropy
    entropy_normal = calculate_entropy("google.com")
    assert 2.0 < entropy_normal < 3.5

    # Random DGA string has high entropy
    entropy_dga = calculate_entropy("x98asdlkfjhq298y71239y4")
    assert entropy_dga > 3.8


def test_extract_and_analyze_phishing_email(url_analyzer: UrlAnalyzer, samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "phishing_account_alert.eml")

    artifacts = url_analyzer.extract_and_analyze(parsed.plain_body, parsed.html_body)
    assert len(artifacts) >= 2

    # Find the deceptive PayPal button URL
    deceptive_url = next((u for u in artifacts if u.is_mismatched_anchor), None)
    assert deceptive_url is not None
    assert deceptive_url.is_ip_host is True
    assert deceptive_url.domain == "185.220.101.5"
    assert deceptive_url.risk_score >= 50.0
    assert any("Hyperlink deception" in r for r in deceptive_url.risk_reasons)

    # Find bit.ly shortener
    shortener_url = next((u for u in artifacts if u.is_shortener), None)
    assert shortener_url is not None
    assert shortener_url.domain == "bit.ly"


def test_extract_and_analyze_benign_email(url_analyzer: UrlAnalyzer, samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "benign_newsletter.eml")

    artifacts = url_analyzer.extract_and_analyze(parsed.plain_body, parsed.html_body)
    assert len(artifacts) >= 1

    for u in artifacts:
        assert u.domain == "techdigest.com"
        assert u.is_mismatched_anchor is False
        assert u.is_ip_host is False
