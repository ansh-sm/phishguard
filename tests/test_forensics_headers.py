"""
Unit tests for Header Forensics and Hop Route Reconstruction.
"""

from pathlib import Path
import pytest
from phishguard.parser.eml_parser import EmlParser
from phishguard.forensics.headers import HeaderForensicsEngine, ReceivedHopParser


@pytest.fixture
def hop_parser() -> ReceivedHopParser:
    return ReceivedHopParser()


@pytest.fixture
def forensics_engine() -> HeaderForensicsEngine:
    return HeaderForensicsEngine()


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent.parent / "samples"


def test_received_hop_parsing(hop_parser: ReceivedHopParser):
    raw_headers = [
        # Newest hop (MX)
        "from mail-relay.paypa1-update.com (185.220.101.5) by mx.enterprise.corp (Postfix) with ESMTPS id 4X98Kj2 for <target@corp.com>; Fri, 14 Nov 2026 18:22:15 +0000",
        # Oldest hop (Origin internal)
        "from internal-bot.phish.ru (192.168.1.50) by mail-relay.paypa1-update.com with HTTP; Fri, 14 Nov 2026 18:22:05 +0000",
    ]

    hops = hop_parser.parse_hops(raw_headers)
    assert len(hops) == 2

    # Chronological check: Hop 0 should be the oldest hop
    hop0 = hops[0]
    assert hop0.hop_index == 0
    assert hop0.client_ip == "192.168.1.50"
    assert hop0.is_private_ip is True
    assert hop0.from_host == "internal-bot.phish.ru"
    assert hop0.by_host == "mail-relay.paypa1-update.com"
    assert hop0.protocol == "HTTP"

    # Hop 1 (relay to MX)
    hop1 = hops[1]
    assert hop1.hop_index == 1
    assert hop1.client_ip == "185.220.101.5"
    assert hop1.is_private_ip is False
    assert hop1.by_host == "mx.enterprise.corp"
    assert hop1.delay_from_previous_seconds == 10.0  # 18:22:15 - 18:22:05 = 10 seconds


def test_originating_ip_identification(forensics_engine: HeaderForensicsEngine, samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "phishing_account_alert.eml")

    hops, orig_ip, anomalies, score = forensics_engine.analyze_headers(parsed)

    assert len(hops) == 2
    # Originating public IP should be 185.220.101.5 (skipping 192.168.1.50 RFC 1918)
    assert orig_ip == "185.220.101.5"


def test_duplicate_from_header_detection(forensics_engine: HeaderForensicsEngine):
    raw_eml = (
        b"From: legitimate@company.com\r\n"
        b"From: attacker@evil.com\r\n"
        b"To: victim@company.com\r\n"
        b"Subject: Test Duplicate From\r\n"
        b"\r\n"
        b"Body content"
    )
    parser = EmlParser()
    parsed = parser.parse_bytes(raw_eml)

    hops, orig_ip, anomalies, score = forensics_engine.analyze_headers(parsed)
    assert any("Multiple 'From' headers detected" in a for a in anomalies)
    assert score >= 25.0
