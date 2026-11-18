"""
Unit tests for IMAP Mailbox Watcher and Automated Quarantine.
"""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from phishguard.cli import _run_analysis
from phishguard.models.report import ScanResult, VerdictEnum
from phishguard.parser.eml_parser import EmlParser
from phishguard.watcher.imap_watcher import ImapMailboxWatcher


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent.parent / "samples"


def test_watcher_process_raw_message_malicious(samples_dir: Path, tmp_path: Path):
    alert_dir = tmp_path / "alerts"
    alert_dir.mkdir()
    watcher = ImapMailboxWatcher(alert_dir=alert_dir)

    raw_eml = (samples_dir / "phishing_account_alert.eml").read_bytes()

    def mock_analyzer(raw_bytes: bytes) -> ScanResult:
        import asyncio
        p = EmlParser()
        parsed = p.parse_bytes(raw_bytes)
        return asyncio.run(_run_analysis(parsed, offline=True))

    res = watcher.process_raw_message(raw_eml, mock_analyzer)

    assert res.verdict == VerdictEnum.MALICIOUS
    assert watcher.stats.total_processed == 1
    assert watcher.stats.malicious_count == 1
    assert watcher.stats.quarantined_count == 1

    # Check alert JSON file created
    alert_files = list(alert_dir.glob("*.json"))
    assert len(alert_files) == 1


def test_watcher_poll_once_with_mock_imap(samples_dir: Path):
    watcher = ImapMailboxWatcher()

    raw_eml = (samples_dir / "benign_newsletter.eml").read_bytes()

    # Mock IMAP client
    mock_imap = MagicMock()
    mock_imap.select.return_value = ("OK", [b"1"])
    mock_imap.search.return_value = ("OK", [b"101"])
    mock_imap.fetch.return_value = ("OK", [(b"101 (RFC822 {100}", raw_eml)])

    def mock_analyzer(raw_bytes: bytes) -> ScanResult:
        import asyncio
        p = EmlParser()
        parsed = p.parse_bytes(raw_bytes)
        return asyncio.run(_run_analysis(parsed, offline=True))

    results = watcher.poll_once(mock_analyzer, client=mock_imap)

    assert len(results) == 1
    assert results[0].verdict == VerdictEnum.CLEAN
    assert watcher.stats.clean_count == 1
    mock_imap.store.assert_called_with(b"101", "+FLAGS", "\\Seen")
