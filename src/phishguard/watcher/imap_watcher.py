"""
IMAP Mailbox Watcher & Automated SOC Quarantine Daemon for PhishGuard.
Monitors security abuse inboxes, triages incoming reports in real time, and quarantines threats.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from email import message_from_bytes
from email.policy import default
import imaplib
from pathlib import Path
import time
from typing import Callable, Optional

from phishguard.models.report import ScanResult, VerdictEnum
from phishguard.parser.eml_parser import EmlParser
from phishguard.reporters.json_reporter import JsonReporter


@dataclass
class WatcherStats:
    """Statistics tracked during mailbox monitoring."""
    total_processed: int = 0
    malicious_count: int = 0
    suspicious_count: int = 0
    clean_count: int = 0
    quarantined_count: int = 0
    errors_count: int = 0


class ImapMailboxWatcher:
    """
    Automated daemon for continuous monitoring of enterprise phishing abuse mailboxes.
    """

    def __init__(
        self,
        host: str = "imap.example.com",
        port: int = 993,
        user: str = "abuse@example.com",
        password: str = "password",
        source_folder: str = "INBOX",
        quarantine_folder: str = "Quarantine",
        alert_dir: Optional[Path] = None,
        use_ssl: bool = True,
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.source_folder = source_folder
        self.quarantine_folder = quarantine_folder
        self.alert_dir = alert_dir
        self.use_ssl = use_ssl
        self.stats = WatcherStats()
        self.parser = EmlParser()
        self.json_reporter = JsonReporter()

    def process_raw_message(
        self, raw_bytes: bytes, analyzer_fn: Callable[[bytes], ScanResult]
    ) -> ScanResult:
        """Process a raw email message payload through the triage pipeline."""
        self.stats.total_processed += 1
        result = analyzer_fn(raw_bytes)

        if result.verdict == VerdictEnum.MALICIOUS:
            self.stats.malicious_count += 1
            self.stats.quarantined_count += 1
            if self.alert_dir:
                alert_path = Path(self.alert_dir) / f"alert_{result.scan_id}.json"
                self.json_reporter.export(result, output_path=alert_path)
        elif result.verdict == VerdictEnum.SUSPICIOUS:
            self.stats.suspicious_count += 1
        else:
            self.stats.clean_count += 1

        return result

    def poll_once(
        self, analyzer_fn: Callable[[bytes], ScanResult], client: Optional[imaplib.IMAP4] = None
    ) -> list[ScanResult]:
        """
        Poll IMAP mailbox once for unseen messages, analyze them, and quarantine threats.
        """
        results: list[ScanResult] = []
        imap = client

        try:
            if not imap:
                imap = (
                    imaplib.IMAP4_SSL(self.host, self.port)
                    if self.use_ssl
                    else imaplib.IMAP4(self.host, self.port)
                )
                imap.login(self.user, self.password)

            status, _ = imap.select(self.source_folder)
            if status != "OK":
                return results

            # Search unread messages
            typ, data = imap.search(None, "UNSEEN")
            if typ != "OK" or not data[0]:
                return results

            msg_ids = data[0].split()
            for msg_id in msg_ids:
                try:
                    fetch_status, fetch_data = imap.fetch(msg_id, "(RFC822)")
                    if fetch_status != "OK" or not fetch_data:
                        continue

                    raw_eml = fetch_data[0][1]
                    res = self.process_raw_message(raw_eml, analyzer_fn)
                    results.append(res)

                    if res.verdict == VerdictEnum.MALICIOUS:
                        # Copy to quarantine folder and mark deleted in INBOX
                        try:
                            imap.copy(msg_id, self.quarantine_folder)
                            imap.store(msg_id, "+FLAGS", "\\Deleted")
                        except Exception:
                            pass
                    else:
                        # Mark read
                        imap.store(msg_id, "+FLAGS", "\\Seen")

                except Exception:
                    self.stats.errors_count += 1

            imap.expunge()

        except Exception:
            self.stats.errors_count += 1
        finally:
            if client is None and imap:
                try:
                    imap.logout()
                except Exception:
                    pass

        return results
