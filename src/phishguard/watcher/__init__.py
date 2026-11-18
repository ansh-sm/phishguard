"""
Real-time Mailbox Ingestion and Quarantine Watcher for PhishGuard SOC.
"""

from phishguard.watcher.imap_watcher import ImapMailboxWatcher, WatcherStats

__all__ = ["ImapMailboxWatcher", "WatcherStats"]
