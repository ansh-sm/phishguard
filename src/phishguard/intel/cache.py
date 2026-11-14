"""
SQLite-backed Persistent Threat Intelligence Cache with TTL.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Optional


class IntelCache:
    """
    Thread-safe SQLite persistent cache for Threat Intel queries with TTL expiration.
    Prevents repeated network hits and respects API rate limits.
    """

    def __init__(self, db_path: Optional[Path] = None, default_ttl_hours: int = 24):
        if db_path is None:
            # Default to local cache directory inside package or user cache
            cache_dir = Path.home() / ".phishguard" / "cache"
            cache_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = cache_dir / "threat_intel_cache.db"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.default_ttl = timedelta(hours=default_ttl_hours)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite cache schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS intel_lookups (
                    url_hash TEXT PRIMARY KEY,
                    raw_url TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    is_flagged INTEGER NOT NULL,
                    tags TEXT,
                    details_json TEXT,
                    cached_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON intel_lookups(expires_at)")
            conn.commit()

    @staticmethod
    def _hash_key(provider: str, url: str) -> str:
        """Create unique key from provider and target URL."""
        return hashlib.sha256(f"{provider}:{url.strip().lower()}".encode("utf-8")).hexdigest()

    def get(self, provider: str, url: str) -> Optional[dict[str, Any]]:
        """Retrieve cached intel record if not expired."""
        key = self._hash_key(provider, url)
        now = datetime.now(timezone.utc)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT is_flagged, tags, details_json, expires_at FROM intel_lookups WHERE url_hash = ?",
                (key,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            is_flagged, tags_str, details_json, expires_at_str = row
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if now > expires_at:
                    # Expired entry, delete and return None
                    conn.execute("DELETE FROM intel_lookups WHERE url_hash = ?", (key,))
                    conn.commit()
                    return None
            except Exception:
                return None

            tags = tags_str.split(",") if tags_str else []
            details = json.loads(details_json) if details_json else {}

            return {
                "is_flagged": bool(is_flagged),
                "tags": tags,
                "details": details,
                "cached": True,
            }

    def set(
        self,
        provider: str,
        url: str,
        is_flagged: bool,
        tags: list[str],
        details: dict[str, Any],
        ttl_hours: Optional[int] = None,
    ) -> None:
        """Store lookup result into persistent SQLite cache."""
        key = self._hash_key(provider, url)
        now = datetime.now(timezone.utc)
        ttl = timedelta(hours=ttl_hours) if ttl_hours else self.default_ttl
        expires_at = now + ttl

        tags_str = ",".join(tags)
        details_json = json.dumps(details)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO intel_lookups 
                (url_hash, raw_url, provider, is_flagged, tags, details_json, cached_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    url,
                    provider,
                    1 if is_flagged else 0,
                    tags_str,
                    details_json,
                    now.isoformat(),
                    expires_at.isoformat(),
                ),
            )
            conn.commit()

    def clear_expired(self) -> int:
        """Clean up expired entries."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM intel_lookups WHERE expires_at < ?", (now,))
            conn.commit()
            return cursor.rowcount
