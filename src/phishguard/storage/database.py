"""
Persistent SOC Incident Database & Threat Hunting Storage.
Stores complete forensic reports in SQLite with fast indexing across IOCs and adversary techniques.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Optional, Union

from phishguard.models.report import ScanResult
from phishguard.storage.models import IncidentQueryFilter, IncidentSummary


class IncidentDatabase:
    """
    SQLite-backed repository for historical triage records, threat hunting, and metrics.
    """

    DEFAULT_DB_PATH = Path("data/phishguard_soc.db")

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        if db_path:
            self.db_path = Path(db_path)
        else:
            env_path = os.getenv("PHISHGUARD_SOC_DB")
            self.db_path = Path(env_path) if env_path else self.DEFAULT_DB_PATH

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        """Initializes tables and high-performance search indexes."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    scan_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    from_email TEXT NOT NULL,
                    from_domain TEXT NOT NULL,
                    originating_ip TEXT,
                    verdict TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    total_score REAL NOT NULL,
                    confidence REAL NOT NULL,
                    file_sha256 TEXT NOT NULL,
                    urls_json TEXT NOT NULL,
                    attachment_hashes_json TEXT NOT NULL,
                    mitre_techniques_json TEXT NOT NULL,
                    matched_rules_json TEXT NOT NULL,
                    full_report_json TEXT NOT NULL
                );
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_verdict ON incidents(verdict);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_domain ON incidents(from_domain);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(originating_ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_file_sha ON incidents(file_sha256);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents(timestamp);")
            conn.commit()

    def save_scan(self, result: ScanResult) -> None:
        """Persists a complete ScanResult into the incident database."""
        sender_email = result.metadata.from_email or result.metadata.from_raw
        sender_domain = result.metadata.from_domain or (sender_email.split("@")[-1] if "@" in sender_email else "")

        urls_list = [u.raw_url for u in result.urls]
        attachment_hashes = [a.sha256 for a in result.attachments if a.sha256]
        mitre_ids = [t.technique_id for t in result.mitre_attack]
        rule_ids = [r.rule_id for r in result.matched_rules]

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    scan_id, timestamp, subject, from_email, from_domain,
                    originating_ip, verdict, severity, total_score, confidence,
                    file_sha256, urls_json, attachment_hashes_json,
                    mitre_techniques_json, matched_rules_json, full_report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    result.scan_id,
                    result.timestamp.isoformat(),
                    result.metadata.subject,
                    sender_email,
                    sender_domain,
                    result.headers.originating_ip,
                    result.verdict.value,
                    result.severity.value,
                    result.score.total_score,
                    result.confidence_percentage,
                    result.eml_file_hash_sha256,
                    json.dumps(urls_list),
                    json.dumps(attachment_hashes),
                    json.dumps(mitre_ids),
                    json.dumps(rule_ids),
                    result.model_dump_json(),
                ),
            )
            conn.commit()

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """Retrieves and deserializes full ScanResult by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT full_report_json FROM incidents WHERE scan_id = ?;", (scan_id,)).fetchone()
            if not row:
                return None
            return ScanResult.model_validate_json(row["full_report_json"])

    def search_incidents(self, filters: IncidentQueryFilter) -> list[IncidentSummary]:
        """Threat hunting query engine across multiple forensic dimensions."""
        query_clauses = ["1=1"]
        params: list[Any] = []

        if filters.query:
            query_clauses.append("(subject LIKE ? OR from_email LIKE ? OR full_report_json LIKE ?)")
            pattern = f"%{filters.query}%"
            params.extend([pattern, pattern, pattern])

        if filters.ip:
            query_clauses.append("originating_ip = ?")
            params.append(filters.ip)

        if filters.domain:
            query_clauses.append("(from_domain LIKE ? OR urls_json LIKE ?)")
            dom_pat = f"%{filters.domain}%"
            params.extend([dom_pat, dom_pat])

        if filters.hash_val:
            query_clauses.append("(file_sha256 = ? OR attachment_hashes_json LIKE ?)")
            params.extend([filters.hash_val, f"%{filters.hash_val}%"])

        if filters.technique:
            query_clauses.append("mitre_techniques_json LIKE ?")
            params.append(f"%{filters.technique}%")

        if filters.verdict:
            query_clauses.append("verdict = ?")
            params.append(filters.verdict.upper())

        sql = f"""
            SELECT scan_id, timestamp, subject, from_email, from_domain,
                   originating_ip, verdict, severity, total_score, file_sha256,
                   matched_rules_json, mitre_techniques_json
            FROM incidents
            WHERE {" AND ".join(query_clauses)}
            ORDER BY timestamp DESC
            LIMIT ?;
        """
        params.append(filters.limit)

        summaries: list[IncidentSummary] = []
        with self._get_connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            for r in rows:
                rules = json.loads(r["matched_rules_json"]) if r["matched_rules_json"] else []
                mitre = json.loads(r["mitre_techniques_json"]) if r["mitre_techniques_json"] else []
                summaries.append(
                    IncidentSummary(
                        scan_id=r["scan_id"],
                        timestamp=r["timestamp"],
                        subject=r["subject"],
                        from_email=r["from_email"],
                        from_domain=r["from_domain"],
                        originating_ip=r["originating_ip"],
                        verdict=r["verdict"],
                        severity=r["severity"],
                        total_score=r["total_score"],
                        file_sha256=r["file_sha256"],
                        matched_rules_count=len(rules),
                        mitre_count=len(mitre),
                        mitre_techniques=",".join(mitre),
                    )
                )

        return summaries

    def get_stats(self) -> dict[str, Any]:
        """Computes executive threat telemetry and triage metrics."""
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM incidents;").fetchone()[0]
            malicious = conn.execute("SELECT COUNT(*) FROM incidents WHERE verdict = 'MALICIOUS';").fetchone()[0]
            suspicious = conn.execute("SELECT COUNT(*) FROM incidents WHERE verdict = 'SUSPICIOUS';").fetchone()[0]
            clean = conn.execute("SELECT COUNT(*) FROM incidents WHERE verdict = 'CLEAN';").fetchone()[0]

            top_ips_rows = conn.execute("""
                SELECT originating_ip, COUNT(*) as cnt
                FROM incidents
                WHERE originating_ip IS NOT NULL AND originating_ip != ''
                GROUP BY originating_ip
                ORDER BY cnt DESC
                LIMIT 5;
            """).fetchall()

            top_domains_rows = conn.execute("""
                SELECT from_domain, COUNT(*) as cnt
                FROM incidents
                WHERE from_domain != ''
                GROUP BY from_domain
                ORDER BY cnt DESC
                LIMIT 5;
            """).fetchall()

            return {
                "total_scans": total,
                "verdict_breakdown": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "clean": clean,
                },
                "top_attacker_ips": [{"ip": r["originating_ip"], "count": r["cnt"]} for r in top_ips_rows],
                "top_sender_domains": [{"domain": r["from_domain"], "count": r["cnt"]} for r in top_domains_rows],
            }
