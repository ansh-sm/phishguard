"""Persistent SQLite repository and manager for SOC triage cases."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Optional
import uuid

from phishguard.cases.models import (
    CaseIoc,
    CaseNote,
    CaseSeverity,
    CaseStatus,
    SocCase,
)
from phishguard.models.report import ScanResult

DEFAULT_CASES_DB = Path.home() / ".phishguard" / "cases.db"


class CaseManager:
    """Enterprise case management repository with SQLite persistence."""

    def __init__(self, db_path: Optional[str | Path] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_CASES_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """Initialize database tables with WAL mode."""
        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    assigned_analyst TEXT NOT NULL,
                    source_scan_id TEXT,
                    sender TEXT,
                    subject TEXT,
                    score REAL,
                    summary TEXT,
                    containment_status TEXT,
                    timeline_json TEXT,
                    iocs_json TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_case_status ON cases(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_case_severity ON cases(severity);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_case_analyst ON cases(assigned_analyst);")
            conn.commit()

    def create_case(
        self,
        title: str,
        severity: CaseSeverity = CaseSeverity.MEDIUM,
        sender: str = "",
        subject: str = "",
        score: float = 0.0,
        summary: str = "",
        assigned_analyst: str = "tier1-analyst",
        source_scan_id: Optional[str] = None,
        iocs: Optional[list[CaseIoc]] = None,
    ) -> SocCase:
        """Create a new SOC triage case."""
        now = datetime.now(timezone.utc).isoformat()
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        random_suffix = uuid.uuid4().hex[:6].upper()
        case_id = f"CASE-{date_str}-{random_suffix}"

        initial_note = CaseNote(
            id=uuid.uuid4().hex[:8],
            timestamp=now,
            analyst="system",
            message=f"Case opened with initial severity {severity.value} (Risk Score: {score}).",
        )

        case = SocCase(
            case_id=case_id,
            title=title,
            created_at=now,
            updated_at=now,
            status=CaseStatus.NEW,
            severity=severity,
            assigned_analyst=assigned_analyst,
            source_scan_id=source_scan_id,
            sender=sender,
            subject=subject,
            score=score,
            summary=summary,
            timeline=[initial_note],
            iocs=iocs or [],
            containment_status="OPEN",
        )

        self._save_case(case)
        return case

    def create_case_from_scan(
        self,
        scan_result: ScanResult,
        assigned_analyst: str = "tier1-analyst",
    ) -> SocCase:
        """Automatically create and populate a SOC case from a completed scan result."""
        score = scan_result.total_score
        if score >= 80.0:
            severity = CaseSeverity.CRITICAL
        elif score >= 60.0:
            severity = CaseSeverity.HIGH
        elif score >= 30.0:
            severity = CaseSeverity.MEDIUM
        else:
            severity = CaseSeverity.LOW

        sender = getattr(scan_result.metadata, "from_email", "") or getattr(scan_result.metadata, "from_raw", "")
        subject = getattr(scan_result.metadata, "subject", "")

        # Extract IOCs
        iocs: list[CaseIoc] = []
        orig_ip = getattr(scan_result, "originating_ip", None) or (getattr(scan_result.headers, "originating_ip", "") if hasattr(scan_result, "headers") else "")
        sender_domain = getattr(scan_result, "sender_domain", None) or (getattr(scan_result.metadata, "from_domain", "") if hasattr(scan_result, "metadata") else "")

        if orig_ip and orig_ip != "Unknown":
            iocs.append(CaseIoc(ioc_type="ip", value=orig_ip, status="PENDING"))
        if sender_domain:
            iocs.append(CaseIoc(ioc_type="domain", value=sender_domain, status="PENDING"))

        for url_art in scan_result.urls:
            raw_url = getattr(url_art, "raw_url", "")
            if raw_url:
                iocs.append(CaseIoc(ioc_type="url", value=raw_url, status="PENDING"))

        for att in scan_result.attachments:
            h = getattr(att, "sha256", "")
            if h:
                iocs.append(CaseIoc(ioc_type="sha256", value=h, status="PENDING"))

        title = f"Phishing Triage: {subject or 'Suspicious Email'}"
        summary = (
            f"Adversary email identified from '{sender}' with risk score {score:.1f}/100. "
            f"Verdict: {scan_result.verdict}. Contributing triggers: {len(scan_result.flags)} flagged rules."
        )

        return self.create_case(
            title=title,
            severity=severity,
            sender=sender,
            subject=subject,
            score=score,
            summary=summary,
            assigned_analyst=assigned_analyst,
            source_scan_id=scan_result.file_hash,
            iocs=iocs,
        )

    def _save_case(self, case: SocCase) -> None:
        """Persist or update a case in SQLite."""
        timeline_json = json.dumps([n.model_dump() for n in case.timeline])
        iocs_json = json.dumps([i.model_dump() for i in case.iocs])

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO cases (
                    case_id, title, created_at, updated_at, status, severity,
                    assigned_analyst, source_scan_id, sender, subject, score,
                    summary, containment_status, timeline_json, iocs_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    title=excluded.title,
                    updated_at=excluded.updated_at,
                    status=excluded.status,
                    severity=excluded.severity,
                    assigned_analyst=excluded.assigned_analyst,
                    containment_status=excluded.containment_status,
                    timeline_json=excluded.timeline_json,
                    iocs_json=excluded.iocs_json;
                """,
                (
                    case.case_id,
                    case.title,
                    case.created_at,
                    case.updated_at,
                    case.status.value,
                    case.severity.value,
                    case.assigned_analyst,
                    case.source_scan_id,
                    case.sender,
                    case.subject,
                    case.score,
                    case.summary,
                    case.containment_status,
                    timeline_json,
                    iocs_json,
                ),
            )
            conn.commit()

    def get_case(self, case_id: str) -> Optional[SocCase]:
        """Fetch a single case by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if not row:
                return None
            return self._row_to_case(row)

    def list_cases(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        analyst: Optional[str] = None,
        limit: int = 50,
    ) -> list[SocCase]:
        """Query cases with optional filtering."""
        query = "SELECT * FROM cases WHERE 1=1"
        params: list[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status.upper())
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if analyst:
            query += " AND assigned_analyst = ?"
            params.append(analyst)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_case(r) for r in rows]

    def update_case(
        self,
        case_id: str,
        status: Optional[CaseStatus | str] = None,
        severity: Optional[CaseSeverity | str] = None,
        assigned_analyst: Optional[str] = None,
        containment_status: Optional[str] = None,
    ) -> Optional[SocCase]:
        """Update case lifecycle state, severity, or assignment."""
        case = self.get_case(case_id)
        if not case:
            return None

        now = datetime.now(timezone.utc).isoformat()
        notes_to_add: list[str] = []

        if status:
            new_status = CaseStatus(status) if isinstance(status, str) else status
            if new_status != case.status:
                notes_to_add.append(f"Status changed from {case.status.value} to {new_status.value}")
                case.status = new_status

        if severity:
            new_sev = CaseSeverity(severity) if isinstance(severity, str) else severity
            if new_sev != case.severity:
                notes_to_add.append(f"Severity adjusted from {case.severity.value} to {new_sev.value}")
                case.severity = new_sev

        if assigned_analyst and assigned_analyst != case.assigned_analyst:
            notes_to_add.append(f"Reassigned from {case.assigned_analyst} to {assigned_analyst}")
            case.assigned_analyst = assigned_analyst

        if containment_status and containment_status != case.containment_status:
            notes_to_add.append(f"Containment status changed to {containment_status}")
            case.containment_status = containment_status

        for msg in notes_to_add:
            case.timeline.append(
                CaseNote(
                    id=uuid.uuid4().hex[:8],
                    timestamp=now,
                    analyst="system",
                    message=msg,
                )
            )

        case.updated_at = now
        self._save_case(case)
        return case

    def add_note(self, case_id: str, analyst: str, message: str) -> Optional[SocCase]:
        """Append an analyst note to the case timeline."""
        case = self.get_case(case_id)
        if not case:
            return None

        now = datetime.now(timezone.utc).isoformat()
        note = CaseNote(
            id=uuid.uuid4().hex[:8],
            timestamp=now,
            analyst=analyst,
            message=message,
        )
        case.timeline.append(note)
        case.updated_at = now

        # Transition NEW to IN_TRIAGE if an analyst starts investigating
        if case.status == CaseStatus.NEW:
            case.status = CaseStatus.IN_TRIAGE

        self._save_case(case)
        return case

    def update_ioc_status(self, case_id: str, ioc_value: str, new_status: str) -> Optional[SocCase]:
        """Update containment status for a specific IOC in the case."""
        case = self.get_case(case_id)
        if not case:
            return None

        updated = False
        for ioc in case.iocs:
            if ioc.value == ioc_value:
                ioc.status = new_status.upper()
                updated = True

        if updated:
            now = datetime.now(timezone.utc).isoformat()
            case.updated_at = now
            case.timeline.append(
                CaseNote(
                    id=uuid.uuid4().hex[:8],
                    timestamp=now,
                    analyst="system",
                    message=f"IOC '{ioc_value}' containment status updated to {new_status.upper()}",
                )
            )
            self._save_case(case)

        return case

    def export_case_dossier(self, case_id: str, format: str = "markdown") -> str:
        """Export case briefing in Markdown or JSON format."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        if format.lower() == "json":
            return case.model_dump_json(indent=2)

        # Markdown Dossier
        lines = [
            f"# SOC Incident Dossier: {case.case_id}",
            f"**Title**: {case.title}",
            f"**Status**: `{case.status.value}` | **Severity**: `{case.severity.value}` | **Risk Score**: {case.score:.1f}/100",
            f"**Assigned Analyst**: {case.assigned_analyst} | **Created**: {case.created_at}",
            "",
            "## Incident Overview",
            f"- **Sender**: `{case.sender}`",
            f"- **Subject**: `{case.subject}`",
            f"- **Source Scan Hash**: `{case.source_scan_id or 'N/A'}`",
            f"- **Containment Status**: `{case.containment_status}`",
            "",
            f"> {case.summary}",
            "",
            "## Indicators of Compromise (IOCs)",
            "| Type | Value | Status |",
            "| :--- | :--- | :--- |",
        ]

        if case.iocs:
            for ioc in case.iocs:
                lines.append(f"| `{ioc.ioc_type}` | `{ioc.value}` | **{ioc.status}** |")
        else:
            lines.append("| N/A | No IOCs linked | - |")

        lines.extend([
            "",
            "## Investigation Timeline & Analyst Notes",
            "| Timestamp | Analyst | Action / Note |",
            "| :--- | :--- | :--- |",
        ])

        for note in case.timeline:
            lines.append(f"| {note.timestamp} | `{note.analyst}` | {note.message} |")

        return "\n".join(lines)

    def _row_to_case(self, row: sqlite3.Row) -> SocCase:
        """Convert a SQLite row to a SocCase model."""
        timeline_raw = json.loads(row["timeline_json"] or "[]")
        iocs_raw = json.loads(row["iocs_json"] or "[]")

        timeline = [CaseNote(**n) for n in timeline_raw]
        iocs = [CaseIoc(**i) for i in iocs_raw]

        return SocCase(
            case_id=row["case_id"],
            title=row["title"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            status=CaseStatus(row["status"]),
            severity=CaseSeverity(row["severity"]),
            assigned_analyst=row["assigned_analyst"],
            source_scan_id=row["source_scan_id"],
            sender=row["sender"] or "",
            subject=row["subject"] or "",
            score=row["score"] or 0.0,
            summary=row["summary"] or "",
            containment_status=row["containment_status"] or "OPEN",
            timeline=timeline,
            iocs=iocs,
        )
