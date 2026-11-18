"""
Rich Terminal Interface for SOC Incident Analysis.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from phishguard.models.report import ScanResult, SeverityEnum, VerdictEnum


class TerminalReporter:
    """
    Renders enterprise SOC incident analysis dashboards to the terminal using Rich.
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render(self, result: ScanResult) -> None:
        """Render complete incident analysis dashboard."""
        self.console.print()

        # 1. Top Verdict Banner
        self._render_banner(result)

        # 2. Metadata & Risk Score Breakdown
        self._render_score_and_metadata(result)

        # 3. Received Hop Routing Tree
        self._render_hop_tree(result)

        # 4. Extracted URLs Table
        if result.urls:
            self._render_urls_table(result)

        # 5. Attachments Table
        if result.attachments:
            self._render_attachments_table(result)

        # 6. MITRE ATT&CK Framework Mapping
        if result.mitre_attack:
            self._render_mitre_table(result)

        # 7. Forensic Evidence & Remediation Playbook
        self._render_evidence_and_playbook(result)
        self.console.print()

    def _render_banner(self, result: ScanResult) -> None:
        """Render prominent color-coded verdict banner."""
        verdict = result.verdict
        severity = result.severity
        score = result.score.total_score

        if verdict == VerdictEnum.MALICIOUS:
            color = "bold red"
            badge = "🚨 MALICIOUS (PHISHING DETECTED)"
        elif verdict == VerdictEnum.SUSPICIOUS:
            color = "bold yellow"
            badge = "⚠️ SUSPICIOUS (ANOMALIES PRESENT)"
        else:
            color = "bold green"
            badge = "🛡️ CLEAN (BENIGN MESSAGE)"

        title = f"[{color}]PHISHGUARD SOC INCIDENT REPORT — {badge}[/{color}]"
        subtitle = f"Severity: [bold]{severity.value}[/bold] | PhishScore: [bold]{score}/100[/bold] | Confidence: {result.confidence_percentage}%"

        banner_content = (
            f"[bold white]{result.written_explanation.splitlines()[0]}[/bold white]\n"
            f"[dim]Scan ID: {result.scan_id} | File SHA256: {result.eml_file_hash_sha256[:16]}...[/dim]"
        )

        self.console.print(
            Panel(
                banner_content,
                title=title,
                subtitle=subtitle,
                border_style=color.split()[-1],
                padding=(1, 2),
            )
        )

    def _render_score_and_metadata(self, result: ScanResult) -> None:
        """Render side-by-side risk score breakdown and message metadata."""
        # Score Breakdown Table
        score_table = Table(title="Risk Vector Sub-scores", show_header=True, header_style="bold cyan")
        score_table.add_column("Vector", style="dim")
        score_table.add_column("Score", justify="right")
        score_table.add_column("Max", justify="right")
        score_table.add_column("Status", justify="center")

        scores = result.score
        score_table.add_row("Header & Spoofing", str(scores.header_score), "30.0", "[red]FLAGGED[/red]" if scores.header_score > 15 else "[green]OK[/green]")
        score_table.add_row("URL & Threat Intel", str(scores.url_score), "35.0", "[red]FLAGGED[/red]" if scores.url_score > 15 else "[green]OK[/green]")
        score_table.add_row("Attachment Forensics", str(scores.attachment_score), "20.0", "[red]FLAGGED[/red]" if scores.attachment_score > 5 else "[green]OK[/green]")
        score_table.add_row("Content & Urgency", str(scores.content_score), "15.0", "[yellow]FLAGGED[/yellow]" if scores.content_score > 7 else "[green]OK[/green]")
        score_table.add_section()
        score_table.add_row("[bold]Total PhishScore[/bold]", f"[bold]{scores.total_score}[/bold]", "100.0", f"[bold]{result.verdict.value}[/bold]")

        # Metadata Table
        meta = result.metadata
        auth = result.headers.auth
        meta_table = Table(title="Email Envelope & Auth", show_header=False)
        meta_table.add_column("Field", style="bold")
        meta_table.add_column("Value")

        meta_table.add_row("Subject", meta.subject)
        meta_table.add_row("From", meta.from_raw)
        meta_table.add_row("Reply-To", meta.reply_to_raw or "[dim]None[/dim]")
        meta_table.add_row("Originating IP", result.headers.originating_ip or "[dim]Unknown[/dim]")
        meta_table.add_row("Date", meta.date or "[dim]Missing[/dim]")
        meta_table.add_row(
            "Authentication",
            f"SPF: [{'green' if auth.spf_status.value == 'pass' else 'red'}]{auth.spf_status.value.upper()}[/] | "
            f"DKIM: [{'green' if auth.dkim_status.value == 'pass' else 'yellow'}]{auth.dkim_status.value.upper()}[/] | "
            f"DMARC: [{'green' if auth.dmarc_status.value == 'pass' else 'red'}]{auth.dmarc_status.value.upper()}[/]"
        )

        self.console.print(score_table)
        self.console.print(meta_table)

    def _render_hop_tree(self, result: ScanResult) -> None:
        """Render Received hops as a chronological tree."""
        hops = result.headers.hops
        if not hops:
            return

        tree = Tree("[bold cyan]Chronological Routing Chain (Origin ➔ Recipient MX)[/bold cyan]")
        for hop in hops:
            delay_str = f" (+{hop.delay_from_previous_seconds}s)" if hop.delay_from_previous_seconds is not None else ""
            ip_str = f"[bold yellow]{hop.client_ip}[/bold yellow]" if hop.client_ip else "[dim]No IP[/dim]"
            scope = "[dim](Private/Internal)[/dim]" if hop.is_private_ip else "[red](Public Egress)[/red]"
            node_label = f"Hop #{hop.hop_index}: from {hop.from_host or 'unknown'} by {hop.by_host or 'unknown'} [{ip_str} {scope}]{delay_str}"
            tree.add(node_label)

        self.console.print(tree)

    def _render_urls_table(self, result: ScanResult) -> None:
        """Render table of extracted URLs and threat status."""
        table = Table(title="Extracted URLs & Threat Intel", show_header=True, header_style="bold magenta")
        table.add_column("Defanged URL", style="cyan", no_wrap=False, max_width=50)
        table.add_column("Anchor Text", style="dim", max_width=25)
        table.add_column("Deception", justify="center")
        table.add_column("Threat Intel", justify="center")
        table.add_column("Risk", justify="right")

        for u in result.urls:
            deception = "[bold red]MISMATCH[/bold red]" if u.is_mismatched_anchor else ("[yellow]IP HOST[/yellow]" if u.is_ip_host else "Normal")
            intel = f"[bold red]{u.threat_intel_source}[/bold red]" if u.threat_intel_flagged else "[green]CLEAN[/green]"
            table.add_row(u.defanged_url, u.anchor_text or "-", deception, intel, f"{u.risk_score}")

        self.console.print(table)

    def _render_attachments_table(self, result: ScanResult) -> None:
        """Render attachments table."""
        table = Table(title="Extracted Attachments Forensics", show_header=True, header_style="bold yellow")
        table.add_column("Filename", style="bold")
        table.add_column("Size", justify="right")
        table.add_column("Declared MIME", style="dim")
        table.add_column("True Type", style="cyan")
        table.add_column("Flags", style="red")

        for att in result.attachments:
            flags = []
            if att.is_executable:
                flags.append("EXECUTABLE")
            if att.is_double_extension:
                flags.append("DOUBLE_EXT")
            if att.has_macros:
                flags.append("VBA_MACRO")
            if att.archive_contents:
                flags.append(f"ARCHIVE({len(att.archive_contents)})")

            table.add_row(
                att.filename,
                f"{att.size_bytes} B",
                att.original_mime,
                att.detected_mime or "Unknown",
                ", ".join(flags) if flags else "[green]None[/green]",
            )

        self.console.print(table)

    def _render_mitre_table(self, result: ScanResult) -> None:
        """Render MITRE ATT&CK techniques table."""
        table = Table(title="MITRE ATT&CK Framework Mapping", show_header=True, header_style="bold red")
        table.add_column("Technique ID", style="bold red")
        table.add_column("Name", style="bold")
        table.add_column("Tactic", style="dim")
        table.add_column("Evidence Summary")

        for t in result.mitre_attack:
            evidence_summary = ", ".join(t.evidence[:2])
            table.add_row(t.technique_id, t.technique_name, t.tactic, evidence_summary)

        self.console.print(table)

    def _render_evidence_and_playbook(self, result: ScanResult) -> None:
        """Render key findings and SOC containment playbook."""
        if result.key_findings:
            evidence_panel = Panel(
                "\n".join([f"• [bold red]{f}[/bold red]" for f in result.key_findings]),
                title="[bold red]Forensic Indicators & Evidence Summary[/bold red]",
                border_style="red",
            )
            self.console.print(evidence_panel)

        if result.remediation_steps:
            playbook_panel = Panel(
                "\n".join([f"[cyan]{step}[/cyan]" for step in result.remediation_steps]),
                title="[bold green]SOC Analyst Triage & Containment Playbook[/bold green]",
                border_style="green",
            )
            self.console.print(playbook_panel)
