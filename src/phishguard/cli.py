"""
PhishGuard SOC CLI - Professional Security Operations Command Line Interface.
"""

import asyncio
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Optional
import uuid

from rich.console import Console
from rich.table import Table
import typer

from phishguard import __version__
from phishguard.engine.mitre import MitreAttackMapper
from phishguard.engine.narrative import NarrativeGenerator
from phishguard.engine.scorer import ScoringEngine
from phishguard.forensics.attachments import AttachmentForensicsEngine
from phishguard.forensics.auth import AuthResultsParser
from phishguard.forensics.headers import HeaderForensicsEngine
from phishguard.forensics.iocs import IOCExporter, IOCExtractor
from phishguard.forensics.quishing import QuishingDetector
from phishguard.forensics.spoofing import SpoofingDetector
from phishguard.forensics.urls import UrlAnalyzer
from phishguard.generator.sample_generator import SampleGenerator
from phishguard.intel.pipeline import ThreatIntelPipeline
from phishguard.models.forensics import HeaderAnalysis
from phishguard.models.report import ScanResult, VerdictEnum
from phishguard.parser.eml_parser import EmlParser, ParsedEmail
from phishguard.reporters.html_reporter import HtmlReporter
from phishguard.reporters.json_reporter import JsonReporter
from phishguard.reporters.terminal import TerminalReporter
from phishguard.watcher.imap_watcher import ImapMailboxWatcher

app = typer.Typer(
    name="phishguard",
    help="Enterprise-grade Automated Phishing Detection & Threat Intelligence Tool.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


async def _run_analysis(
    parsed: ParsedEmail,
    offline: bool = False,
    vt_key: Optional[str] = None,
    otx_key: Optional[str] = None,
) -> ScanResult:
    """Core analysis orchestrator pipeline."""
    # 1. Header & Routing Forensics
    header_engine = HeaderForensicsEngine()
    hops, orig_ip, h_anomalies, h_score = header_engine.analyze_headers(parsed)

    # 2. Authentication & Spoofing
    auth_parser = AuthResultsParser()
    auth = auth_parser.parse(parsed.auth_results_headers)

    spoof_detector = SpoofingDetector()
    disp_spoof, reply_mismatch, puny, homo, target, s_anomalies, s_score = spoof_detector.analyze(parsed.metadata)

    anomalies = list(h_anomalies) + list(s_anomalies)
    header_analysis = HeaderAnalysis(
        hops=hops,
        originating_ip=orig_ip,
        auth=auth,
        display_name_spoof=disp_spoof,
        reply_to_mismatch=reply_mismatch,
        lookalike_domain=bool(target),
        lookalike_target=target,
        punycode_detected=puny,
        homoglyph_detected=homo,
        anomalies=anomalies,
        risk_score=min(30.0, h_score + s_score),
    )

    # 3. URL Extraction & Threat Intel
    url_analyzer = UrlAnalyzer()
    raw_urls = url_analyzer.extract_and_analyze(parsed.plain_body, parsed.html_body)

    intel_pipeline = ThreatIntelPipeline(vt_key=vt_key, otx_key=otx_key)
    enriched_urls = await intel_pipeline.enrich_all(raw_urls, offline=offline)

    # 4. Attachment Forensics & VT Enrichment
    attachment_engine = AttachmentForensicsEngine()
    raw_attachments = [attachment_engine.inspect_attachment(att) for att in parsed.attachments]
    analyzed_attachments = await intel_pipeline.enrich_all_attachments(raw_attachments, offline=offline)

    # 5. Quishing Analysis
    quishing_detector = QuishingDetector()
    quishing_result = quishing_detector.analyze(parsed)

    # 6. Multi-Vector Scoring
    scoring_engine = ScoringEngine()
    scores, verdict, severity, confidence, key_findings = scoring_engine.calculate(
        headers=header_analysis,
        urls=enriched_urls,
        attachments=analyzed_attachments,
        quishing=quishing_result,
        plain_body=parsed.plain_body,
        subject=parsed.metadata.subject,
    )

    # 7. MITRE ATT&CK Framework Mapping
    mitre_mapper = MitreAttackMapper()
    mitre_techniques = mitre_mapper.map_attack(
        headers=header_analysis,
        urls=enriched_urls,
        attachments=analyzed_attachments,
        quishing=quishing_result,
        scores=scores,
    )

    # 8. Narrative & Remediation
    narrative_gen = NarrativeGenerator()
    written_explanation, remediation_steps = narrative_gen.generate(
        verdict=verdict,
        severity=severity,
        scores=scores,
        key_findings=key_findings,
        from_email=parsed.metadata.from_email,
        originating_ip=orig_ip,
    )

    scan_id = f"PG-{uuid.uuid4().hex[:8].upper()}"

    return ScanResult(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc),
        eml_file_path=parsed.file_path,
        eml_file_hash_sha256=parsed.file_sha256,
        metadata=parsed.metadata,
        headers=header_analysis,
        urls=enriched_urls,
        attachments=analyzed_attachments,
        quishing=quishing_result,
        score=scores,
        verdict=verdict,
        severity=severity,
        confidence_percentage=confidence,
        key_findings=key_findings,
        mitre_attack=mitre_techniques,
        written_explanation=written_explanation,
        remediation_steps=remediation_steps,
    )


@app.command(name="scan")
def scan(
    eml_path: Path = typer.Argument(..., help="Path to the target .eml email file to analyze"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw SIEM-compatible JSON to console"),
    json_file: Optional[Path] = typer.Option(None, "--json-out", help="Write SIEM JSON report to file"),
    html_file: Optional[Path] = typer.Option(None, "--html", "-H", help="Generate standalone HTML incident report"),
    offline: bool = typer.Option(False, "--offline", help="Run without external threat intelligence lookups"),
    vt_key: Optional[str] = typer.Option(None, "--vt-key", help="VirusTotal API Key"),
    otx_key: Optional[str] = typer.Option(None, "--otx-key", help="AlienVault OTX API Key"),
):
    """Ingest and forensically analyze a single .eml email file."""
    if not eml_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {eml_path}")
        raise typer.Exit(code=1)

    parser = EmlParser()
    parsed = parser.parse_file(eml_path)

    result = asyncio.run(_run_analysis(parsed, offline=offline, vt_key=vt_key, otx_key=otx_key))

    # Exports
    if json_file:
        JsonReporter().export(result, output_path=json_file)
        console.print(f"[green]✓[/green] SIEM JSON report written to: [bold]{json_file}[/bold]")

    if html_file:
        HtmlReporter().generate(result, output_path=html_file)
        console.print(f"[green]✓[/green] Standalone HTML incident report written to: [bold]{html_file}[/bold]")

    if json_output:
        console.print(JsonReporter().export(result))
    elif not json_file and not html_file:
        TerminalReporter(console=console).render(result)
    elif not json_output:
        TerminalReporter(console=console).render(result)


@app.command(name="export-iocs")
def export_iocs(
    eml_path: Path = typer.Argument(..., help="Path to target .eml email file"),
    format_type: str = typer.Option("csv", "--format", "-f", help="Export format: csv, json, or stix"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="File to write exported IOCs"),
    offline: bool = typer.Option(False, "--offline", help="Run without external threat intelligence lookups"),
):
    """Extract and export Indicators of Compromise (IOCs) in CSV, JSON, or STIX 2.1 format."""
    if not eml_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {eml_path}")
        raise typer.Exit(code=1)

    parser = EmlParser()
    parsed = parser.parse_file(eml_path)
    result = asyncio.run(_run_analysis(parsed, offline=offline))

    extractor = IOCExtractor()
    exporter = IOCExporter()
    bundle = extractor.extract(result)

    fmt = format_type.lower().strip()
    if fmt == "csv":
        content = exporter.to_csv(bundle, output_path=output_file)
    elif fmt == "json":
        content = exporter.to_json(bundle, output_path=output_file)
    elif fmt in ("stix", "stix2", "stix21"):
        content = exporter.to_stix21(bundle, output_path=output_file)
    else:
        console.print(f"[bold red]Error:[/bold red] Unsupported format '{format_type}'. Choose csv, json, or stix.")
        raise typer.Exit(code=1)

    if output_file:
        console.print(f"[green]✓[/green] Exported {bundle.total_iocs} IOCs ({fmt.upper()}) to [bold]{output_file}[/bold]")
    else:
        console.print(content, markup=False)


@app.command(name="serve")
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host address"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port number"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload on changes"),
):
    """Start the interactive local SOC Web Dashboard and REST API."""
    import uvicorn
    console.print(f"[bold cyan]PhishGuard SOC Server[/bold cyan] listening at [bold green]http://{host}:{port}[/bold green]")
    console.print(f"  • Interactive Web Console: [link]http://{host}:{port}[/link]")
    console.print(f"  • OpenAPI / Swagger Docs:  [link]http://{host}:{port}/docs[/link]")
    uvicorn.run("phishguard.server.app:app", host=host, port=port, reload=reload)


@app.command(name="generate-sample")
def generate_sample(
    lure: str = typer.Option("credential-harvest", "--lure", "-l", help="Lure type: credential-harvest, bec, quishing, macro-invoice, benign"),
    recipient: str = typer.Option("target@company.com", "--recipient", "-r", help="Target email address"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="File path to save .eml sample"),
):
    """Synthesize high-fidelity phishing and benign test .eml emails for detection engineering."""
    generator = SampleGenerator()
    content = generator.generate(lure_type=lure, recipient=recipient, output_path=output)
    if output:
        console.print(f"[green]✓[/green] Generated synthetic [bold]{lure}[/bold] email at: [yellow]{output}[/yellow]")
    else:
        console.print(content, markup=False)


@app.command(name="watch")
def watch(
    server: str = typer.Option("imap.example.com", "--server", "-s", help="IMAP server hostname"),
    port: int = typer.Option(993, "--port", "-p", help="IMAP port"),
    user: str = typer.Option("abuse@company.com", "--user", "-u", help="Mailbox username"),
    password: str = typer.Option(..., "--password", "-P", envvar="IMAP_PASSWORD", help="Mailbox password or env IMAP_PASSWORD"),
    folder: str = typer.Option("INBOX", "--folder", "-f", help="Source folder to monitor"),
    quarantine: str = typer.Option("Quarantine", "--quarantine", "-q", help="Destination quarantine folder"),
    alert_dir: Optional[Path] = typer.Option(None, "--alert-dir", "-a", help="Directory to save JSON alerts"),
    interval: int = typer.Option(60, "--interval", "-i", help="Poll interval in seconds"),
    once: bool = typer.Option(False, "--once", help="Poll once and exit"),
    offline: bool = typer.Option(False, "--offline", help="Run without external API queries"),
):
    """Continuously monitor an IMAP abuse inbox, triage incoming emails, and quarantine threats."""
    import time
    console.print(f"[bold cyan]PhishGuard Watcher[/bold cyan] monitoring [yellow]{user}@{server}:{folder}[/yellow]")
    watcher = ImapMailboxWatcher(
        host=server, port=port, user=user, password=password,
        source_folder=folder, quarantine_folder=quarantine, alert_dir=alert_dir
    )

    def analyze_raw(raw_bytes: bytes) -> ScanResult:
        p = EmlParser()
        parsed = p.parse_bytes(raw_bytes)
        return asyncio.run(_run_analysis(parsed, offline=offline))

    if once:
        results = watcher.poll_once(analyze_raw)
        console.print(f"[green]✓[/green] Processed {len(results)} incoming emails. (Quarantined: {watcher.stats.quarantined_count})")
        return

    console.print(f"[green]✓[/green] Mailbox listener active. Polling every {interval}s... Press Ctrl+C to stop.")
    try:
        while True:
            watcher.poll_once(analyze_raw)
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Watcher terminated by analyst.[/yellow]")


@app.command(name="scan-dir")
def scan_dir(
    directory: Path = typer.Argument(..., help="Directory containing .eml files to batch analyze"),
    offline: bool = typer.Option(False, "--offline", help="Run without external threat intelligence lookups"),
):
    """Batch scan an entire directory of .eml email files."""
    if not directory.is_dir():
        console.print(f"[bold red]Error:[/bold red] Directory not found: {directory}")
        raise typer.Exit(code=1)

    eml_files = list(directory.glob("*.eml"))
    if not eml_files:
        console.print(f"[yellow]No .eml files found in {directory}[/yellow]")
        return

    console.print(f"[bold cyan]PhishGuard SOC[/bold cyan] Batch scanning {len(eml_files)} files...\n")
    parser = EmlParser()

    table = Table(title="Batch Scan Summary", show_header=True, header_style="bold cyan")
    table.add_column("Filename", style="bold")
    table.add_column("From Address", style="dim")
    table.add_column("Subject", max_width=40)
    table.add_column("Score", justify="right")
    table.add_column("Verdict", justify="center")

    for file_path in eml_files:
        try:
            parsed = parser.parse_file(file_path)
            res = asyncio.run(_run_analysis(parsed, offline=offline))

            verdict_color = "red" if res.verdict == VerdictEnum.MALICIOUS else ("yellow" if res.verdict == VerdictEnum.SUSPICIOUS else "green")
            table.add_row(
                file_path.name,
                res.metadata.from_email or "-",
                res.metadata.subject,
                f"{res.score.total_score}",
                f"[{verdict_color}]{res.verdict.value}[/{verdict_color}]",
            )
        except Exception as e:
            table.add_row(file_path.name, "-", f"[red]Error: {e}[/red]", "-", "[red]FAILED[/red]")

    console.print(table)


@app.command(name="version")
def version():
    """Display PhishGuard version information."""
    console.print(f"[bold cyan]PhishGuard SOC Engine[/bold cyan] v{__version__}")


def main():
    app()


if __name__ == "__main__":
    main()
