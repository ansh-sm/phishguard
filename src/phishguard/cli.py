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
from phishguard.ai import AiTriageEngine, AiTriageResult, EmailIntentEnum
from phishguard.alerts import AlertConfig, AlertDispatcher, AlertWebhookType
from phishguard.cases import CaseManager, CaseSeverity, CaseStatus, SocCase
from phishguard.engine.mitre import MitreAttackMapper
from phishguard.engine.narrative import NarrativeGenerator
from phishguard.engine.scorer import ScoringEngine
from phishguard.forensics.attachments import AttachmentForensicsEngine
from phishguard.forensics.auth import AuthResultsParser
from phishguard.forensics.dns_validator import DnsPolicyValidator, DomainDnsInspection
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
from phishguard.rules.engine import RuleEngine
from phishguard.sandbox import UrlDetonator, UrlDetonationResult, DetonationVerdict
from phishguard.hunting import AttackGraphBuilder, CampaignClusterer, ThreatCampaign, AttackGraph
from phishguard.siem import SiemConfig, SiemForwarder, SiemTargetType, SiemForwardResult
from phishguard.soar.generator import RemediationEngine
from phishguard.soar.models import PlatformType
from phishguard.storage.database import IncidentDatabase
from phishguard.storage.models import IncidentQueryFilter
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
    rules_dir: Optional[str] = None,
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

    # 5.5 Custom Detection Rules Evaluation
    matched_rules = []
    target_dir = rules_dir or ("rules" if Path("rules").is_dir() else None)
    if target_dir and Path(target_dir).is_dir():
        rule_engine = RuleEngine.from_directory(target_dir)
        matched_rules = rule_engine.evaluate_all(
            parsed=parsed,
            headers=header_analysis,
            urls=enriched_urls,
            attachments=analyzed_attachments,
            quishing=quishing_result,
        )

    # 6. Multi-Vector Scoring
    scoring_engine = ScoringEngine()
    scores, verdict, severity, confidence, key_findings = scoring_engine.calculate(
        headers=header_analysis,
        urls=enriched_urls,
        attachments=analyzed_attachments,
        quishing=quishing_result,
        plain_body=parsed.plain_body,
        subject=parsed.metadata.subject,
        matched_rules=matched_rules,
    )

    # 7. MITRE ATT&CK Framework Mapping
    mitre_mapper = MitreAttackMapper()
    mitre_techniques = mitre_mapper.map_attack(
        headers=header_analysis,
        urls=enriched_urls,
        attachments=analyzed_attachments,
        quishing=quishing_result,
        scores=scores,
        matched_rules=matched_rules,
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

    scan_res = ScanResult(
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
        matched_rules=matched_rules,
        mitre_attack=mitre_techniques,
        written_explanation=written_explanation,
        remediation_steps=remediation_steps,
    )

    try:
        IncidentDatabase().save_scan(scan_res)
    except Exception:
        pass

    return scan_res


@app.command(name="scan")
def scan(
    eml_path: Path = typer.Argument(..., help="Path to the target .eml email file to analyze"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw SIEM-compatible JSON to console"),
    json_file: Optional[Path] = typer.Option(None, "--json-out", help="Write SIEM JSON report to file"),
    html_file: Optional[Path] = typer.Option(None, "--html", "-H", help="Generate standalone HTML incident report"),
    offline: bool = typer.Option(False, "--offline", help="Run without external threat intelligence lookups"),
    vt_key: Optional[str] = typer.Option(None, "--vt-key", help="VirusTotal API Key"),
    otx_key: Optional[str] = typer.Option(None, "--otx-key", help="AlienVault OTX API Key"),
    rules_dir: Optional[str] = typer.Option("rules", "--rules-dir", "-r", help="Directory containing custom YAML detection rules"),
    webhook_url: Optional[str] = typer.Option(None, "--webhook-url", help="Webhook URL for real-time SOC alerts"),
    webhook_type: str = typer.Option("generic", "--webhook-type", help="Webhook adapter: slack, discord, teams, generic"),
    min_score: float = typer.Option(60.0, "--min-score", help="Minimum PhishScore to trigger outbound alert (0-100)"),
):
    """Ingest and forensically analyze a single .eml email file."""
    if not eml_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {eml_path}")
        raise typer.Exit(code=1)

    parser = EmlParser()
    parsed = parser.parse_file(eml_path)

    result = asyncio.run(_run_analysis(parsed, offline=offline, vt_key=vt_key, otx_key=otx_key, rules_dir=rules_dir))

    # Exports
    if json_file:
        JsonReporter().export(result, output_path=json_file)
        console.print(f"[green]✓[/green] SIEM JSON report written to: [bold]{json_file}[/bold]")

    if html_file:
        HtmlReporter().generate(result, output_path=html_file)
        console.print(f"[green]✓[/green] Standalone HTML incident report written to: [bold]{html_file}[/bold]")

    if webhook_url:
        alert_config = AlertConfig(
            webhook_url=webhook_url,
            webhook_type=AlertWebhookType(webhook_type.lower()),
            min_score=min_score,
        )
        dispatcher = AlertDispatcher(alert_config)
        dispatched = asyncio.run(dispatcher.send_alert(result))
        if dispatched:
            console.print(f"[bold green]✓ Alert successfully dispatched to {webhook_type.upper()} webhook.[/bold green]")
        else:
            console.print(f"[dim]Alert not dispatched (Score {result.score.total_score} below threshold {min_score} or endpoint unreachable).[/dim]")

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
    rules_dir: Optional[str] = typer.Option("rules", "--rules-dir", "-r", help="Directory containing custom YAML rules"),
    webhook_url: Optional[str] = typer.Option(None, "--webhook-url", help="Webhook URL for automated alert dispatch"),
    webhook_type: str = typer.Option("generic", "--webhook-type", help="Webhook adapter: slack, discord, teams, generic"),
    min_score: float = typer.Option(60.0, "--min-score", help="Minimum score to trigger outbound alert"),
):
    """Continuously monitor an IMAP abuse inbox, triage incoming emails, and quarantine threats."""
    import time
    console.print(f"[bold cyan]PhishGuard Watcher[/bold cyan] monitoring [yellow]{user}@{server}:{folder}[/yellow]")
    watcher = ImapMailboxWatcher(
        host=server, port=port, user=user, password=password,
        source_folder=folder, quarantine_folder=quarantine, alert_dir=alert_dir
    )

    alert_dispatcher = None
    if webhook_url:
        alert_config = AlertConfig(
            webhook_url=webhook_url,
            webhook_type=AlertWebhookType(webhook_type.lower()),
            min_score=min_score,
        )
        alert_dispatcher = AlertDispatcher(alert_config)

    def analyze_raw(raw_bytes: bytes) -> ScanResult:
        p = EmlParser()
        parsed = p.parse_bytes(raw_bytes)
        res = asyncio.run(_run_analysis(parsed, offline=offline, rules_dir=rules_dir))
        if alert_dispatcher and alert_dispatcher.should_alert(res):
            asyncio.run(alert_dispatcher.send_alert(res))
        return res

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


@app.command(name="test-rules")
def test_rules(
    rules_dir: Path = typer.Option(Path("rules"), "--rules-dir", "-r", help="Directory containing custom YAML rules"),
    samples_dir: Path = typer.Option(Path("samples"), "--samples-dir", "-s", help="Directory containing sample .eml files"),
):
    """Evaluate and validate custom YAML detection rules across a corpus of sample emails."""
    if not rules_dir.is_dir():
        console.print(f"[bold red]Error:[/bold red] Rules directory not found: {rules_dir}")
        raise typer.Exit(code=1)

    rule_engine = RuleEngine.from_directory(rules_dir)
    console.print(f"[bold cyan]Loaded {len(rule_engine.rules)} detection rules from [yellow]{rules_dir}[/yellow][/bold cyan]\n")

    if not samples_dir.is_dir():
        console.print(f"[bold red]Error:[/bold red] Samples directory not found: {samples_dir}")
        raise typer.Exit(code=1)

    sample_files = list(samples_dir.glob("*.eml"))
    if not sample_files:
        console.print(f"[yellow]No .eml samples found in {samples_dir}[/yellow]")
        return

    parser = EmlParser()
    table = Table(title="Rule Evaluation Detection Matrix", show_header=True, header_style="bold blue")
    table.add_column("Sample EML File", style="bold")
    table.add_column("Verdict", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Triggered Rules", style="cyan")

    for sf in sample_files:
        parsed = parser.parse_file(sf)
        res = asyncio.run(_run_analysis(parsed, offline=True, rules_dir=str(rules_dir)))
        rule_tags = ", ".join([f"{r.rule_id} ({r.severity})" for r in res.matched_rules]) or "[dim]None[/dim]"
        v_color = "red" if res.verdict == VerdictEnum.MALICIOUS else ("yellow" if res.verdict == VerdictEnum.SUSPICIOUS else "green")
        table.add_row(
            sf.name,
            f"[{v_color}]{res.verdict.value}[/{v_color}]",
            f"{res.score.total_score}",
            rule_tags,
        )

    console.print(table)


@app.command(name="alert-test")
def alert_test(
    webhook_url: str = typer.Option(..., "--webhook-url", "-w", help="Target webhook endpoint URL"),
    webhook_type: str = typer.Option("generic", "--webhook-type", "-t", help="Webhook adapter: slack, discord, teams, generic"),
    secret: Optional[str] = typer.Option(None, "--secret", help="HMAC secret for generic webhooks"),
):
    """Dispatch a simulated high-fidelity incident alert to verify webhook integration."""
    from phishguard.models.email import AuthenticationResults, AuthStatus, EmailMetadata
    from phishguard.models.forensics import HeaderAnalysis, UrlArtifact
    from phishguard.models.report import MitreTechnique, RuleMatch, ScoreBreakdown, SeverityEnum, VerdictEnum

    console.print(f"[bold cyan]Dispatching simulated incident alert to [yellow]{webhook_url}[/yellow] (Adapter: {webhook_type})...[/bold cyan]")

    simulated_result = ScanResult(
        scan_id="PG-TEST-SIM01",
        timestamp=datetime.now(timezone.utc),
        eml_file_path="simulated_phish.eml",
        eml_file_hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        metadata=EmailMetadata(
            subject="CRITICAL: Unauthorized Login Attempt Detected",
            from_address="security@paypal-verification-alert.com",
            from_name="PayPal Security Team",
            from_raw='"PayPal Security Team" <security@paypal-verification-alert.com>',
            to_addresses=["analyst@enterprise.com"],
            date="Sun, 22 Nov 2026 08:00:00 +0000",
        ),
        headers=HeaderAnalysis(
            hops=[],
            originating_ip="198.51.100.45",
            auth=AuthenticationResults(spf_status=AuthStatus.FAIL, dkim_status=AuthStatus.FAIL, dmarc_status=AuthStatus.FAIL),
            risk_score=30.0,
        ),
        urls=[
            UrlArtifact(
                raw_url="http://paypal-verification-alert.com/login",
                defanged_url="hxxp://paypal-verification-alert[.]com/login",
                domain="paypal-verification-alert.com",
                threat_intel_flagged=True,
                threat_intel_source="URLhaus",
                risk_score=35.0,
            )
        ],
        score=ScoreBreakdown(header_score=30.0, url_score=35.0, attachment_score=0.0, content_score=15.0, total_score=92.0),
        verdict=VerdictEnum.MALICIOUS,
        severity=SeverityEnum.CRITICAL,
        confidence_percentage=99.0,
        key_findings=[
            "High urgency credential harvesting threat detected.",
            "DMARC and SPF authentication failed for sender domain.",
            "Known malicious domain flagged in threat intelligence feed.",
        ],
        matched_rules=[
            RuleMatch(
                rule_id="PG-RULE-001",
                rule_name="Urgent Credential Harvesting Lure",
                severity="HIGH",
                score_impact=20.0,
                description="Urgent account suspension threat with embedded action link.",
            )
        ],
        mitre_attack=[
            MitreTechnique(
                technique_id="T1566.002",
                technique_name="Spearphishing Link",
                tactic="Initial Access",
                description="Adversary delivers spearphishing link.",
                evidence=["Malicious credential harvest link detected."],
                attack_url="https://attack.mitre.org/techniques/T1566/002/",
            )
        ],
        written_explanation="SIMULATED INCIDENT: Critical credential harvesting phishing attack targeting organization credentials.",
        remediation_steps=[
            "Block originating IP 198.51.100.45 on perimeter firewalls.",
            "Null-route paypal-verification-alert.com in enterprise DNS sinkhole.",
            "Purge message matching subject from all Exchange/M365 mailboxes.",
        ],
    )

    alert_config = AlertConfig(
        webhook_url=webhook_url,
        webhook_type=AlertWebhookType(webhook_type.lower()),
        min_score=0.0,
        hmac_secret=secret,
    )
    dispatcher = AlertDispatcher(alert_config)
    success = asyncio.run(dispatcher.send_alert(simulated_result))

    if success:
        console.print("[bold green]✓ Test alert delivered successfully![/bold green]")
    else:
        console.print("[bold red]✗ Failed to deliver test alert. Check webhook URL and network connectivity.[/bold red]")


@app.command(name="scan-dir")
def scan_dir(
    directory: Path = typer.Argument(..., help="Directory containing .eml files to batch analyze"),
    offline: bool = typer.Option(False, "--offline", help="Run without external threat intelligence lookups"),
    rules_dir: Optional[str] = typer.Option("rules", "--rules-dir", "-r", help="Directory containing custom YAML rules"),
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
            res = asyncio.run(_run_analysis(parsed, offline=offline, rules_dir=rules_dir))

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


@app.command(name="remediate")
def remediate(
    target: str = typer.Argument(..., help="Path to .eml file OR historical Scan ID (e.g. PG-A1B2C3D4)"),
    platform: str = typer.Option("all", "--platform", "-p", help="Target platform: m365, google, edr, firewall, all"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Directory to save generated playbook scripts"),
    offline: bool = typer.Option(False, "--offline", help="Run without external threat intelligence lookups"),
):
    """Generate automated SOAR remediation scripts (M365, Google Workspace, EDR, Firewalls)."""
    db = IncidentDatabase()
    result: Optional[ScanResult] = None

    # Check if target is a Scan ID
    if target.startswith("PG-") and not Path(target).exists():
        result = db.get_scan(target)
        if not result:
            console.print(f"[bold red]Error:[/bold red] Scan ID not found in SOC database: {target}")
            raise typer.Exit(code=1)
    else:
        eml_path = Path(target)
        if not eml_path.exists():
            console.print(f"[bold red]Error:[/bold red] Target file not found: {target}")
            raise typer.Exit(code=1)
        parser = EmlParser()
        parsed = parser.parse_file(eml_path)
        result = asyncio.run(_run_analysis(parsed, offline=offline))

    engine = RemediationEngine()
    plat_enum = PlatformType(platform.lower())
    package = engine.generate_package(result, platforms=[plat_enum])

    console.print(f"\n[bold cyan]🛡️ PHISHGUARD SOAR INCIDENT REMEDIATION PACKAGE[/bold cyan]")
    console.print(f"[bold]Scan ID:[/bold] {package.scan_id} | [bold]Verdict:[/bold] {package.verdict} | [bold]Target:[/bold] {package.target_subject}")
    console.print(f"[bold]Attacker Sender:[/bold] {package.sender_email} | [bold]Originating IP:[/bold] {package.originating_ip or 'Unknown'}\n")

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    from rich.syntax import Syntax
    for action in package.actions:
        console.print(f"[bold yellow]▶ {action.name}[/bold yellow] ([cyan]{action.platform.value.upper()}[/cyan] | [dim]{action.category}[/dim])")
        console.print(f"[dim]{action.description}[/dim]")

        syntax = Syntax(action.code, action.language, theme="monokai", line_numbers=True)
        console.print(syntax)
        console.print()

        if output_dir:
            clean_name = action.name.lower().replace(" ", "_").replace("/", "_").replace("(", "").replace(")", "")
            ext = "ps1" if action.language == "powershell" else ("sh" if action.language == "bash" else ("kql" if action.language == "kql" else "txt"))
            file_out = output_dir / f"{clean_name}.{ext}"
            file_out.write_text(action.code, encoding="utf-8")

    if output_dir:
        console.print(f"[bold green]✓ Saved {len(package.actions)} remediation scripts to: [yellow]{output_dir}[/yellow][/bold green]")


@app.command(name="hunt")
def hunt(
    query: Optional[str] = typer.Option(None, "--query", "-q", help="Free-text search in subject, sender, or content"),
    ip: Optional[str] = typer.Option(None, "--ip", help="Originating IP address"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Sender or URL domain"),
    hash_val: Optional[str] = typer.Option(None, "--hash", help="SHA256 hash of attachment or file"),
    technique: Optional[str] = typer.Option(None, "--technique", "-t", help="MITRE ATT&CK technique ID (e.g. T1566.002)"),
    verdict: Optional[str] = typer.Option(None, "--verdict", "-v", help="Verdict filter: MALICIOUS, SUSPICIOUS, CLEAN"),
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum records to return"),
    stats: bool = typer.Option(False, "--stats", help="Display overall threat telemetry statistics"),
):
    """Threat hunt across historical triage records and query past incidents."""
    db = IncidentDatabase()

    if stats:
        stat_data = db.get_stats()
        console.print("\n[bold cyan]📊 PhishGuard SOC Threat Telemetry Statistics[/bold cyan]")
        console.print(f"Total Scans Ingested: [bold]{stat_data['total_scans']}[/bold]")

        vb = stat_data["verdict_breakdown"]
        console.print(f"• [red]Malicious:[/red] {vb['malicious']}  |  [yellow]Suspicious:[/yellow] {vb['suspicious']}  |  [green]Clean:[/green] {vb['clean']}\n")

        if stat_data["top_attacker_ips"]:
            ip_table = Table(title="Top Attacker Originating IPs", show_header=True, header_style="bold magenta")
            ip_table.add_column("Originating IP", style="bold red")
            ip_table.add_column("Incidents", justify="right")
            for item in stat_data["top_attacker_ips"]:
                ip_table.add_row(item["ip"], str(item["count"]))
            console.print(ip_table)

        if stat_data["top_sender_domains"]:
            dom_table = Table(title="Top Adversary Sender Domains", show_header=True, header_style="bold yellow")
            dom_table.add_column("Sender Domain", style="bold yellow")
            dom_table.add_column("Incidents", justify="right")
            for item in stat_data["top_sender_domains"]:
                dom_table.add_row(item["domain"], str(item["count"]))
            console.print(dom_table)
        return

    filter_obj = IncidentQueryFilter(
        query=query,
        ip=ip,
        domain=domain,
        hash_val=hash_val,
        technique=technique,
        verdict=verdict,
        limit=limit,
    )
    results = db.search_incidents(filter_obj)

    if not results:
        console.print("[yellow]No historical incidents matching query criteria.[/yellow]")
        return

    console.print(f"\n[bold cyan]Found {len(results)} historical incidents matching hunt parameters:[/bold cyan]\n")
    table = Table(title="SOC Threat Hunting Results", show_header=True, header_style="bold cyan")
    table.add_column("Scan ID", style="bold cyan")
    table.add_column("Timestamp", style="dim", max_width=20)
    table.add_column("Sender", style="dim", max_width=25)
    table.add_column("Subject", max_width=35)
    table.add_column("Origin IP", style="yellow")
    table.add_column("Score", justify="right")
    table.add_column("Verdict", justify="center")

    for r in results:
        v_color = "red" if r.verdict == "MALICIOUS" else ("yellow" if r.verdict == "SUSPICIOUS" else "green")
        table.add_row(
            r.scan_id,
            r.timestamp[:19].replace("T", " "),
            r.from_email[:25],
            r.subject[:35],
            r.originating_ip or "-",
            f"{r.total_score}",
            f"[{v_color}]{r.verdict}[/{v_color}]",
        )

    console.print(table)


@app.command(name="forward")
def forward_event(
    file_path: Path = typer.Argument(..., help="Path to .eml file to analyze and stream to SIEM"),
    target: str = typer.Option("splunk", "--target", "-t", help="SIEM target: splunk, elastic, sentinel, webhook"),
    url: str = typer.Option(..., "--url", "-u", help="SIEM collector/ingestion endpoint URL"),
    token: Optional[str] = typer.Option(None, "--token", help="Auth token or Bearer secret"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Elasticsearch API Key"),
    index: str = typer.Option("phishguard_threats", "--index", "-i", help="Index, sourcetype, or dataset name"),
    workspace_id: Optional[str] = typer.Option(None, "--workspace-id", help="Azure Log Analytics Workspace ID"),
    workspace_key: Optional[str] = typer.Option(None, "--workspace-key", help="Azure Log Analytics Workspace Key"),
    offline: bool = typer.Option(False, "--offline", help="Run without external threat intelligence lookups"),
):
    """Stream analyzed phishing incident event directly into enterprise SIEM (Splunk, Elastic, Sentinel)."""
    if not file_path.exists():
        console.print(f"[bold red]Error:[/bold red] Email file not found: {file_path}")
        raise typer.Exit(code=1)

    console.print(f"[bold cyan]PhishGuard SOC[/bold cyan] Analyzing [yellow]{file_path.name}[/yellow] for SIEM forwarding...")
    parser = EmlParser()
    parsed = parser.parse_file(file_path)
    result = asyncio.run(_run_analysis(parsed, offline=offline))

    target_enum = SiemTargetType(target.lower())
    config = SiemConfig(
        target_type=target_enum,
        endpoint_url=url,
        auth_token=token,
        api_key=api_key,
        index_name=index,
        workspace_id=workspace_id,
        workspace_key=workspace_key,
    )

    forward_res = SiemForwarder.forward_scan_result(config, result)
    if forward_res.success:
        console.print(f"\n[bold green]✓ Successfully forwarded incident to {target.upper()}![/bold green]")
        console.print(f"  • [bold]Status Code:[/bold] {forward_res.status_code}")
        console.print(f"  • [bold]Target URL:[/bold] {url}")
        console.print(f"  • [bold]Event ID:[/bold] {result.scan_id}")
        console.print(f"  • [bold]Verdict:[/bold] {result.verdict.value} (Score {result.score.total_score})")
    else:
        console.print(f"\n[bold red]✗ Failed to forward incident to {target.upper()}:[/bold red]")
        console.print(f"  • [bold]Error:[/bold] {forward_res.error_message}")
        raise typer.Exit(code=1)


@app.command(name="forward-test")
def forward_test(
    target: str = typer.Option("splunk", "--target", "-t", help="SIEM target: splunk, elastic, sentinel, webhook"),
    url: str = typer.Option(..., "--url", "-u", help="SIEM collector/ingestion endpoint URL"),
    token: Optional[str] = typer.Option(None, "--token", help="Auth token or Bearer secret"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Elasticsearch API Key"),
    index: str = typer.Option("phishguard_threats", "--index", "-i", help="Index, sourcetype, or dataset name"),
    workspace_id: Optional[str] = typer.Option(None, "--workspace-id", help="Azure Log Analytics Workspace ID"),
    workspace_key: Optional[str] = typer.Option(None, "--workspace-key", help="Azure Log Analytics Workspace Key"),
):
    """Test connectivity, authentication, and endpoint reachability for enterprise SIEM."""
    target_enum = SiemTargetType(target.lower())
    config = SiemConfig(
        target_type=target_enum,
        endpoint_url=url,
        auth_token=token,
        api_key=api_key,
        index_name=index,
        workspace_id=workspace_id,
        workspace_key=workspace_key,
    )

    console.print(f"[bold cyan]Testing connection to {target.upper()} at [dim]{url}[/dim]...[/bold cyan]")
    test_res = SiemForwarder.test_connection(config)

    if test_res.success:
        console.print(f"[bold green]✓ Connection test PASSED (HTTP {test_res.status_code})[/bold green]")
        if test_res.response_body:
            console.print(f"[dim]Response: {test_res.response_body}[/dim]")
    else:
        console.print(f"[bold red]✗ Connection test FAILED:[/bold red] {test_res.error_message}")
        raise typer.Exit(code=1)


@app.command(name="campaign-hunt")
def campaign_hunt(
    min_size: int = typer.Option(1, "--min-size", "-m", help="Minimum incidents per campaign cluster"),
    mermaid: bool = typer.Option(False, "--mermaid", help="Render Mermaid attack topology for top campaign"),
):
    """Correlate historical incidents into persistent adversary campaigns and attack clusters."""
    db = IncidentDatabase()
    incidents = db.search_incidents(IncidentQueryFilter(limit=100))

    if not incidents:
        console.print("[yellow]No historical incidents available in database to correlate.[/yellow]")
        return

    campaigns = CampaignClusterer.cluster_incidents(incidents, min_cluster_size=min_size)

    if not campaigns:
        console.print(f"[yellow]No threat campaigns identified meeting minimum size {min_size}.[/yellow]")
        return

    console.print(f"\n[bold cyan]🎯 Identified {len(campaigns)} Active Adversary Campaigns:[/bold cyan]\n")
    table = Table(title="Correlated Threat Campaigns", show_header=True, header_style="bold cyan")
    table.add_column("Campaign ID", style="bold red")
    table.add_column("Campaign Name", style="bold white", max_width=40)
    table.add_column("Risk Score", justify="right")
    table.add_column("Incidents", justify="center")
    table.add_column("Victims", justify="center")
    table.add_column("Primary Tactics", style="dim", max_width=25)
    table.add_column("Shared IOCs", style="yellow", max_width=30)

    for c in campaigns:
        tactics_str = ", ".join(c.primary_techniques[:3]) or "Unknown"
        iocs_str = ", ".join(c.shared_iocs[:2]) or "None"
        table.add_row(
            c.campaign_id,
            c.name,
            f"{c.risk_score}",
            str(len(c.incident_ids)),
            str(c.victim_count),
            tactics_str,
            iocs_str,
        )

    console.print(table)

    if mermaid and campaigns and campaigns[0].graph:
        console.print(f"\n[bold magenta]Attack Topology (Mermaid) - {campaigns[0].name}:[/bold magenta]\n")
        console.print(campaigns[0].graph.to_mermaid())
        console.print()


@app.command(name="graph")
def generate_graph(
    file_path: Path = typer.Argument(..., help="Path to .eml file to build attack graph for"),
    format_type: str = typer.Option("mermaid", "--format", "-f", help="Output format: mermaid, json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="File to write graph definition to"),
    offline: bool = typer.Option(False, "--offline", help="Run offline analysis"),
):
    """Generate relational attack graph capturing incident delivery topology."""
    if not file_path.exists():
        console.print(f"[bold red]Error:[/bold red] Email file not found: {file_path}")
        raise typer.Exit(code=1)

    parser = EmlParser()
    parsed = parser.parse_file(file_path)
    result = asyncio.run(_run_analysis(parsed, offline=offline))

    graph = AttackGraphBuilder.build_incident_graph(result)

    if format_type.lower() == "json":
        import json
        content = json.dumps(graph.to_dict(), indent=2)
    else:
        content = graph.to_mermaid()

    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"[bold green]✓ Wrote {format_type.upper()} graph to [yellow]{output}[/yellow][/bold green]")
    else:
        console.print(content)


@app.command(name="triage-intent")
def triage_intent(
    file_path: Path = typer.Argument(..., help="Path to .eml file to analyze for phishing intent"),
    provider: str = typer.Option("offline", "--provider", "-p", help="Provider: offline or gemini"),
    summary_only: bool = typer.Option(False, "--summary", "-s", help="Output only the executive summary"),
):
    """Analyze email content for adversary intent, psychological manipulation, and urgency."""
    if not file_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
        raise typer.Exit(code=1)

    parser = EmlParser()
    parsed = parser.parse_file(file_path)
    res = AiTriageEngine.triage_email(parsed, provider=provider)

    if summary_only:
        console.print(f"\n[bold cyan]Executive Summary:[/bold cyan] {res.executive_summary}\n")
        return

    console.print(f"\n[bold cyan]🧠 AI Phishing Intent & Cognitive Triage Report[/bold cyan]")
    console.print(f"File: [yellow]{file_path.name}[/yellow] | Engine: [dim]{res.provider_used}[/dim]\n")

    intent_color = "red" if "BENIGN" not in res.primary_intent.value else "green"
    console.print(f"• [bold]Primary Intent:[/bold] [{intent_color}]{res.primary_intent.value}[/{intent_color}]")
    if res.secondary_intents:
        sec_str = ", ".join(s.value for s in res.secondary_intents)
        console.print(f"• [bold]Secondary Vectors:[/bold] [yellow]{sec_str}[/yellow]")

    urgency_bar = "█" * int(res.urgency_score * 10) + "░" * (10 - int(res.urgency_score * 10))
    console.print(f"• [bold]Urgency Index:[/bold] [yellow]{urgency_bar}[/yellow] ({res.urgency_score:.2f}/1.0)")

    if res.vip_impersonation_score > 0.0:
        console.print(f"• [bold red]VIP Impersonation Risk:[/bold red] {res.vip_impersonation_score:.2f}/1.0")

    if res.psychological_tactics:
        tactics_str = ", ".join(t.value for t in res.psychological_tactics)
        console.print(f"• [bold]Psychological Tactics:[/bold] [magenta]{tactics_str}[/magenta]")

    if res.suspicious_phrases:
        console.print(f"• [bold]Trigger Phrases:[/bold] [dim]{', '.join(res.suspicious_phrases)}[/dim]")

    if res.call_to_action:
        console.print(f"• [bold]Call-to-Action:[/bold] [bold red]{res.call_to_action}[/bold red]")

    console.print(f"\n[bold cyan]SOC Executive Assessment:[/bold cyan]")
    console.print(f"{res.executive_summary}\n")


@app.command(name="dns-check")
def dns_check(
    domain: str = typer.Argument(..., help="Domain name to verify (e.g. paypal.com, paypa1-update.com)"),
    ip: Optional[str] = typer.Option(None, "--ip", help="Originating IP address to test against SPF record"),
):
    """Perform live DNS query and audit domain SPF/DMARC spoofing resilience."""
    console.print(f"[bold cyan]PhishGuard SOC[/bold cyan] Auditing DNS authentication for [yellow]{domain}[/yellow]...\n")
    audit = DnsPolicyValidator.inspect_domain(domain, originating_ip=ip)

    table = Table(title=f"DNS Authentication Audit: {audit.domain}", show_header=True, header_style="bold cyan")
    table.add_column("Protocol", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Details", max_width=60)

    # SPF Row
    if audit.spf.has_spf:
        spf_status = "[green]AUTHORIZED[/green]" if audit.spf.ip_authorized else ("[red]UNAUTHORIZED[/red]" if ip else "[yellow]PUBLISHED[/yellow]")
        spf_det = audit.spf.raw_record or "-"
        if ip and audit.spf.mechanism_matched:
            spf_det += f" (Matched: {audit.spf.mechanism_matched})"
        table.add_row("SPF (v=spf1)", spf_status, spf_det)
    else:
        table.add_row("SPF (v=spf1)", "[red]MISSING[/red]", "No SPF TXT record published on domain")

    # DMARC Row
    if audit.dmarc.has_dmarc:
        dmarc_color = "red" if audit.dmarc.policy == "none" else "green"
        table.add_row("DMARC (v=DMARC1)", f"[{dmarc_color}]{audit.dmarc.policy.upper()}[/{dmarc_color}]", audit.dmarc.raw_record or "-")
    else:
        table.add_row("DMARC (v=DMARC1)", "[red]MISSING[/red]", f"No DMARC record at _dmarc.{domain}")

    # MX Row
    if audit.mx_records:
        table.add_row("MX Records", "[green]FOUND[/green]", ", ".join(audit.mx_records))
    else:
        table.add_row("MX Records", "[yellow]NONE[/yellow]", "No inbound mail exchangers published")

    console.print(table)

    risk_color = "red" if audit.risk_score >= 60 else ("yellow" if audit.risk_score >= 25 else "green")
    console.print(f"\n[bold]DNS Security Risk Score:[/bold] [{risk_color}]{audit.risk_score:.0f}/100[/{risk_color}]")
    if audit.risk_reasons:
        console.print("[bold red]Vulnerabilities Identified:[/bold red]")
        for reason in audit.risk_reasons:
            console.print(f"  • {reason}")
    console.print()


@app.command(name="sandbox")
def sandbox_url(
    url: str = typer.Argument(..., help="Suspicious URL to detonate inside sandbox"),
    timeout: float = typer.Option(8.0, "--timeout", help="HTTP connection timeout in seconds"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom browser User-Agent"),
    json_output: bool = typer.Option(False, "--json", help="Output detonation result in JSON"),
):
    """Detonate an untrusted URL in the sandbox, trace redirects, and analyze landing DOM."""
    console.print(f"[bold cyan]PhishGuard SOC[/bold cyan] Detonating target URL in sandbox: [yellow]{url}[/yellow]...\n")
    kwargs = {"timeout_seconds": timeout}
    if user_agent:
        kwargs["user_agent"] = user_agent
    detonator = UrlDetonator(**kwargs)
    result = detonator.detonate(url)

    if json_output:
        console.print_json(result.model_dump_json(indent=2))
        return

    verdict_color = "red" if result.verdict == DetonationVerdict.MALICIOUS else ("yellow" if result.verdict == DetonationVerdict.SUSPICIOUS else "green")
    console.print(f"[bold]Target URL:[/bold] {result.target_url}")
    console.print(f"[bold]Final URL:[/bold]  {result.final_url}")
    console.print(f"[bold]Status Code:[/bold] {result.status_code}")
    console.print(f"[bold]Verdict:[/bold]     [{verdict_color}]{result.verdict.value}[/{verdict_color}]")
    console.print(f"[bold]Risk Score:[/bold]  [{verdict_color}]{result.risk_score:.0f}/100[/{verdict_color}]")
    if result.page_title:
        console.print(f"[bold]Page Title:[/bold]  {result.page_title}")
    if result.server_banner:
        console.print(f"[bold]Server Banner:[/bold] {result.server_banner}")

    if result.redirect_chain:
        table = Table(title="HTTP & Client-Side Redirect Chain", show_header=True, header_style="bold cyan")
        table.add_column("Hop #", justify="center", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Destination URL", max_width=60)
        table.add_column("Latency (ms)", justify="right")

        for hop in result.redirect_chain:
            table.add_row(
                str(hop.hop_number),
                str(hop.status_code),
                hop.url,
                f"{hop.elapsed_ms:.1f}",
            )
        console.print()
        console.print(table)

    if result.forms_detected:
        f_table = Table(title="Discovered HTML Interactive Forms", show_header=True, header_style="bold magenta")
        f_table.add_column("Action Target", max_width=45)
        f_table.add_column("Method", justify="center")
        f_table.add_column("Password Field?", justify="center")
        f_table.add_column("External POST?", justify="center")

        for form in result.forms_detected:
            f_table.add_row(
                form.action,
                form.method,
                "[bold red]YES[/bold red]" if form.has_password_field else "NO",
                "[bold red]YES[/bold red]" if form.is_external_post else "NO",
            )
        console.print()
        console.print(f_table)

    if result.brand_impersonation.detected:
        console.print(f"\n[bold red]⚠️ BRAND IMPERSONATION ALERT:[/bold red] Impersonating [bold yellow]{result.brand_impersonation.impersonated_brand}[/bold yellow] (Confidence: {result.brand_impersonation.confidence * 100:.0f}%)")
        for ind in result.brand_impersonation.matched_indicators:
            console.print(f"  • Matched: {ind}")

    if result.suspicious_indicators:
        console.print("\n[bold red]Forensic Indicators Discovered:[/bold red]")
        for ind in result.suspicious_indicators:
            console.print(f"  • {ind}")
    console.print()


case_app = typer.Typer(help="Enterprise SOC Incident Case Management and triage queues.")
app.add_typer(case_app, name="case")


@case_app.command(name="create")
def case_create(
    eml_path: Path = typer.Argument(..., help="Path to suspicious .eml file"),
    analyst: str = typer.Option("tier1-analyst", "--analyst", help="Assigned SOC analyst"),
):
    """Scan an email and automatically create a tracked SOC investigation case ticket."""
    if not eml_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found at: {eml_path}")
        raise typer.Exit(code=1)

    parser = EmlParser()
    parsed = parser.parse_file(eml_path)
    scan_result = asyncio.run(_run_analysis(parsed, offline=True))

    mgr = CaseManager()
    case = mgr.create_case_from_scan(scan_result, assigned_analyst=analyst)

    sev_color = "red" if case.severity == CaseSeverity.CRITICAL else ("yellow" if case.severity in (CaseSeverity.HIGH, CaseSeverity.MEDIUM) else "green")
    console.print(f"\n[bold green]✓ SOC Incident Case Ticket Opened Successfully![/bold green]")
    console.print(f"• [bold]Case ID:[/bold]          [bold cyan]{case.case_id}[/bold cyan]")
    console.print(f"• [bold]Title:[/bold]            {case.title}")
    console.print(f"• [bold]Severity:[/bold]         [{sev_color}]{case.severity.value}[/{sev_color}]")
    console.print(f"• [bold]Assigned Analyst:[/bold] {case.assigned_analyst}")
    console.print(f"• [bold]Sender:[/bold]           {case.sender}")
    console.print(f"• [bold]Risk Score:[/bold]       [{sev_color}]{case.score:.1f}/100[/{sev_color}]")
    console.print(f"• [bold]Linked IOCs:[/bold]      {len(case.iocs)} artifacts tracked\n")


@case_app.command(name="list")
def case_list(
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status (NEW, IN_TRIAGE, CONTAINED, CLOSED_MALICIOUS, CLOSED_FALSE_POSITIVE)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    analyst: Optional[str] = typer.Option(None, "--analyst", help="Filter by assigned analyst"),
    limit: int = typer.Option(20, "--limit", help="Max cases to display"),
):
    """List active SOC incident cases in the triage queue."""
    mgr = CaseManager()
    cases = mgr.list_cases(status=status, severity=severity, analyst=analyst, limit=limit)

    if not cases:
        console.print("[yellow]No SOC cases found matching filter criteria.[/yellow]")
        return

    table = Table(title=f"SOC Incident Case Queue ({len(cases)} items)", show_header=True, header_style="bold cyan")
    table.add_column("Case ID", style="bold cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Sender", max_width=25)
    table.add_column("Subject", max_width=30)
    table.add_column("Analyst", style="dim")
    table.add_column("Created", style="dim")

    for c in cases:
        sev_color = "red" if c.severity == CaseSeverity.CRITICAL else ("yellow" if c.severity in (CaseSeverity.HIGH, CaseSeverity.MEDIUM) else "green")
        stat_color = "green" if c.status == CaseStatus.CONTAINED else ("blue" if c.status == CaseStatus.IN_TRIAGE else ("red" if c.status == CaseStatus.NEW else "dim"))
        table.add_row(
            c.case_id,
            f"[{sev_color}]{c.severity.value}[/{sev_color}]",
            f"[{stat_color}]{c.status.value}[/{stat_color}]",
            f"{c.score:.0f}",
            c.sender,
            c.subject,
            c.assigned_analyst,
            c.created_at[:10],
        )

    console.print()
    console.print(table)
    console.print()


@case_app.command(name="view")
def case_view(
    case_id: str = typer.Argument(..., help="Case ID (e.g. CASE-20261125-9A4B)"),
    dossier: bool = typer.Option(False, "--dossier", help="Output full Markdown incident dossier"),
):
    """View detailed case information, investigation timeline, and IOC checklist."""
    mgr = CaseManager()
    case = mgr.get_case(case_id)
    if not case:
        console.print(f"[bold red]Error:[/bold red] Case '{case_id}' not found.")
        raise typer.Exit(code=1)

    if dossier:
        console.print(mgr.export_case_dossier(case_id, format="markdown"))
        return

    sev_color = "red" if case.severity == CaseSeverity.CRITICAL else ("yellow" if case.severity in (CaseSeverity.HIGH, CaseSeverity.MEDIUM) else "green")
    console.print(f"\n[bold cyan]SOC Case Dossier:[/bold cyan] [bold]{case.case_id}[/bold] ({case.title})")
    console.print(f"• [bold]Status:[/bold]           {case.status.value}")
    console.print(f"• [bold]Severity:[/bold]         [{sev_color}]{case.severity.value}[/{sev_color}]")
    console.print(f"• [bold]Assigned Analyst:[/bold] {case.assigned_analyst}")
    console.print(f"• [bold]Risk Score:[/bold]       [{sev_color}]{case.score:.1f}/100[/{sev_color}]")
    console.print(f"• [bold]Summary:[/bold]          {case.summary}")

    if case.iocs:
        ioc_table = Table(title="Associated Indicators of Compromise (IOCs)", show_header=True, header_style="bold magenta")
        ioc_table.add_column("Type", style="bold")
        ioc_table.add_column("Indicator Value", max_width=50)
        ioc_table.add_column("Containment Status", justify="center")

        for ioc in case.iocs:
            status_color = "green" if ioc.status in ("BLOCKED", "QUARANTINED") else "yellow"
            ioc_table.add_row(ioc.ioc_type, ioc.value, f"[{status_color}]{ioc.status}[/{status_color}]")

        console.print()
        console.print(ioc_table)

    if case.timeline:
        t_table = Table(title="Investigation Timeline & Audit Trail", show_header=True, header_style="bold blue")
        t_table.add_column("Timestamp", style="dim")
        t_table.add_column("Analyst", style="bold")
        t_table.add_column("Log Note / Action Taken", max_width=60)

        for note in case.timeline:
            t_table.add_row(note.timestamp, note.analyst, note.message)

        console.print()
        console.print(t_table)
    console.print()


@case_app.command(name="update")
def case_update(
    case_id: str = typer.Argument(..., help="Case ID to update"),
    status: Optional[str] = typer.Option(None, "--status", help="New status (NEW, IN_TRIAGE, CONTAINED, CLOSED_MALICIOUS, CLOSED_FALSE_POSITIVE)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="New severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    analyst: Optional[str] = typer.Option(None, "--analyst", help="Reassign analyst"),
    note: Optional[str] = typer.Option(None, "--note", help="Analyst note or investigation update to add"),
):
    """Update case lifecycle state, severity rating, assignment, or add a note."""
    mgr = CaseManager()
    case = mgr.update_case(case_id, status=status, severity=severity, assigned_analyst=analyst)
    if not case:
        console.print(f"[bold red]Error:[/bold red] Case '{case_id}' not found.")
        raise typer.Exit(code=1)

    if note:
        case = mgr.add_note(case_id, analyst or case.assigned_analyst, note)

    console.print(f"[bold green]✓ Case '{case_id}' successfully updated.[/bold green]")
    console.print(f"• Current Status: {case.status.value}")
    console.print(f"• Current Severity: {case.severity.value}")
    console.print(f"• Assigned Analyst: {case.assigned_analyst}\n")


@app.command(name="version")
def version():
    """Display PhishGuard version information."""
    console.print(f"[bold cyan]PhishGuard SOC Engine[/bold cyan] v{__version__}")


def main():
    app()


if __name__ == "__main__":
    main()
