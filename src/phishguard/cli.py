"""
PhishGuard CLI - Multi-command SOC Analyst Interface.
"""

from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

from phishguard import __version__
from phishguard.parser.eml_parser import EmlParser

app = typer.Typer(
    name="phishguard",
    help="Enterprise-grade Automated Phishing Detection & Threat Intelligence Tool.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.command(name="scan")
def scan(
    eml_path: Path = typer.Argument(..., help="Path to the target .eml email file to analyze"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw SIEM-compatible JSON report"),
    offline: bool = typer.Option(False, "--offline", help="Run without external threat intelligence lookups"),
):
    """Ingest and analyze a single .eml email file."""
    if not eml_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {eml_path}")
        raise typer.Exit(code=1)

    console.print(f"[bold cyan]PhishGuard SOC[/bold cyan] Ingesting: [yellow]{eml_path.name}[/yellow]")
    parser = EmlParser()
    parsed = parser.parse_file(eml_path)

    console.print(f"[green]✓[/green] Successfully parsed RFC 5322 message:")
    console.print(f"  • Subject: [bold]{parsed.metadata.subject}[/bold]")
    console.print(f"  • From: {parsed.metadata.from_raw}")
    console.print(f"  • Date: {parsed.metadata.date}")
    console.print(f"  • Received Hops: {len(parsed.received_headers)}")
    console.print(f"  • MIME Parts: {len(parsed.mime_parts)}")
    console.print(f"  • Attachments: {len(parsed.attachments)}")
    console.print(f"  • Plaintext Body length: {len(parsed.plain_body)} chars")
    console.print(f"  • HTML Body length: {len(parsed.html_body)} chars")


@app.command(name="version")
def version():
    """Display PhishGuard version information."""
    console.print(f"[bold cyan]PhishGuard SOC Engine[/bold cyan] v{__version__}")


def main():
    app()


if __name__ == "__main__":
    main()
