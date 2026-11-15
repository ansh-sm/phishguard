"""
FastAPI REST API & Local SOC Web Console for PhishGuard.
"""

from pathlib import Path
from typing import Optional
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from phishguard import __version__
from phishguard.cli import _run_analysis
from phishguard.forensics.iocs import IOCExporter, IOCExtractor
from phishguard.intel.cache import IntelCache
from phishguard.models.report import ScanResult
from phishguard.parser.eml_parser import EmlParser
from phishguard.reporters.html_reporter import HtmlReporter
from phishguard.server.dashboard import DASHBOARD_HTML

app = FastAPI(
    title="PhishGuard SOC API",
    description="Enterprise Automated Phishing Email Detection & Threat Intelligence Engine",
    version=__version__,
)

# In-memory store for recent scans
SCAN_CACHE: dict[str, ScanResult] = {}
iocs_extractor = IOCExtractor()
iocs_exporter = IOCExporter()
html_reporter = HtmlReporter()


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serves the interactive SOC Web Dashboard."""
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/api/health")
async def health_check():
    """Health status and active features."""
    return {
        "status": "healthy",
        "version": __version__,
        "engine": "PhishGuard SOC",
        "providers": ["URLhaus", "PhishTank", "VirusTotal", "AlienVault OTX"],
    }


@app.get("/api/cache/stats")
async def cache_stats():
    """Returns local SQLite intel cache statistics."""
    cache = IntelCache()
    return {
        "cache_db_path": str(cache.db_path),
        "db_exists": cache.db_path.exists(),
        "size_bytes": cache.db_path.stat().st_size if cache.db_path.exists() else 0,
    }


@app.post("/api/scan", response_model=ScanResult)
async def scan_eml(
    file: UploadFile = File(...),
    offline: bool = Query(False, description="Disable external network API queries"),
):
    """
    Ingest and forensically analyze an uploaded .eml file.
    Returns complete ScanResult JSON.
    """
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    parser = EmlParser()
    parsed = parser.parse_bytes(content, file_path=file.filename)

    result = await _run_analysis(parsed, offline=offline)
    SCAN_CACHE[result.scan_id] = result

    return result


@app.get("/api/export/csv")
async def export_csv(scan_id: str = Query(...)):
    """Export IOCs for a scan as CSV."""
    if scan_id not in SCAN_CACHE:
        raise HTTPException(status_code=404, detail="Scan ID not found in active session cache")
    bundle = iocs_extractor.extract(SCAN_CACHE[scan_id])
    csv_data = iocs_exporter.to_csv(bundle)
    return PlainTextResponse(content=csv_data, media_type="text/csv")


@app.get("/api/export/stix")
async def export_stix(scan_id: str = Query(...)):
    """Export IOCs for a scan as OASIS STIX 2.1 JSON Bundle."""
    if scan_id not in SCAN_CACHE:
        raise HTTPException(status_code=404, detail="Scan ID not found in active session cache")
    bundle = iocs_extractor.extract(SCAN_CACHE[scan_id])
    stix_data = iocs_exporter.to_stix21(bundle)
    return Response(content=stix_data, media_type="application/json")


@app.get("/api/export/html", response_class=HTMLResponse)
async def export_html(scan_id: str = Query(...)):
    """Export standalone executive HTML report."""
    if scan_id not in SCAN_CACHE:
        raise HTTPException(status_code=404, detail="Scan ID not found in active session cache")
    html_data = html_reporter.generate(SCAN_CACHE[scan_id])
    return HTMLResponse(content=html_data)
