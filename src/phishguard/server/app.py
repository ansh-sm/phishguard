"""
FastAPI REST API & Local SOC Web Console for PhishGuard.
"""

from pathlib import Path
from typing import Optional
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel

from phishguard import __version__
from phishguard.cli import _run_analysis
from phishguard.ai import AiTriageEngine, AiTriageRequest, AiTriageResult
from phishguard.forensics.dns_validator import DnsPolicyValidator, DomainDnsInspection
from phishguard.forensics.iocs import IOCExporter, IOCExtractor
from phishguard.intel.cache import IntelCache
from phishguard.models.report import ScanResult
from phishguard.parser.eml_parser import EmlParser
from phishguard.reporters.html_reporter import HtmlReporter
from phishguard.sandbox import UrlDetonator, UrlDetonationResult
from phishguard.cases import CaseManager, CaseSeverity, CaseStatus, SocCase
from phishguard.server.dashboard import DASHBOARD_HTML
from phishguard.hunting import AttackGraphBuilder, CampaignClusterer, ThreatCampaign, AttackGraph
from phishguard.siem import SiemConfig, SiemForwarder, SiemForwardResult
from phishguard.soar.generator import RemediationEngine
from phishguard.soar.models import PlatformType, RemediationPackage
from phishguard.storage.database import IncidentDatabase
from phishguard.storage.models import IncidentQueryFilter, IncidentSummary

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


@app.get("/api/rules")
async def get_rules(rules_dir: str = Query("rules", description="Directory containing custom YAML rules")):
    """Returns all active custom detection rules."""
    from phishguard.rules import RuleEngine
    engine = RuleEngine.from_directory(rules_dir)
    return {
        "total_rules": len(engine.rules),
        "rules": [r.model_dump() for r in engine.rules],
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


@app.get("/api/remediate/{scan_id}", response_model=RemediationPackage)
async def get_remediation_package(
    scan_id: str,
    platform: str = Query("all", description="Target platform: m365, google, edr, firewall, all"),
):
    """Generate multi-platform SOAR remediation playbooks for a scan."""
    db = IncidentDatabase()
    result = SCAN_CACHE.get(scan_id) or db.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Incident '{scan_id}' not found")

    engine = RemediationEngine()
    plat_enum = PlatformType(platform.lower())
    return engine.generate_package(result, platforms=[plat_enum])


@app.get("/api/hunt")
async def hunt_incidents(
    query: Optional[str] = Query(None, description="Free-text search in subject or sender"),
    ip: Optional[str] = Query(None, description="Originating IP"),
    domain: Optional[str] = Query(None, description="Sender or URL domain"),
    hash_val: Optional[str] = Query(None, description="Attachment or file SHA256"),
    technique: Optional[str] = Query(None, description="MITRE ATT&CK technique ID"),
    verdict: Optional[str] = Query(None, description="Verdict: MALICIOUS, SUSPICIOUS, CLEAN"),
    limit: int = Query(50, description="Max results"),
):
    """Query historical incidents across threat intelligence dimensions."""
    db = IncidentDatabase()
    filt = IncidentQueryFilter(
        query=query, ip=ip, domain=domain,
        hash_val=hash_val, technique=technique,
        verdict=verdict, limit=limit
    )
    results = db.search_incidents(filt)
    return {
        "count": len(results),
        "results": [r.model_dump() for r in results],
    }


@app.get("/api/stats")
async def get_incident_stats():
    """Returns SOC triage metrics and threat statistics."""
    db = IncidentDatabase()
    return db.get_stats()


@app.get("/api/campaigns")
async def get_campaigns(min_size: int = Query(1, description="Minimum incidents per campaign cluster")):
    """Discover and correlate active threat campaigns across historical incidents."""
    db = IncidentDatabase()
    incidents = db.search_incidents(IncidentQueryFilter(limit=100))
    campaigns = CampaignClusterer.cluster_incidents(incidents, min_cluster_size=min_size)
    return {
        "count": len(campaigns),
        "campaigns": [c.model_dump() for c in campaigns],
    }


@app.get("/api/graph/{scan_id}")
async def get_incident_graph(scan_id: str):
    """Generate topological attack graph for an analyzed email incident."""
    db = IncidentDatabase()
    result = SCAN_CACHE.get(scan_id) or db.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Incident '{scan_id}' not found")
    graph = AttackGraphBuilder.build_incident_graph(result)
    return {
        "scan_id": scan_id,
        "mermaid": graph.to_mermaid(),
        "graph": graph.to_dict(),
    }


class SiemForwardRequest(BaseModel):
    scan_id: str
    config: SiemConfig


@app.post("/api/siem/forward", response_model=SiemForwardResult)
async def forward_to_siem(req: SiemForwardRequest):
    """Stream incident event to configured enterprise SIEM."""
    db = IncidentDatabase()
    result = SCAN_CACHE.get(req.scan_id) or db.get_scan(req.scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Incident '{req.scan_id}' not found")
    return SiemForwarder.forward_scan_result(req.config, result)


@app.post("/api/siem/test", response_model=SiemForwardResult)
async def test_siem_connection(config: SiemConfig):
    """Test connectivity and authentication to destination SIEM."""
    return SiemForwarder.test_connection(config)


@app.post("/api/ai/triage", response_model=AiTriageResult)
async def triage_email_content(req: AiTriageRequest):
    """Run AI social engineering and intent classification on email text."""
    return AiTriageEngine.triage_text(
        subject=req.subject,
        body=req.body_text,
        from_name=req.from_name,
        from_email=req.from_email,
        provider=req.provider,
        api_key=req.api_key,
    )


@app.get("/api/dns/verify/{domain}", response_model=DomainDnsInspection)
async def verify_domain_dns(domain: str, ip: Optional[str] = Query(None, description="Originating IP to test")):
    """Perform live DNS queries to audit SPF and DMARC spoofing resilience."""
    return DnsPolicyValidator.inspect_domain(domain, originating_ip=ip)


class DetonateRequest(BaseModel):
    url: str
    timeout: float = 8.0
    user_agent: Optional[str] = None


@app.post("/api/sandbox/detonate", response_model=UrlDetonationResult)
async def detonate_url(req: DetonateRequest):
    """Detonate suspicious URL in sandbox and inspect redirect chain and landing DOM."""
    kwargs = {"timeout_seconds": req.timeout}
    if req.user_agent:
        kwargs["user_agent"] = req.user_agent
    detonator = UrlDetonator(**kwargs)
    return detonator.detonate(req.url)


class CreateCaseRequest(BaseModel):
    title: str
    severity: str = "MEDIUM"
    sender: str = ""
    subject: str = ""
    score: float = 0.0
    summary: str = ""
    assigned_analyst: str = "tier1-analyst"
    source_scan_id: Optional[str] = None


class CaseUpdateRequest(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    assigned_analyst: Optional[str] = None
    note: Optional[str] = None
    note_analyst: Optional[str] = "analyst"


@app.post("/api/cases", response_model=SocCase)
async def create_case(req: CreateCaseRequest):
    """Create a new tracked SOC incident case."""
    mgr = CaseManager()
    sev = CaseSeverity(req.severity.upper()) if req.severity else CaseSeverity.MEDIUM
    return mgr.create_case(
        title=req.title,
        severity=sev,
        sender=req.sender,
        subject=req.subject,
        score=req.score,
        summary=req.summary,
        assigned_analyst=req.assigned_analyst,
        source_scan_id=req.source_scan_id,
    )


@app.post("/api/cases/from-scan/{scan_id}", response_model=SocCase)
async def create_case_from_scan_id(scan_id: str, analyst: str = Query("tier1-analyst")):
    """Create a SOC case directly from an analyzed scan result."""
    db = IncidentDatabase()
    result = SCAN_CACHE.get(scan_id) or db.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    mgr = CaseManager()
    return mgr.create_case_from_scan(result, assigned_analyst=analyst)


@app.get("/api/cases", response_model=list[SocCase])
async def list_cases(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    analyst: Optional[str] = Query(None),
    limit: int = Query(50),
):
    """List cases in the SOC investigation queue."""
    mgr = CaseManager()
    return mgr.list_cases(status=status, severity=severity, analyst=analyst, limit=limit)


@app.get("/api/cases/{case_id}", response_model=SocCase)
async def get_case(case_id: str):
    """Fetch single case details including timeline and linked IOCs."""
    mgr = CaseManager()
    case = mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return case


@app.patch("/api/cases/{case_id}", response_model=SocCase)
async def update_case(case_id: str, req: CaseUpdateRequest):
    """Update case state, assignment, or append an analyst note."""
    mgr = CaseManager()
    case = mgr.update_case(
        case_id,
        status=req.status,
        severity=req.severity,
        assigned_analyst=req.assigned_analyst,
    )
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    if req.note:
        case = mgr.add_note(case_id, req.note_analyst or "analyst", req.note)
    return case


@app.get("/api/cases/{case_id}/dossier")
async def get_case_dossier(case_id: str, format: str = Query("markdown")):
    """Export case briefing dossier in markdown or json format."""
    mgr = CaseManager()
    try:
        dossier = mgr.export_case_dossier(case_id, format=format)
        media_type = "application/json" if format.lower() == "json" else "text/markdown"
        return Response(content=dossier, media_type=media_type)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
