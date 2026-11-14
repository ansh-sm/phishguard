"""
Unit tests for Terminal, JSON, and HTML Reporters.
"""

from pathlib import Path
import json
import pytest

from phishguard.engine.scorer import ScoringEngine
from phishguard.engine.narrative import NarrativeGenerator
from phishguard.forensics.headers import HeaderForensicsEngine
from phishguard.forensics.urls import UrlAnalyzer
from phishguard.models.forensics import HeaderAnalysis
from phishguard.models.report import ScanResult
from phishguard.parser.eml_parser import EmlParser
from phishguard.reporters.html_reporter import HtmlReporter
from phishguard.reporters.json_reporter import JsonReporter


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent.parent / "samples"


@pytest.fixture
def sample_scan_result(samples_dir: Path) -> ScanResult:
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "phishing_account_alert.eml")

    header_engine = HeaderForensicsEngine()
    hops, orig_ip, anomalies, h_score = header_engine.analyze_headers(parsed)
    header_analysis = HeaderAnalysis(hops=hops, originating_ip=orig_ip, anomalies=anomalies, risk_score=h_score)

    url_analyzer = UrlAnalyzer()
    urls = url_analyzer.extract_and_analyze(parsed.plain_body, parsed.html_body)

    scorer = ScoringEngine()
    scores, verdict, severity, conf, findings = scorer.calculate(
        headers=header_analysis,
        urls=urls,
        attachments=[],
        quishing=None,
        plain_body=parsed.plain_body,
        subject=parsed.metadata.subject,
    )

    narrative_gen = NarrativeGenerator()
    explanation, remediation = narrative_gen.generate(
        verdict=verdict, severity=severity, scores=scores, key_findings=findings, from_email=parsed.metadata.from_email, originating_ip=orig_ip
    )

    return ScanResult(
        scan_id="TEST-SCAN-123",
        eml_file_path=str(samples_dir / "phishing_account_alert.eml"),
        eml_file_hash_sha256=parsed.file_sha256,
        metadata=parsed.metadata,
        headers=header_analysis,
        urls=urls,
        attachments=[],
        score=scores,
        verdict=verdict,
        severity=severity,
        confidence_percentage=conf,
        key_findings=findings,
        written_explanation=explanation,
        remediation_steps=remediation,
    )


def test_json_reporter_export(sample_scan_result: ScanResult, tmp_path: Path):
    reporter = JsonReporter()
    json_out = tmp_path / "test_out.json"
    result_str = reporter.export(sample_scan_result, output_path=json_out)

    assert json_out.exists()
    data = json.loads(result_str)
    assert data["scan_id"] == "TEST-SCAN-123"
    assert data["verdict"] in ("MALICIOUS", "SUSPICIOUS", "CLEAN")
    assert "score" in data
    assert "remediation_steps" in data


def test_html_reporter_export(sample_scan_result: ScanResult, tmp_path: Path):
    reporter = HtmlReporter()
    html_out = tmp_path / "test_out.html"
    result_str = reporter.generate(sample_scan_result, output_path=html_out)

    assert html_out.exists()
    assert "<!DOCTYPE html>" in result_str
    assert "TEST-SCAN-123" in result_str
    assert "PhishGuard SOC" in result_str
    assert "Risk Matrix" in result_str
