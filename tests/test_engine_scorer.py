"""
Unit tests for Multi-Vector Scoring Engine and SOC Incident Narrative.
"""

from pathlib import Path
import pytest

from phishguard.engine.narrative import NarrativeGenerator
from phishguard.engine.scorer import ScoringEngine
from phishguard.forensics.auth import AuthResultsParser
from phishguard.forensics.headers import HeaderForensicsEngine
from phishguard.forensics.quishing import QuishingDetector
from phishguard.forensics.spoofing import SpoofingDetector
from phishguard.forensics.urls import UrlAnalyzer
from phishguard.models.forensics import HeaderAnalysis
from phishguard.models.report import VerdictEnum
from phishguard.parser.eml_parser import EmlParser


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent.parent / "samples"


def test_scorer_phishing_account_alert(samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "phishing_account_alert.eml")

    # Run forensics
    header_engine = HeaderForensicsEngine()
    auth_parser = AuthResultsParser()
    spoof_detector = SpoofingDetector()
    url_analyzer = UrlAnalyzer()
    quish_detector = QuishingDetector()

    hops, orig_ip, anomalies, h_score = header_engine.analyze_headers(parsed)
    auth = auth_parser.parse(parsed.auth_results_headers)
    disp, reply, puny, homo, target, s_anomalies, s_score = spoof_detector.analyze(parsed.metadata)

    anomalies.extend(s_anomalies)
    header_analysis = HeaderAnalysis(
        hops=hops,
        originating_ip=orig_ip,
        auth=auth,
        display_name_spoof=disp,
        reply_to_mismatch=reply,
        lookalike_domain=bool(target),
        lookalike_target=target,
        anomalies=anomalies,
        risk_score=min(30.0, h_score + s_score),
    )

    urls = url_analyzer.extract_and_analyze(parsed.plain_body, parsed.html_body)
    quishing = quish_detector.analyze(parsed)

    scorer = ScoringEngine()
    scores, verdict, severity, confidence, findings = scorer.calculate(
        headers=header_analysis,
        urls=urls,
        attachments=[],
        quishing=quishing,
        plain_body=parsed.plain_body,
        subject=parsed.metadata.subject,
    )

    assert verdict == VerdictEnum.MALICIOUS
    assert scores.total_score >= 60.0
    assert len(findings) > 0

    narrative_gen = NarrativeGenerator()
    explanation, remediation = narrative_gen.generate(
        verdict=verdict,
        severity=severity,
        scores=scores,
        key_findings=findings,
        from_email=parsed.metadata.from_email,
        originating_ip=orig_ip,
    )

    assert "INCIDENT ASSESSMENT: The ingested message is confirmed MALICIOUS" in explanation
    assert len(remediation) >= 3


def test_scorer_benign_newsletter(samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "benign_newsletter.eml")

    header_engine = HeaderForensicsEngine()
    auth_parser = AuthResultsParser()
    url_analyzer = UrlAnalyzer()

    hops, orig_ip, anomalies, h_score = header_engine.analyze_headers(parsed)
    auth = auth_parser.parse(parsed.auth_results_headers)

    header_analysis = HeaderAnalysis(
        hops=hops,
        originating_ip=orig_ip,
        auth=auth,
        risk_score=h_score,
    )

    urls = url_analyzer.extract_and_analyze(parsed.plain_body, parsed.html_body)

    scorer = ScoringEngine()
    scores, verdict, severity, confidence, findings = scorer.calculate(
        headers=header_analysis,
        urls=urls,
        attachments=[],
        quishing=None,
        plain_body=parsed.plain_body,
        subject=parsed.metadata.subject,
    )

    assert verdict == VerdictEnum.CLEAN
    assert scores.total_score <= 25.0
