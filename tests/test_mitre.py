"""
Unit tests for MITRE ATT&CK Framework Mapping and STIX 2.1 Attack Patterns.
"""

from pathlib import Path
import json
import pytest

from phishguard.cli import _run_analysis
from phishguard.forensics.iocs import IOCExporter, IOCExtractor
from phishguard.parser.eml_parser import EmlParser


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent.parent / "samples"


@pytest.mark.asyncio
async def test_mitre_mapping_phishing_account_alert(samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "phishing_account_alert.eml")
    result = await _run_analysis(parsed, offline=True)

    assert len(result.mitre_attack) >= 2
    technique_ids = {t.technique_id for t in result.mitre_attack}

    # Should detect Masquerading (Typosquatting) and Spearphishing Link
    assert "T1036.005" in technique_ids
    assert "T1566.002" in technique_ids
    assert "T1204.001" in technique_ids

    # Check that STIX 2.1 bundle includes attack-pattern objects
    extractor = IOCExtractor()
    exporter = IOCExporter()
    bundle = extractor.extract(result)
    stix_str = exporter.to_stix21(bundle)
    stix_data = json.loads(stix_str)

    attack_patterns = [obj for obj in stix_data["objects"] if obj.get("type") == "attack-pattern"]
    assert len(attack_patterns) >= 2
    assert any("T1036.005" in p["name"] for p in attack_patterns)


@pytest.mark.asyncio
async def test_mitre_mapping_weaponized_attachment(samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "weaponized_invoice_attachment.eml")
    result = await _run_analysis(parsed, offline=True)

    technique_ids = {t.technique_id for t in result.mitre_attack}
    assert "T1566.001" in technique_ids
    assert "T1204.002" in technique_ids


@pytest.mark.asyncio
async def test_mitre_mapping_benign_newsletter(samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "benign_newsletter.eml")
    result = await _run_analysis(parsed, offline=True)

    assert len(result.mitre_attack) == 0
