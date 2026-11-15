"""
Unit tests for IOC Extraction and STIX 2.1 / CSV Export.
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
async def test_ioc_extraction_and_formats(samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "phishing_account_alert.eml")
    result = await _run_analysis(parsed, offline=True)

    extractor = IOCExtractor()
    exporter = IOCExporter()

    bundle = extractor.extract(result)
    assert bundle.total_iocs >= 6

    # Verify types of IOCs present
    types = {item.ioc_type for item in bundle.items}
    assert "email" in types
    assert "domain" in types
    assert "ipv4" in types
    assert "url" in types

    # Test CSV export
    csv_str = exporter.to_csv(bundle)
    assert "ioc_type,value,defanged_value" in csv_str
    assert "185[.]220[.]101[.]5" in csv_str

    # Test JSON export
    json_str = exporter.to_json(bundle)
    data = json.loads(json_str)
    assert data["total_iocs"] == bundle.total_iocs

    # Test STIX 2.1 export
    stix_str = exporter.to_stix21(bundle)
    stix_data = json.loads(stix_str)
    assert stix_data["type"] == "bundle"
    assert len(stix_data["objects"]) >= 7
    assert stix_data["objects"][0]["type"] == "report"
    assert any("[ipv4-addr:value =" in obj.get("pattern", "") for obj in stix_data["objects"])
