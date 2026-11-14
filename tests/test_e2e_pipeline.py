"""
End-to-End Pipeline Verification across PhishGuard Email Corpus.
"""

from pathlib import Path
import pytest

from phishguard.cli import _run_analysis
from phishguard.models.report import VerdictEnum
from phishguard.parser.eml_parser import EmlParser


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parent.parent / "samples"


@pytest.mark.asyncio
async def test_e2e_quishing_email(samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "quishing_mfa_lure.eml")
    result = await _run_analysis(parsed, offline=True)

    assert result.quishing is not None
    assert result.quishing.found is True
    assert result.verdict in (VerdictEnum.MALICIOUS, VerdictEnum.SUSPICIOUS)
    assert any("Quishing" in f for f in result.key_findings)


@pytest.mark.asyncio
async def test_e2e_ceo_fraud_email(samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "ceo_fraud_wire_transfer.eml")
    result = await _run_analysis(parsed, offline=True)

    assert result.headers.reply_to_mismatch is True
    assert result.score.content_score > 0
    assert any("urgency" in f.lower() or "reply-to" in f.lower() for f in result.key_findings)


@pytest.mark.asyncio
async def test_e2e_weaponized_attachment(samples_dir: Path):
    parser = EmlParser()
    parsed = parser.parse_file(samples_dir / "weaponized_invoice_attachment.eml")
    result = await _run_analysis(parsed, offline=True)

    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.is_executable is True
    assert att.is_double_extension is True
    assert result.verdict == VerdictEnum.MALICIOUS
    assert result.score.total_score >= 60.0
