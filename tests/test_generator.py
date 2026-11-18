"""
Unit tests for Synthetic Phishing and Benign Sample Generator.
"""

from pathlib import Path
import pytest

from phishguard.generator.sample_generator import SampleGenerator
from phishguard.parser.eml_parser import EmlParser


@pytest.fixture
def generator() -> SampleGenerator:
    return SampleGenerator()


def test_generate_all_lure_types(generator: SampleGenerator, tmp_path: Path):
    parser = EmlParser()

    for lure in generator.SUPPORTED_LURES:
        out_file = tmp_path / f"test_{lure}.eml"
        content = generator.generate(lure, recipient="target@company.com", output_path=out_file)

        assert out_file.exists()
        assert "From:" in content
        assert "To: target@company.com" in content

        # Verify parser can ingest generated file cleanly
        parsed = parser.parse_file(out_file)
        assert parsed.metadata.to_emails == ["target@company.com"]
        assert len(parsed.metadata.subject) > 0


def test_invalid_lure_type_raises_error(generator: SampleGenerator):
    with pytest.raises(ValueError, match="Unsupported lure type"):
        generator.generate("non_existent_lure")
