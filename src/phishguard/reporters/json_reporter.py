"""
SIEM JSON Exporter for PhishGuard SOC.
"""

import json
from pathlib import Path
from typing import Optional

from phishguard.models.report import ScanResult


class JsonReporter:
    """
    Exports ScanResult as structured SIEM-ready JSON (compatible with Splunk, Elastic, Sentinel).
    """

    def export(self, result: ScanResult, output_path: Optional[Path] = None) -> str:
        """Serialize ScanResult to JSON string and optionally write to disk."""
        data_json = result.model_dump_json(indent=2)

        if output_path:
            path = Path(output_path).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data_json, encoding="utf-8")

        return data_json
