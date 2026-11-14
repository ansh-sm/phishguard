"""
EML and MIME parsing subsystem for PhishGuard SOC.
"""

from phishguard.parser.eml_parser import EmlParser, ParsedEmail, RawAttachment

__all__ = ["EmlParser", "ParsedEmail", "RawAttachment"]
