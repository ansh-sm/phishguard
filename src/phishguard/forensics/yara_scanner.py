"""
Binary Signature & YARA-Style Pattern Scanner for Attachment Forensics.
Performs in-depth byte inspection for malware stagers, shellcode APIs, and evasion artifacts.
"""

from dataclasses import dataclass
import io
import re
from typing import Optional
import zipfile


@dataclass
class YaraMatch:
    """Represents a byte pattern detection match."""
    rule_name: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    matched_indicators: list[str]


class YaraScanner:
    """
    In-memory byte pattern and heuristic binary scanner for email payloads.
    """

    # 1. PE Injection and API hooking indicators
    PE_INJECTION_APIS = [
        rb"VirtualAlloc",
        rb"VirtualProtect",
        rb"WriteProcessMemory",
        rb"CreateRemoteThread",
        rb"RtlMoveMemory",
        rb"QueueUserAPC",
        rb"SetWindowsHookEx",
        rb"NtUnmapViewOfSection",
    ]

    # 2. Obfuscated PowerShell patterns
    POWERSHELL_PATTERNS = [
        rb"-enc\s+",
        rb"-encodedcommand\s+",
        rb"FromBase64String",
        rb"DownloadString",
        rb"DownloadFile",
        rb"IEX\s*\(",
        rb"bypass\s+-nop",
        rb"Invoke-Expression",
    ]

    # 3. PDF weaponization actions
    PDF_ACTIONS = [
        (rb"/JavaScript", "Embedded JavaScript Engine Stream"),
        (rb"/JS", "Direct JavaScript Script Execution"),
        (rb"/Launch", "Operating System Binary Launch Action"),
        (rb"/OpenAction", "Auto-Execution on Document Open"),
        (rb"/EmbeddedFiles", "Concealed Embedded File Payloads"),
    ]

    # 4. VBA Auto-Execution Hooks
    VBA_HOOKS = [
        rb"AutoOpen",
        rb"Document_Open",
        rb"Workbook_Open",
        rb"Auto_Close",
        rb"ShellExecute",
        rb"WScript\.Shell",
    ]

    def scan_bytes(self, payload: bytes, filename: str = "") -> list[YaraMatch]:
        """Scans binary payload bytes against signature catalog."""
        if not payload:
            return []

        matches: list[YaraMatch] = []

        # Rule 1: Disguised PE Executable
        if payload.startswith(b"MZ"):
            # Check for PE signature within first 1024 bytes
            pe_offset = payload[:1024].find(b"PE\x00\x00")
            if pe_offset != -1:
                matches.append(
                    YaraMatch(
                        rule_name="YARA_DISGUISED_PE_BINARY",
                        category="malware",
                        severity="CRITICAL",
                        description="Valid Portable Executable (PE) binary header structure discovered.",
                        matched_indicators=[f"MZ header at offset 0, PE signature at offset {pe_offset}"],
                    )
                )

        # Rule 2: PE Memory Injection / Shellcode APIs
        api_hits = []
        for api_pat in self.PE_INJECTION_APIS:
            if re.search(api_pat, payload, re.IGNORECASE):
                api_hits.append(api_pat.decode("latin-1"))

        if len(api_hits) >= 2:
            matches.append(
                YaraMatch(
                    rule_name="YARA_SUSPICIOUS_MEMORY_INJECTION_APIS",
                    category="injection",
                    severity="HIGH",
                    description="Multiple Windows memory tampering or process injection APIs referenced in binary.",
                    matched_indicators=api_hits,
                )
            )

        # Rule 3: Obfuscated PowerShell Stager
        ps_hits = []
        for ps_pat in self.POWERSHELL_PATTERNS:
            if re.search(ps_pat, payload, re.IGNORECASE):
                ps_hits.append(ps_pat.decode("latin-1"))

        if ps_hits:
            matches.append(
                YaraMatch(
                    rule_name="YARA_OBFUSCATED_POWERSHELL_STAGER",
                    category="stager",
                    severity="HIGH",
                    description="PowerShell encoded execution or web download cradle indicators detected.",
                    matched_indicators=ps_hits,
                )
            )

        # Rule 4: PDF Malicious Action Streams
        if payload.startswith(b"%PDF-"):
            pdf_hits = []
            for pdf_pat, desc in self.PDF_ACTIONS:
                if re.search(pdf_pat, payload):
                    pdf_hits.append(f"{desc} ({pdf_pat.decode('latin-1')})")

            if pdf_hits:
                matches.append(
                    YaraMatch(
                        rule_name="YARA_PDF_SUSPICIOUS_ACTIVE_CONTENT",
                        category="exploit",
                        severity="HIGH",
                        description="PDF document contains active script execution or process launch triggers.",
                        matched_indicators=pdf_hits,
                    )
                )

        # Rule 5: Office VBA Auto-Execution Hooks
        vba_hits = []
        for vba_pat in self.VBA_HOOKS:
            if re.search(vba_pat, payload, re.IGNORECASE):
                vba_hits.append(vba_pat.decode("latin-1"))

        if vba_hits:
            matches.append(
                YaraMatch(
                    rule_name="YARA_VBA_AUTOEXEC_STAGER",
                    category="macro",
                    severity="HIGH",
                    description="Office document exhibits auto-execution hooks designed to trigger upon opening.",
                    matched_indicators=vba_hits,
                )
            )

        # Rule 6: Windows Shortcut LNK Command Stager
        if payload.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00") or filename.lower().endswith(".lnk"):
            cmd_hits = []
            for cmd_pat in (rb"cmd\.exe", rb"powershell", rb"mshta", rb"cscript", rb"wscript"):
                if re.search(cmd_pat, payload, re.IGNORECASE):
                    cmd_hits.append(cmd_pat.decode("latin-1"))

            if cmd_hits:
                matches.append(
                    YaraMatch(
                        rule_name="YARA_LNK_BINARY_COMMAND_STAGER",
                        category="stager",
                        severity="CRITICAL",
                        description="Windows Shell Link (.lnk) invokes command interpreter or script engine.",
                        matched_indicators=cmd_hits,
                    )
                )

        # Rule 7: Password-Protected / Encrypted Zip Archive
        if payload.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as z:
                    encrypted_entries = [info.filename for info in z.infolist() if info.flag_bits & 0x1]
                    if encrypted_entries:
                        matches.append(
                            YaraMatch(
                                rule_name="YARA_ENCRYPTED_ZIP_PAYLOAD",
                                category="evasion",
                                severity="HIGH",
                                description="Zip archive contains password-protected members concealing inspection.",
                                matched_indicators=encrypted_entries[:5],
                            )
                        )
            except Exception:
                pass

        return matches
