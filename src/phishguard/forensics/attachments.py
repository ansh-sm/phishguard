"""
Attachment Forensics Engine: Magic Byte Signatures, Macro Detection, and Archive Inspection.
"""

import io
from pathlib import Path
import re
from typing import Optional
import zipfile

from phishguard.models.forensics import AttachmentArtifact
from phishguard.parser.eml_parser import RawAttachment


class AttachmentForensicsEngine:
    """
    Forensic analyzer for email attachments:
    - Magic byte true-type identification
    - Dangerous / double extension detection
    - Office macro inspection (OLE2 & OOXML vbaProject.bin)
    - Archive inspection (zip payload examination)
    """

    # Magic byte signatures
    MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
        (b"MZ", "application/x-dosexec", "PE Executable (.exe / .dll / .scr)"),
        (b"\x7fELF", "application/x-elf", "Linux Executable (.elf)"),
        (b"%PDF-", "application/pdf", "Adobe PDF"),
        (b"PK\x03\x04", "application/zip", "ZIP Archive or OOXML Document"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", "OLE Compound Document (.doc/.xls)"),
        (b"Rar!\x1a\x07", "application/x-rar-compressed", "RAR Archive"),
        (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip Archive"),
        (b"\x1f\x8b\x08", "application/gzip", "GZIP Compressed Archive"),
        (b"\x89PNG\r\n\x1a\n", "image/png", "PNG Image"),
        (b"\xff\xd8\xff", "image/jpeg", "JPEG Image"),
        (b"GIF87a", "image/gif", "GIF Image"),
        (b"GIF89a", "image/gif", "GIF Image"),
    ]

    DANGEROUS_EXTENSIONS = {
        "exe", "dll", "scr", "bat", "cmd", "vbs", "vbe", "js", "jse",
        "hta", "ps1", "psm1", "pif", "cpl", "wsf", "jar", "iso", "img",
        "lnk", "reg", "inf"
    }

    SCRIPT_EXTENSIONS = {"bat", "cmd", "vbs", "js", "ps1", "hta", "wsf"}
    EXECUTABLE_EXTENSIONS = {"exe", "dll", "scr", "pif", "cpl"}
    ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz", "iso", "img"}
    MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm"}

    def inspect_attachment(self, attachment: RawAttachment) -> AttachmentArtifact:
        """Perform comprehensive forensic inspection on an extracted attachment."""
        filename = attachment.filename
        payload = attachment.payload_bytes

        # 1. Detect True File Type from Magic Bytes
        detected_mime, detected_desc = self._identify_magic_bytes(payload)

        # 2. Filename and Extension Forensics
        ext_parts = filename.lower().split(".")
        is_double_ext = False
        primary_ext = ext_parts[-1] if len(ext_parts) > 1 else ""

        if len(ext_parts) > 2:
            second_last = ext_parts[-2]
            # Common double-extension tricks: e.g. .pdf.exe, .docx.vbs
            if primary_ext in self.DANGEROUS_EXTENSIONS and second_last in ("pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg"):
                is_double_ext = True

        is_executable = primary_ext in self.EXECUTABLE_EXTENSIONS or (detected_mime == "application/x-dosexec")
        is_script = primary_ext in self.SCRIPT_EXTENSIONS
        is_archive = primary_ext in self.ARCHIVE_EXTENSIONS or (detected_mime in ("application/zip", "application/x-rar-compressed", "application/x-7z-compressed"))

        # 3. Macro and Archive Inspection
        has_macros = False
        archive_contents: list[str] = []
        risk_reasons: list[str] = []
        risk_score: float = 0.0

        # Check for Office Macros
        if primary_ext in self.MACRO_EXTENSIONS or detected_mime in ("application/zip", "application/x-ole-storage"):
            has_macros = self._check_for_macros(payload, primary_ext)

        # Inspect Archive Contents (if ZIP)
        if is_archive and payload.startswith(b"PK\x03\x04"):
            archive_contents = self._inspect_zip_contents(payload)
            # Check if archive conceals executable or script payloads
            for item in archive_contents:
                sub_ext = item.lower().split(".")[-1] if "." in item else ""
                if sub_ext in self.DANGEROUS_EXTENSIONS:
                    risk_reasons.append(f"Archive contains hidden executable or script payload: '{item}'.")
                    risk_score += 40.0
                    break

        # 4. Synthesize Risk Scoring & Findings
        if is_executable:
            risk_reasons.append(f"Direct executable file payload detected ({primary_ext or detected_desc}).")
            risk_score += 45.0

        if is_double_ext:
            risk_reasons.append(f"Deceptive double extension detected on '{filename}'.")
            risk_score += 35.0

        if is_script:
            risk_reasons.append(f"Dangerous script file attachment: '.{primary_ext}'.")
            risk_score += 30.0

        if has_macros:
            risk_reasons.append("Weaponized VBA macro streams detected inside Office document.")
            risk_score += 35.0

        # MIME Mismatch check (e.g. claims to be PDF but magic bytes say PE executable)
        if attachment.content_type.startswith("application/pdf") and detected_mime == "application/x-dosexec":
            risk_reasons.append("Severe MIME Spoofing: Declared as PDF, but binary signature is a Windows Executable (MZ).")
            risk_score += 50.0

        return AttachmentArtifact(
            filename=filename,
            original_mime=attachment.content_type,
            detected_mime=detected_mime,
            size_bytes=attachment.size_bytes,
            md5=attachment.md5,
            sha1=attachment.sha1,
            sha256=attachment.sha256,
            is_double_extension=is_double_ext,
            is_executable=is_executable,
            is_script=is_script,
            is_archive=is_archive,
            has_macros=has_macros,
            archive_contents=archive_contents,
            risk_score=min(100.0, risk_score),
            risk_reasons=risk_reasons,
        )

    def _identify_magic_bytes(self, payload: bytes) -> tuple[Optional[str], Optional[str]]:
        """Match initial bytes against known file signatures."""
        for signature, mime, desc in self.MAGIC_SIGNATURES:
            if payload.startswith(signature):
                return mime, desc
        return None, None

    def _check_for_macros(self, payload: bytes, ext: str) -> bool:
        """Scan payload for VBA macro indicators."""
        # 1. OOXML zip format (.docm, .xlsm, .pptm)
        if payload.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as z:
                    for name in z.namelist():
                        if "vbaProject.bin" in name or "word/vbaData.xml" in name:
                            return True
            except Exception:
                pass

        # 2. OLE2 Compound document format (.doc, .xls)
        if payload.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            # Search for typical VBA streams or keywords
            vba_keywords = [b"VBA", b"_VBA_PROJECT", b"AutoOpen", b"Workbook_Open", b"Sub Auto_Open"]
            for kw in vba_keywords:
                if kw in payload:
                    return True

        return False

    def _inspect_zip_contents(self, payload: bytes) -> list[str]:
        """Safely list filenames inside a zip archive without extracting."""
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as z:
                return z.namelist()[:50]  # Cap at 50 to prevent DoS
        except Exception:
            return []
