"""
Unit tests for binary YARA pattern scanner on attachment payloads.
"""

from phishguard.forensics.yara_scanner import YaraScanner


def test_yara_detect_disguised_pe():
    scanner = YaraScanner()
    # Mock PE binary with MZ header and PE signature at offset 0x80
    pe_payload = b"MZ" + b"\x00" * 126 + b"PE\x00\x00" + b"\x00" * 500
    matches = scanner.scan_bytes(pe_payload, filename="invoice.pdf")
    rule_names = [m.rule_name for m in matches]

    assert "YARA_DISGUISED_PE_BINARY" in rule_names
    m = next(m for m in matches if m.rule_name == "YARA_DISGUISED_PE_BINARY")
    assert m.severity == "CRITICAL"


def test_yara_detect_injection_apis():
    scanner = YaraScanner()
    payload = b"MZ\x00\x00" + b"Some payload text... VirtualAlloc ... WriteProcessMemory ... CreateRemoteThread"
    matches = scanner.scan_bytes(payload)
    rule_names = [m.rule_name for m in matches]

    assert "YARA_SUSPICIOUS_MEMORY_INJECTION_APIS" in rule_names
    m = next(m for m in matches if m.rule_name == "YARA_SUSPICIOUS_MEMORY_INJECTION_APIS")
    assert "VirtualAlloc" in m.matched_indicators
    assert "WriteProcessMemory" in m.matched_indicators


def test_yara_detect_powershell_stager():
    scanner = YaraScanner()
    payload = b"powershell.exe -nop -w hidden -enc JAB3AGM..."
    matches = scanner.scan_bytes(payload)
    rule_names = [m.rule_name for m in matches]

    assert "YARA_OBFUSCATED_POWERSHELL_STAGER" in rule_names


def test_yara_detect_pdf_active_content():
    scanner = YaraScanner()
    pdf_payload = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('XSS');) >> >>\nendobj"
    matches = scanner.scan_bytes(pdf_payload, filename="document.pdf")
    rule_names = [m.rule_name for m in matches]

    assert "YARA_PDF_SUSPICIOUS_ACTIVE_CONTENT" in rule_names


def test_yara_detect_vba_autoexec():
    scanner = YaraScanner()
    vba_payload = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00Sub AutoOpen()\nShellExecute 0, \"open\", \"calc.exe\", \"\", \"\", 1\nEnd Sub"
    matches = scanner.scan_bytes(vba_payload, filename="order.docm")
    rule_names = [m.rule_name for m in matches]

    assert "YARA_VBA_AUTOEXEC_STAGER" in rule_names


def test_yara_detect_lnk_stager():
    scanner = YaraScanner()
    lnk_header = b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 30 + b"cmd.exe /c powershell -enc ..."
    matches = scanner.scan_bytes(lnk_header, filename="invoice.lnk")
    rule_names = [m.rule_name for m in matches]

    assert "YARA_LNK_BINARY_COMMAND_STAGER" in rule_names
    m = next(m for m in matches if m.rule_name == "YARA_LNK_BINARY_COMMAND_STAGER")
    assert m.severity == "CRITICAL"
