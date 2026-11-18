"""
Standalone Executive HTML SOC Incident Report Generator.
"""

import html
from pathlib import Path
from typing import Optional

from phishguard.models.report import ScanResult, VerdictEnum


class HtmlReporter:
    """
    Generates a responsive, standalone HTML SOC Incident Report with zero external dependencies.
    """

    def generate(self, result: ScanResult, output_path: Optional[Path] = None) -> str:
        """Render ScanResult into standalone HTML report."""
        verdict = result.verdict.value
        severity = result.severity.value
        score = result.score.total_score

        badge_color = "#e53e3e" if verdict == "MALICIOUS" else ("#dd6b20" if verdict == "SUSPICIOUS" else "#38a169")
        badge_bg = "rgba(229, 62, 62, 0.15)" if verdict == "MALICIOUS" else ("rgba(221, 107, 32, 0.15)" if verdict == "SUSPICIOUS" else "rgba(56, 161, 105, 0.15)")

        # Escape strings safely
        subject_esc = html.escape(result.metadata.subject)
        from_esc = html.escape(result.metadata.from_raw)
        to_esc = html.escape(", ".join(result.metadata.to_emails) or "(None)")
        date_esc = html.escape(result.metadata.date or "(Unknown)")
        orig_ip_esc = html.escape(result.headers.originating_ip or "(Unknown)")
        explanation_esc = html.escape(result.written_explanation).replace("\n", "<br>")

        # Rows for URLs
        url_rows = []
        for u in result.urls:
            intel_label = f"<span class='badge danger'>{html.escape(u.threat_intel_source)}</span>" if u.threat_intel_flagged else "<span class='badge success'>Clean</span>"
            deception_label = "<span class='badge danger'>MISMATCH</span>" if u.is_mismatched_anchor else ("<span class='badge warning'>IP Host</span>" if u.is_ip_host else "Standard")
            url_rows.append(f"""
                <tr>
                    <td class="code">{html.escape(u.defanged_url)}</td>
                    <td>{html.escape(u.anchor_text or "-")}</td>
                    <td>{deception_label}</td>
                    <td>{intel_label}</td>
                    <td><strong>{u.risk_score}</strong></td>
                </tr>
            """)
        urls_table_html = "".join(url_rows) if url_rows else "<tr><td colspan='5' class='text-muted'>No external URLs extracted.</td></tr>"

        # Rows for Hops
        hop_rows = []
        for h in result.headers.hops:
            delay = f"+{h.delay_from_previous_seconds}s" if h.delay_from_previous_seconds is not None else "-"
            scope = "<span class='badge warning'>Private</span>" if h.is_private_ip else "<span class='badge danger'>Public Egress</span>"
            hop_rows.append(f"""
                <tr>
                    <td>Hop #{h.hop_index}</td>
                    <td>{html.escape(h.from_host or "unknown")}</td>
                    <td>{html.escape(h.by_host or "unknown")}</td>
                    <td class="code">{html.escape(h.client_ip or "-")} {scope}</td>
                    <td>{delay}</td>
                </tr>
            """)
        hops_table_html = "".join(hop_rows) if hop_rows else "<tr><td colspan='5' class='text-muted'>No Received headers found.</td></tr>"

        # Rows for Attachments
        att_rows = []
        for a in result.attachments:
            flags = []
            if a.is_executable: flags.append("EXECUTABLE")
            if a.is_double_extension: flags.append("DOUBLE_EXT")
            if a.has_macros: flags.append("VBA_MACRO")
            flag_badges = " ".join([f"<span class='badge danger'>{f}</span>" for f in flags]) if flags else "<span class='badge success'>Clean</span>"
            att_rows.append(f"""
                <tr>
                    <td><strong>{html.escape(a.filename)}</strong></td>
                    <td>{a.size_bytes} B</td>
                    <td>{html.escape(a.original_mime)}</td>
                    <td class="code">{html.escape(a.sha256[:16])}...</td>
                    <td>{flag_badges}</td>
                </tr>
            """)
        att_table_html = "".join(att_rows) if att_rows else "<tr><td colspan='5' class='text-muted'>No attachments present.</td></tr>"

        # Rows for MITRE ATT&CK
        mitre_rows = []
        for t in result.mitre_attack:
            evidence_str = html.escape("; ".join(t.evidence[:2]))
            mitre_rows.append(f"""
                <tr>
                    <td><a href="{html.escape(t.attack_url)}" target="_blank" class="code" style="color: var(--danger); font-weight: bold; text-decoration: none;">{html.escape(t.technique_id)}</a></td>
                    <td><strong>{html.escape(t.technique_name)}</strong></td>
                    <td>{html.escape(t.tactic)}</td>
                    <td>{evidence_str}</td>
                </tr>
            """)
        mitre_table_html = "".join(mitre_rows) if mitre_rows else "<tr><td colspan='4' class='text-muted'>No overt adversary techniques mapped.</td></tr>"

        # Findings items
        findings_html = "".join([f"<li>{html.escape(f)}</li>" for f in result.key_findings]) or "<li>No critical security anomalies discovered.</li>"

        # Remediation items
        remediation_html = "".join([f"<li>{html.escape(s)}</li>" for s in result.remediation_steps])

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard SOC Incident Report - {html.escape(result.scan_id)}</title>
<style>
  :root {{
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --card-bg: #1e293b;
    --border-color: #334155;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --accent-blue: #38bdf8;
    --danger: #ef4444;
    --warning: #f59e0b;
    --success: #10b981;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  body {{ background-color: var(--bg-primary); color: var(--text-primary); padding: 30px 15px; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; border-bottom: 1px solid var(--border-color); padding-bottom: 20px; }}
  .logo {{ font-size: 24px; font-weight: 800; color: var(--accent-blue); display: flex; align-items: center; gap: 8px; }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 700; text-transform: uppercase; }}
  .badge.danger {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
  .badge.warning {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }}
  .badge.success {{ background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }}
  .banner {{ background: {badge_bg}; border: 1px solid {badge_color}; border-left: 6px solid {badge_color}; border-radius: 8px; padding: 20px; margin-bottom: 25px; }}
  .banner-title {{ font-size: 20px; font-weight: 800; color: {badge_color}; margin-bottom: 8px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; margin-bottom: 25px; }}
  .card {{ background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; }}
  .card-title {{ font-size: 16px; font-weight: 700; margin-bottom: 15px; color: var(--accent-blue); display: flex; justify-content: space-between; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
  th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border-color); }}
  th {{ background: #0f172a; color: var(--text-secondary); text-transform: uppercase; font-size: 11px; }}
  .code {{ font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; color: #a5b4fc; word-break: break-all; }}
  ul {{ padding-left: 20px; margin-top: 10px; }}
  li {{ margin-bottom: 8px; color: #cbd5e1; }}
  .text-muted {{ color: var(--text-secondary); font-style: italic; }}
  .score-gauge {{ font-size: 38px; font-weight: 900; color: {badge_color}; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">🛡️ PhishGuard SOC <span style="font-size: 14px; font-weight: 400; color: var(--text-secondary);">Enterprise Forensics</span></div>
    <div>Scan ID: <span class="code">{html.escape(result.scan_id)}</span></div>
  </div>

  <div class="banner">
    <div class="banner-title">VERDICT: {verdict} ({severity} SEVERITY)</div>
    <div style="font-size: 15px;">{explanation_esc}</div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Risk Matrix & Score <span class="score-gauge">{score}/100</span></div>
      <table>
        <tr><td>Header & Spoofing</td><td style="text-align: right;"><strong>{result.score.header_score}</strong> / 30.0</td></tr>
        <tr><td>URL & Threat Intel</td><td style="text-align: right;"><strong>{result.score.url_score}</strong> / 35.0</td></tr>
        <tr><td>Attachment Forensics</td><td style="text-align: right;"><strong>{result.score.attachment_score}</strong> / 20.0</td></tr>
        <tr><td>Content & Urgency</td><td style="text-align: right;"><strong>{result.score.content_score}</strong> / 15.0</td></tr>
        <tr><td><strong>Confidence Level</strong></td><td style="text-align: right;"><strong>{result.confidence_percentage}%</strong></td></tr>
      </table>
    </div>

    <div class="card">
      <div class="card-title">Message Envelope & Authentication</div>
      <table>
        <tr><td><strong>Subject</strong></td><td>{subject_esc}</td></tr>
        <tr><td><strong>From</strong></td><td class="code">{from_esc}</td></tr>
        <tr><td><strong>To</strong></td><td>{to_esc}</td></tr>
        <tr><td><strong>Date</strong></td><td>{date_esc}</td></tr>
        <tr><td><strong>Originating IP</strong></td><td class="code">{orig_ip_esc}</td></tr>
        <tr><td><strong>Auth Results</strong></td><td>SPF: <strong>{result.headers.auth.spf_status.value.upper()}</strong> | DKIM: <strong>{result.headers.auth.dkim_status.value.upper()}</strong> | DMARC: <strong>{result.headers.auth.dmarc_status.value.upper()}</strong></td></tr>
      </table>
    </div>
  </div>

  <div class="card" style="margin-bottom: 25px;">
    <div class="card-title">Forensic Evidence & Key Findings</div>
    <ul style="color: #fca5a5;">
      {findings_html}
    </ul>
  </div>

  <div class="card" style="margin-bottom: 25px;">
    <div class="card-title">Extracted URLs & Threat Intelligence</div>
    <table>
      <thead>
        <tr><th>Defanged URL</th><th>Anchor Text</th><th>Deception Flag</th><th>Threat Intel</th><th>Risk</th></tr>
      </thead>
      <tbody>
        {urls_table_html}
      </tbody>
    </table>
  </div>

  <div class="card" style="margin-bottom: 25px;">
    <div class="card-title">Chronological Hop Route (Origin ➔ MX Gateway)</div>
    <table>
      <thead>
        <tr><th>Hop</th><th>From Host</th><th>By Host</th><th>Transmitting IP</th><th>Latency</th></tr>
      </thead>
      <tbody>
        {hops_table_html}
      </tbody>
    </table>
  </div>

  <div class="card" style="margin-bottom: 25px;">
    <div class="card-title">Extracted Attachments Forensics</div>
    <table>
      <thead>
        <tr><th>Filename</th><th>Size</th><th>Declared MIME</th><th>SHA256</th><th>Forensic Flags</th></tr>
      </thead>
      <tbody>
        {att_table_html}
      </tbody>
    </table>
  </div>

  <div class="card" style="margin-bottom: 25px; border-left: 4px solid var(--danger);">
    <div class="card-title" style="color: var(--danger);">MITRE ATT&CK Enterprise Matrix Mapping</div>
    <table>
      <thead>
        <tr><th>Technique ID</th><th>Technique Name</th><th>Tactic</th><th>Forensic Evidence</th></tr>
      </thead>
      <tbody>
        {mitre_table_html}
      </tbody>
    </table>
  </div>

  <div class="card" style="border-left: 4px solid var(--success);">
    <div class="card-title" style="color: var(--success);">SOC Analyst Triage & Containment Playbook</div>
    <ul>
      {remediation_html}
    </ul>
  </div>
</div>
</body>
</html>
"""
        if output_path:
            path = Path(output_path).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html_doc, encoding="utf-8")

        return html_doc
