"""
Embedded Single-Page Interactive SOC Web Dashboard for PhishGuard.
Zero external CDNs or network dependencies (air-gap compatible).
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard SOC — Enterprise Phishing Triage Console</title>
<style>
  :root {
    --bg-base: #0b0f19;
    --bg-surface: #131b2e;
    --bg-surface-elevated: #1a243d;
    --border-color: #24304f;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --accent: #38bdf8;
    --accent-glow: rgba(56, 189, 248, 0.25);
    --danger: #ef4444;
    --danger-glow: rgba(239, 68, 68, 0.25);
    --warning: #f59e0b;
    --success: #10b981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  body { background: var(--bg-base); color: var(--text-primary); line-height: 1.5; min-height: 100vh; padding: 20px; }
  .container { max-width: 1200px; margin: 0 auto; }
  header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 16px; border-bottom: 1px solid var(--border-color); margin-bottom: 24px; }
  .logo { display: flex; align-items: center; gap: 10px; font-size: 22px; font-weight: 800; color: var(--accent); }
  .badge-live { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid var(--success); padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  
  /* Upload Zone */
  .drop-zone {
    background: var(--bg-surface);
    border: 2px dashed var(--border-color);
    border-radius: 12px;
    padding: 35px 20px;
    text-align: center;
    cursor: pointer;
    transition: all 0.2s ease;
    margin-bottom: 25px;
  }
  .drop-zone:hover, .drop-zone.dragover {
    border-color: var(--accent);
    background: rgba(56, 189, 248, 0.04);
    box-shadow: 0 0 20px var(--accent-glow);
  }
  .drop-zone h3 { font-size: 18px; margin-bottom: 6px; color: var(--text-primary); }
  .drop-zone p { color: var(--text-secondary); font-size: 13px; }
  #fileInput { display: none; }

  /* Results Grid */
  #resultsArea { display: none; }
  .grid-header { display: grid; grid-template-columns: 240px 1fr; gap: 20px; margin-bottom: 25px; }
  @media (max-width: 768px) { .grid-header { grid-template-columns: 1fr; } }
  
  .gauge-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 24px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
  }
  .gauge-val { font-size: 48px; font-weight: 900; line-height: 1; margin: 10px 0; }
  .gauge-label { font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }

  .banner-card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 24px;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }
  .banner-title { font-size: 20px; font-weight: 800; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }
  .banner-desc { color: var(--text-secondary); font-size: 14px; margin-bottom: 16px; }
  .actions-row { display: flex; gap: 10px; flex-wrap: wrap; }
  .btn {
    background: var(--bg-surface-elevated);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    padding: 8px 16px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn:hover { background: var(--accent); color: #000; border-color: var(--accent); }

  /* Navigation Tabs */
  .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--border-color); margin-bottom: 20px; }
  .tab-btn {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    padding: 10px 18px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    border-bottom: 2px solid transparent;
  }
  .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

  /* Content Cards */
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  .card { background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 10px; padding: 20px; margin-bottom: 20px; }
  .card h4 { font-size: 15px; font-weight: 700; color: var(--accent); margin-bottom: 12px; }
  
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border-color); }
  th { color: var(--text-secondary); text-transform: uppercase; font-size: 11px; }
  .code { font-family: "SFMono-Regular", Consolas, monospace; color: #a5b4fc; font-size: 12px; }
  .pill { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  .pill.danger { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }
  .pill.warning { background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }
  .pill.success { background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }
  
  /* Loading Spinner */
  #loading { display: none; text-align: center; padding: 40px; }
  .spinner { border: 4px solid var(--border-color); border-top: 4px solid var(--accent); border-radius: 50%; width: 40px; height: 40px; animation: spin 0.8s linear infinite; margin: 0 auto 12px; }
  @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">🛡️ PhishGuard SOC <span style="font-size: 13px; font-weight: 400; color: var(--text-secondary);">Enterprise Triage Console</span></div>
    <div><span class="badge-live">Engine v0.1.0 Active</span></div>
  </header>

  <!-- Upload Area -->
  <div class="drop-zone" id="dropZone" onclick="document.getElementById('fileInput').click()">
    <input type="file" id="fileInput" accept=".eml" onchange="handleFileSelect(event)">
    <h3>Drag and drop an .eml email file here</h3>
    <p>or click to browse from local computer</p>
  </div>

  <div id="loading">
    <div class="spinner"></div>
    <p style="color: var(--text-secondary); font-size: 14px;">Ingesting RFC 5322 MIME tree, running forensics & threat intelligence queries...</p>
  </div>

  <!-- Results Dashboard -->
  <div id="resultsArea">
    <div class="grid-header">
      <div class="gauge-card" id="gaugeCard">
        <div style="font-size: 12px; color: var(--text-secondary); font-weight: 600;">AGGREGATE PHISHSCORE</div>
        <div class="gauge-val" id="scoreVal">--</div>
        <div class="gauge-label" id="verdictLabel">ANALYZING</div>
      </div>
      <div class="banner-card">
        <div class="banner-title" id="bannerTitle">Incident Assessment</div>
        <div class="banner-desc" id="bannerDesc">Loading...</div>
        <div class="actions-row">
          <button class="btn" onclick="downloadJSON()">Export SIEM JSON</button>
          <button class="btn" onclick="downloadSTIX()">Export STIX 2.1</button>
          <button class="btn" onclick="downloadHTML()">Export HTML Report</button>
          <button class="btn" onclick="copyIOCs()">Copy All IOCs</button>
        </div>
      </div>
    </div>

    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab('tabOverview')">Overview & Evidence</button>
      <button class="tab-btn" onclick="switchTab('tabMitre')">MITRE ATT&CK</button>
      <button class="tab-btn" onclick="switchTab('tabHops')">Hop Route Tracer</button>
      <button class="tab-btn" onclick="switchTab('tabURLs')">URLs & Intel</button>
      <button class="tab-btn" onclick="switchTab('tabAttachments')">Attachments</button>
      <button class="tab-btn" onclick="switchTab('tabPlaybook')">Containment Playbook</button>
    </div>

    <!-- Tab 1: Overview -->
    <div id="tabOverview" class="tab-content active">
      <div class="card">
        <h4>Envelope & Authentication</h4>
        <table>
          <tr><td style="width: 140px; font-weight: bold;">Subject</td><td id="mSubject">-</td></tr>
          <tr><td style="font-weight: bold;">From</td><td class="code" id="mFrom">-</td></tr>
          <tr><td style="font-weight: bold;">Reply-To</td><td class="code" id="mReplyTo">-</td></tr>
          <tr><td style="font-weight: bold;">Originating IP</td><td class="code" id="mOrigIP">-</td></tr>
          <tr><td style="font-weight: bold;">Authentication</td><td id="mAuth">-</td></tr>
        </table>
      </div>

      <div class="card">
        <h4>Primary Forensic Indicators</h4>
        <ul id="findingsList" style="padding-left: 20px; color: #fca5a5; font-size: 14px;"></ul>
      </div>
    </div>

    <!-- Tab 2: MITRE ATT&CK -->
    <div id="tabMitre" class="tab-content">
      <div class="card" style="border-left: 4px solid var(--danger);">
        <h4 style="color: var(--danger);">MITRE ATT&CK Framework Adversary Techniques</h4>
        <table>
          <thead><tr><th>Technique ID</th><th>Technique Name</th><th>Tactic</th><th>Confidence</th><th>Forensic Evidence</th></tr></thead>
          <tbody id="mitreBody"></tbody>
        </table>
      </div>
    </div>

    <!-- Tab 3: Hops -->
    <div id="tabHops" class="tab-content">
      <div class="card">
        <h4>Chronological Received Hop Trail (Origin ➔ MX Gateway)</h4>
        <table>
          <thead><tr><th>Hop</th><th>From Host</th><th>By Host</th><th>Transmitting IP</th><th>Latency Delta</th></tr></thead>
          <tbody id="hopsBody"></tbody>
        </table>
      </div>
    </div>

    <!-- Tab 3: URLs -->
    <div id="tabURLs" class="tab-content">
      <div class="card">
        <h4>Extracted URLs & Deception Checks</h4>
        <table>
          <thead><tr><th>Defanged URL</th><th>Anchor Text</th><th>Deception Flag</th><th>Threat Intel</th><th>Risk</th></tr></thead>
          <tbody id="urlsBody"></tbody>
        </table>
      </div>
    </div>

    <!-- Tab 4: Attachments -->
    <div id="tabAttachments" class="tab-content">
      <div class="card">
        <h4>Extracted Attachment Forensics</h4>
        <table>
          <thead><tr><th>Filename</th><th>Size</th><th>Declared MIME</th><th>True Type</th><th>SHA256</th><th>Flags</th></tr></thead>
          <tbody id="attBody"></tbody>
        </table>
      </div>
    </div>

    <!-- Tab 5: Playbook -->
    <div id="tabPlaybook" class="tab-content">
      <div class="card" style="border-left: 4px solid var(--success);">
        <h4 style="color: var(--success);">SOC Analyst Triage & Containment Playbook</h4>
        <ul id="playbookList" style="padding-left: 20px; font-size: 14px; line-height: 1.8;"></ul>
      </div>
    </div>
  </div>
</div>

<script>
let currentResult = null;

const dropZone = document.getElementById('dropZone');
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('dragover'); });
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  if (e.dataTransfer.files.length > 0) uploadFile(e.dataTransfer.files[0]);
});

function handleFileSelect(event) {
  if (event.target.files.length > 0) uploadFile(event.target.files[0]);
}

async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  document.getElementById('loading').style.display = 'block';
  document.getElementById('resultsArea').style.display = 'none';

  try {
    const resp = await fetch('/api/scan', { method: 'POST', body: formData });
    const data = await resp.json();
    currentResult = data;
    renderResults(data);
  } catch (err) {
    alert('Error scanning email: ' + err.message);
  } finally {
    document.getElementById('loading').style.display = 'none';
  }
}

function renderResults(res) {
  document.getElementById('resultsArea').style.display = 'block';
  const score = res.score.total_score;
  const verdict = res.verdict;

  document.getElementById('scoreVal').innerText = score + '/100';
  document.getElementById('verdictLabel').innerText = verdict;
  
  const scoreCard = document.getElementById('gaugeCard');
  if (verdict === 'MALICIOUS') {
    scoreCard.style.borderColor = 'var(--danger)';
    document.getElementById('scoreVal').style.color = 'var(--danger)';
    document.getElementById('verdictLabel').style.color = 'var(--danger)';
  } else if (verdict === 'SUSPICIOUS') {
    scoreCard.style.borderColor = 'var(--warning)';
    document.getElementById('scoreVal').style.color = 'var(--warning)';
    document.getElementById('verdictLabel').style.color = 'var(--warning)';
  } else {
    scoreCard.style.borderColor = 'var(--success)';
    document.getElementById('scoreVal').style.color = 'var(--success)';
    document.getElementById('verdictLabel').style.color = 'var(--success)';
  }

  document.getElementById('bannerTitle').innerText = `Incident Assessment: ${verdict} (${res.severity} Severity)`;
  document.getElementById('bannerDesc').innerText = res.written_explanation.split('\\n')[0];

  // Metadata
  document.getElementById('mSubject').innerText = res.metadata.subject;
  document.getElementById('mFrom').innerText = res.metadata.from_raw;
  document.getElementById('mReplyTo').innerText = res.metadata.reply_to_raw || 'None';
  document.getElementById('mOrigIP').innerText = res.headers.originating_ip || 'Unknown';
  
  const auth = res.headers.auth;
  document.getElementById('mAuth').innerHTML = `SPF: <span class="pill ${auth.spf_status === 'pass' ? 'success' : 'danger'}">${auth.spf_status.toUpperCase()}</span> | DKIM: <span class="pill ${auth.dkim_status === 'pass' ? 'success' : 'warning'}">${auth.dkim_status.toUpperCase()}</span> | DMARC: <span class="pill ${auth.dmarc_status === 'pass' ? 'success' : 'danger'}">${auth.dmarc_status.toUpperCase()}</span>`;

  // Findings
  const findingsList = document.getElementById('findingsList');
  findingsList.innerHTML = res.key_findings.map(f => `<li>${f}</li>`).join('') || '<li>No critical anomalies discovered.</li>';

  // MITRE ATT&CK
  const mitreBody = document.getElementById('mitreBody');
  mitreBody.innerHTML = (res.mitre_attack || []).map(m => `
    <tr>
      <td><a href="${m.attack_url}" target="_blank" class="code" style="color: var(--danger); font-weight: bold; text-decoration: none;">${m.technique_id}</a></td>
      <td><strong>${m.technique_name}</strong></td>
      <td>${m.tactic}</td>
      <td><span class="pill danger">${m.confidence}</span></td>
      <td>${(m.evidence || []).join('; ')}</td>
    </tr>
  `).join('') || '<tr><td colspan="5">No overt adversary techniques mapped.</td></tr>';

  // Hops
  const hopsBody = document.getElementById('hopsBody');
  hopsBody.innerHTML = res.headers.hops.map(h => `
    <tr>
      <td>Hop #${h.hop_index}</td>
      <td>${h.from_host || 'unknown'}</td>
      <td>${h.by_host || 'unknown'}</td>
      <td class="code">${h.client_ip || '-'} ${h.is_private_ip ? '<span class="pill warning">Private</span>' : '<span class="pill danger">Public</span>'}</td>
      <td>${h.delay_from_previous_seconds !== null ? '+' + h.delay_from_previous_seconds + 's' : '-'}</td>
    </tr>
  `).join('') || '<tr><td colspan="5">No hops extracted.</td></tr>';

  // URLs
  const urlsBody = document.getElementById('urlsBody');
  urlsBody.innerHTML = res.urls.map(u => `
    <tr>
      <td class="code">${u.defanged_url}</td>
      <td>${u.anchor_text || '-'}</td>
      <td>${u.is_mismatched_anchor ? '<span class="pill danger">MISMATCH</span>' : (u.is_ip_host ? '<span class="pill warning">IP Host</span>' : 'Standard')}</td>
      <td>${u.threat_intel_flagged ? `<span class="pill danger">${u.threat_intel_source}</span>` : '<span class="pill success">Clean</span>'}</td>
      <td><strong>${u.risk_score}</strong></td>
    </tr>
  `).join('') || '<tr><td colspan="5">No URLs extracted.</td></tr>';

  // Attachments
  const attBody = document.getElementById('attBody');
  attBody.innerHTML = res.attachments.map(a => `
    <tr>
      <td><strong>${a.filename}</strong></td>
      <td>${a.size_bytes} B</td>
      <td>${a.original_mime}</td>
      <td>${a.detected_mime || 'Unknown'}</td>
      <td class="code">${a.sha256.substring(0, 16)}...</td>
      <td>${a.is_executable ? '<span class="pill danger">EXECUTABLE</span>' : (a.has_macros ? '<span class="pill danger">MACRO</span>' : '<span class="pill success">Clean</span>')}</td>
    </tr>
  `).join('') || '<tr><td colspan="6">No attachments present.</td></tr>';

  // Playbook
  const playbookList = document.getElementById('playbookList');
  playbookList.innerHTML = res.remediation_steps.map(s => `<li>${s}</li>`).join('');
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  event.target.classList.add('active');
}

function downloadJSON() {
  if (!currentResult) return;
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `phishguard_${currentResult.scan_id}.json`; a.click();
}

async function downloadSTIX() {
  if (!currentResult) return;
  const resp = await fetch(`/api/export/stix?scan_id=${currentResult.scan_id}`);
  const stixData = await resp.text();
  const blob = new Blob([stixData], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `stix21_${currentResult.scan_id}.json`; a.click();
}

async function downloadHTML() {
  if (!currentResult) return;
  const resp = await fetch(`/api/export/html?scan_id=${currentResult.scan_id}`);
  const htmlData = await resp.text();
  const blob = new Blob([htmlData], { type: 'text/html' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `report_${currentResult.scan_id}.html`; a.click();
}

async function copyIOCs() {
  if (!currentResult) return;
  const resp = await fetch(`/api/export/csv?scan_id=${currentResult.scan_id}`);
  const csvData = await resp.text();
  navigator.clipboard.writeText(csvData);
  alert('All IOCs copied to clipboard in CSV format!');
}
</script>
</body>
</html>
"""
