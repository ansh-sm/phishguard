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
      <button class="tab-btn" onclick="switchTab('tabAttachments')">Attachments & YARA</button>
      <button class="tab-btn" onclick="switchTab('tabPlaybook')">Containment Playbook</button>
      <button class="tab-btn" onclick="switchTab('tabRemediation')">⚡ SOAR Playbooks</button>
      <button class="tab-btn" onclick="switchTab('tabHunting')">🔍 Threat Hunting</button>
      <button class="tab-btn" onclick="switchTab('tabCampaigns')">🌐 Threat Campaigns & Graph</button>
      <button class="tab-btn" onclick="switchTab('tabSiem')">📡 SIEM Streaming</button>
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

    <!-- Tab 6: SOAR Remediation -->
    <div id="tabRemediation" class="tab-content">
      <div class="card" style="border-left: 4px solid var(--accent);">
        <h4 style="color: var(--accent); margin-bottom: 12px;">Automated Multi-Platform SOAR Containment Playbooks</h4>
        <div id="remediationList" style="display: flex; flex-direction: column; gap: 16px;"></div>
      </div>
    </div>

    <!-- Tab 7: Threat Hunting -->
    <div id="tabHunting" class="tab-content">
      <div class="card" style="border-left: 4px solid var(--warning);">
        <h4 style="color: var(--warning); margin-bottom: 12px;">SOC Threat Hunting & Historical Incident Search</h4>
        <div style="display: flex; gap: 10px; margin-bottom: 16px;">
          <input id="huntSearch" type="text" placeholder="Search by domain, sender, IP, or keyword (e.g. PayPal, 185.220...)" style="flex: 1; padding: 10px; background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 6px;">
          <button class="btn" onclick="executeHunt()" style="background: var(--accent); color: #0b0f19; font-weight: 700;">Search</button>
        </div>
        <table>
          <thead><tr><th>Scan ID</th><th>Timestamp</th><th>Sender</th><th>Subject</th><th>Origin IP</th><th>Score</th><th>Verdict</th></tr></thead>
          <tbody id="huntBody"><tr><td colspan="7" style="color: var(--text-secondary);">Click Search or enter a query to hunt past incidents.</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- Tab 8: Threat Campaigns & Graph -->
    <div id="tabCampaigns" class="tab-content">
      <div class="card" style="border-left: 4px solid var(--danger);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h4 style="color: var(--danger); margin: 0;">Correlated Adversary Threat Campaigns</h4>
          <button class="btn" onclick="loadCampaigns()" style="background: var(--accent); color: #0b0f19;">Refresh Campaigns</button>
        </div>
        <table>
          <thead><tr><th>Campaign ID</th><th>Campaign Name</th><th>Risk</th><th>Incidents</th><th>Victims</th><th>Shared IOCs</th><th>Action</th></tr></thead>
          <tbody id="campaignsBody"><tr><td colspan="7" style="color: var(--text-secondary);">Click Refresh Campaigns to correlate clusters.</td></tr></tbody>
        </table>
      </div>

      <div class="card" style="border-left: 4px solid #a855f7;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h4 style="color: #a855f7; margin: 0;">Incident Attack Graph Topology (Mermaid)</h4>
          <button class="btn" onclick="navigator.clipboard.writeText(document.getElementById('graphMermaidCode').innerText); alert('Copied Mermaid syntax!');">Copy Graph</button>
        </div>
        <pre id="graphMermaidCode" style="background: var(--bg-base); padding: 14px; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 12px; color: #c084fc; max-height: 250px;">Upload an email or select a campaign to render attack topology.</pre>
      </div>
    </div>

    <!-- Tab 9: SIEM Streaming -->
    <div id="tabSiem" class="tab-content">
      <div class="card" style="border-left: 4px solid var(--accent);">
        <h4 style="color: var(--accent); margin-bottom: 12px;">Stream Incident Telemetry to Enterprise SIEM</h4>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
          <div>
            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Target SIEM</label>
            <select id="siemTarget" style="width: 100%; padding: 8px; background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 6px;">
              <option value="splunk">Splunk HEC (HTTP Event Collector)</option>
              <option value="elastic">Elasticsearch (ECS 8.x Ingestion)</option>
              <option value="sentinel">Microsoft Sentinel (Log Analytics API)</option>
              <option value="webhook">Generic Webhook / SOAR Collector</option>
            </select>
          </div>
          <div>
            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Collector / Ingestion URL</label>
            <input id="siemUrl" type="text" placeholder="https://splunk.corp.com:8088/services/collector/event" style="width: 100%; padding: 8px; background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 6px;">
          </div>
          <div>
            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Auth Token / API Key</label>
            <input id="siemToken" type="password" placeholder="HEC Token or ApiKey secret" style="width: 100%; padding: 8px; background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 6px;">
          </div>
          <div>
            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Index / Dataset Name</label>
            <input id="siemIndex" type="text" value="phishguard_threats" style="width: 100%; padding: 8px; background: var(--bg-base); border: 1px solid var(--border-color); color: var(--text-primary); border-radius: 6px;">
          </div>
        </div>
        <div style="display: flex; gap: 10px; margin-bottom: 14px;">
          <button class="btn" onclick="testSiem()" style="background: var(--bg-surface-elevated); border: 1px solid var(--accent); color: var(--accent);">Test SIEM Connection</button>
          <button class="btn" onclick="forwardSiem()" style="background: var(--accent); color: #0b0f19; font-weight: 700;">Forward Active Incident</button>
        </div>
        <div id="siemLog" style="background: var(--bg-base); padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; color: var(--text-secondary); min-height: 50px;">Awaiting forwarding or diagnostic test...</div>
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

  // Load SOAR Remediation & Attack Graph
  loadRemediation(res.scan_id);
  loadIncidentGraph(res.scan_id);
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

async function loadRemediation(scanId) {
  const container = document.getElementById('remediationList');
  try {
    const resp = await fetch(`/api/remediate/${scanId}`);
    const data = await resp.json();
    if (!data.actions || data.actions.length === 0) {
      container.innerHTML = '<p style="color: var(--text-secondary);">No automated playbooks generated.</p>';
      return;
    }
    container.innerHTML = data.actions.map((act, idx) => `
      <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-color); border-radius: 8px; padding: 14px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <div>
            <strong style="color: var(--accent);">${act.name}</strong> 
            <span class="pill danger" style="margin-left: 8px;">${act.platform.toUpperCase()}</span>
            <span class="pill warning">${act.category}</span>
          </div>
          <button class="btn" onclick="navigator.clipboard.writeText(document.getElementById('code_${idx}').innerText); alert('Copied script to clipboard!');">Copy Script</button>
        </div>
        <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 8px;">${act.description}</p>
        <pre style="background: var(--bg-base); padding: 12px; border-radius: 6px; overflow-x: auto; font-family: monospace; font-size: 12px; color: #a5b4fc;"><code id="code_${idx}">${act.code.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></pre>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = '<p style="color: var(--danger);">Failed to load remediation playbooks.</p>';
  }
}

async function executeHunt() {
  const q = document.getElementById('huntSearch').value.trim();
  const huntBody = document.getElementById('huntBody');
  huntBody.innerHTML = '<tr><td colspan="7">Searching SOC database...</td></tr>';
  try {
    const resp = await fetch(`/api/hunt?query=${encodeURIComponent(q)}`);
    const data = await resp.json();
    if (!data.results || data.results.length === 0) {
      huntBody.innerHTML = '<tr><td colspan="7" style="color: var(--warning);">No historical incidents found.</td></tr>';
      return;
    }
    huntBody.innerHTML = data.results.map(r => `
      <tr>
        <td class="code" style="color: var(--accent); font-weight: bold;">${r.scan_id}</td>
        <td>${r.timestamp.substring(0, 19).replace('T', ' ')}</td>
        <td>${r.from_email}</td>
        <td>${r.subject}</td>
        <td class="code">${r.originating_ip || '-'}</td>
        <td><strong>${r.total_score}</strong></td>
        <td><span class="pill ${r.verdict === 'MALICIOUS' ? 'danger' : (r.verdict === 'SUSPICIOUS' ? 'warning' : 'success')}">${r.verdict}</span></td>
      </tr>
    `).join('');
  } catch (err) {
    huntBody.innerHTML = '<tr><td colspan="7" style="color: var(--danger);">Error executing hunt query.</td></tr>';
  }
}

async function loadIncidentGraph(scanId) {
  try {
    const resp = await fetch(`/api/graph/${scanId}`);
    if (!resp.ok) return;
    const data = await resp.json();
    document.getElementById('graphMermaidCode').innerText = data.mermaid;
  } catch (e) {}
}

async function loadCampaigns() {
  const body = document.getElementById('campaignsBody');
  body.innerHTML = '<tr><td colspan="7">Correlating historical attack clusters...</td></tr>';
  try {
    const resp = await fetch('/api/campaigns?min_size=1');
    const data = await resp.json();
    if (!data.campaigns || data.campaigns.length === 0) {
      body.innerHTML = '<tr><td colspan="7" style="color: var(--warning);">No correlated threat campaigns found.</td></tr>';
      return;
    }
    body.innerHTML = data.campaigns.map((c, idx) => `
      <tr>
        <td class="code" style="color: var(--danger); font-weight: bold;">${c.campaign_id}</td>
        <td><strong>${c.name}</strong></td>
        <td><span class="pill danger">${c.risk_score}</span></td>
        <td>${c.incident_ids.length}</td>
        <td>${c.victim_count}</td>
        <td class="code" style="font-size: 11px;">${(c.shared_iocs || []).slice(0, 2).join(', ') || 'None'}</td>
        <td><button class="btn" style="padding: 4px 8px; font-size: 11px;" onclick="renderCampaignGraph(${idx})">View Graph</button></td>
      </tr>
    `).join('');
    window._lastCampaigns = data.campaigns;
    if (data.campaigns.length > 0) renderCampaignGraph(0);
  } catch (err) {
    body.innerHTML = '<tr><td colspan="7" style="color: var(--danger);">Error loading campaigns.</td></tr>';
  }
}

function renderCampaignGraph(idx) {
  if (!window._lastCampaigns || !window._lastCampaigns[idx]) return;
  const c = window._lastCampaigns[idx];
  if (c.graph) {
    // Generate mermaid from graph object if available
    let mm = 'flowchart LR\\n';
    c.graph.nodes.forEach(n => {
      const clean = n.id.replace(/[^a-zA-Z0-9_]/g, '_');
      mm += `    n_${clean}["${n.label.replace(/"/g, "'")}"]\\n`;
    });
    c.graph.edges.forEach(e => {
      const src = e.source.replace(/[^a-zA-Z0-9_]/g, '_');
      const tgt = e.target.replace(/[^a-zA-Z0-9_]/g, '_');
      mm += `    n_${src} -->|"${e.relationship}"| n_${tgt}\\n`;
    });
    document.getElementById('graphMermaidCode').innerText = mm;
  }
}

async function testSiem() {
  const log = document.getElementById('siemLog');
  const target = document.getElementById('siemTarget').value;
  const url = document.getElementById('siemUrl').value.trim();
  const token = document.getElementById('siemToken').value.trim();
  const index = document.getElementById('siemIndex').value.trim();

  if (!url) { alert('Please provide a SIEM Endpoint URL'); return; }

  log.innerText = `Testing connection to ${target.toUpperCase()} at ${url}...`;
  try {
    const resp = await fetch('/api/siem/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_type: target,
        endpoint_url: url,
        auth_token: token || null,
        index_name: index || 'phishguard_threats'
      })
    });
    const data = await resp.json();
    if (data.success) {
      log.innerHTML = `<span style="color: var(--success); font-weight: bold;">✓ Connection SUCCESS (HTTP ${data.status_code})</span>\\n${data.response_body}`;
    } else {
      log.innerHTML = `<span style="color: var(--danger); font-weight: bold;">✗ Connection FAILED:</span> ${data.error_message}`;
    }
  } catch (err) {
    log.innerHTML = `<span style="color: var(--danger);">Error: ${err.message}</span>`;
  }
}

async function forwardSiem() {
  const log = document.getElementById('siemLog');
  if (!currentResult) { alert('Please upload and triage an email before forwarding.'); return; }

  const target = document.getElementById('siemTarget').value;
  const url = document.getElementById('siemUrl').value.trim();
  const token = document.getElementById('siemToken').value.trim();
  const index = document.getElementById('siemIndex').value.trim();

  if (!url) { alert('Please provide a SIEM Endpoint URL'); return; }

  log.innerText = `Streaming incident ${currentResult.scan_id} to ${target.toUpperCase()}...`;
  try {
    const resp = await fetch('/api/siem/forward', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scan_id: currentResult.scan_id,
        config: {
          target_type: target,
          endpoint_url: url,
          auth_token: token || null,
          index_name: index || 'phishguard_threats'
        }
      })
    });
    const data = await resp.json();
    if (data.success) {
      log.innerHTML = `<span style="color: var(--success); font-weight: bold;">✓ Incident Streamed (HTTP ${data.status_code})</span>\\nEvent ID: ${currentResult.scan_id}\\nEvents Delivered: ${data.events_forwarded}\\nServer Response: ${data.response_body}`;
    } else {
      log.innerHTML = `<span style="color: var(--danger); font-weight: bold;">✗ Forwarding FAILED:</span> ${data.error_message}`;
    }
  } catch (err) {
    log.innerHTML = `<span style="color: var(--danger);">Error: ${err.message}</span>`;
  }
}
</script>
</body>
</html>
"""
