#!/usr/bin/env python3
"""
Claw Breaker — Report Dashboard Server
Serves scan results as a live visual dashboard.
"""

import json
import os
import sys
import time
import asyncio
from pathlib import Path

# Add parent to path for claw_breaker import
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from claw_breaker import run_scan, PROBES

app = FastAPI(title="Claw Breaker", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Store latest scan result in memory
latest_report = {"status": "idle", "data": None}

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CLAW BREAKER — OpenClaw Security Scanner</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg-void: #05060a;
  --bg-panel: #0a0d14;
  --bg-card: #0f1219;
  --bg-card-hover: #141822;
  --border: #1a1f2e;
  --border-bright: #252b3d;
  --text-primary: #e8eaf0;
  --text-secondary: #7a8199;
  --text-dim: #454d66;
  --accent-red: #ff3b4f;
  --accent-red-glow: rgba(255,59,79,0.15);
  --accent-green: #00e676;
  --accent-green-glow: rgba(0,230,118,0.12);
  --accent-yellow: #ffab00;
  --accent-yellow-glow: rgba(255,171,0,0.12);
  --accent-cyan: #00e5ff;
  --accent-orange: #ff6d00;
  --accent-purple: #b388ff;
  --font-mono: 'JetBrains Mono', monospace;
  --font-sans: 'Space Grotesk', sans-serif;
}

* { margin:0; padding:0; box-sizing:border-box; }

body {
  background: var(--bg-void);
  color: var(--text-primary);
  font-family: var(--font-sans);
  min-height: 100vh;
  overflow-x: hidden;
}

/* Scanline overlay */
body::after {
  content: '';
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
  pointer-events: none;
  z-index: 9999;
}

.container {
  max-width: 1100px;
  margin: 0 auto;
  padding: 24px 20px;
}

/* ── Header ── */
.header {
  text-align: center;
  padding: 48px 0 36px;
  position: relative;
}

.header::before {
  content: '';
  position: absolute;
  top: 0; left: 50%;
  transform: translateX(-50%);
  width: 300px; height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent-red), transparent);
}

.logo-text {
  font-family: var(--font-mono);
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 6px;
  text-transform: uppercase;
  color: var(--accent-red);
  margin-bottom: 8px;
}

.title {
  font-family: var(--font-mono);
  font-size: 36px;
  font-weight: 800;
  letter-spacing: -0.5px;
  background: linear-gradient(135deg, #fff 0%, var(--text-secondary) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.subtitle {
  font-size: 14px;
  color: var(--text-secondary);
  margin-top: 8px;
  font-weight: 400;
}

/* ── Scan Form ── */
.scan-form {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
  margin: 24px 0;
  display: flex;
  gap: 12px;
  align-items: end;
  flex-wrap: wrap;
}

.form-group {
  flex: 1;
  min-width: 200px;
}

.form-group label {
  display: block;
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--text-dim);
  margin-bottom: 6px;
}

.form-group input {
  width: 100%;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 14px;
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: 13px;
  outline: none;
  transition: border-color 0.2s;
}

.form-group input:focus {
  border-color: var(--accent-red);
}

.scan-btn {
  background: var(--accent-red);
  color: #fff;
  border: none;
  border-radius: 8px;
  padding: 12px 28px;
  font-family: var(--font-mono);
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 1px;
  text-transform: uppercase;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}

.scan-btn:hover { background: #e6293c; transform: translateY(-1px); }
.scan-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
.scan-btn.scanning { animation: pulse 1.5s infinite; }

@keyframes pulse {
  0%,100% { box-shadow: 0 0 0 0 var(--accent-red-glow); }
  50% { box-shadow: 0 0 20px 8px var(--accent-red-glow); }
}

/* ── Risk Banner ── */
.risk-banner {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 28px 32px;
  margin: 20px 0;
  display: flex;
  align-items: center;
  gap: 28px;
  position: relative;
  overflow: hidden;
}

.risk-banner.critical { border-color: rgba(255,59,79,0.3); }
.risk-banner.high { border-color: rgba(255,171,0,0.3); }
.risk-banner.medium { border-color: rgba(255,109,0,0.3); }
.risk-banner.low { border-color: rgba(0,230,118,0.3); }

.risk-banner.critical::before {
  content: '';
  position: absolute;
  inset: 0;
  background: radial-gradient(ellipse at 0% 50%, var(--accent-red-glow), transparent 60%);
}

.risk-ring {
  position: relative;
  width: 100px;
  height: 100px;
  flex-shrink: 0;
}

.risk-ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
.risk-ring circle { fill: none; stroke-width: 6; stroke-linecap: round; }
.risk-ring .track { stroke: var(--border); }
.risk-ring .fill { transition: stroke-dashoffset 1s ease, stroke 0.3s; }

.risk-pct {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-family: var(--font-mono);
  font-size: 24px;
  font-weight: 800;
}

.risk-pct small {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--text-dim);
}

.risk-meta { position: relative; z-index: 1; }
.risk-meta h2 { font-family: var(--font-mono); font-size: 20px; font-weight: 700; margin-bottom: 4px; }
.risk-meta p { font-size: 13px; color: var(--text-secondary); }

.stats-row {
  display: flex;
  gap: 20px;
  margin-top: 12px;
}

.stat-chip {
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 600;
  padding: 4px 10px;
  border-radius: 6px;
  background: var(--bg-card);
  border: 1px solid var(--border);
}

.stat-chip.vuln { color: var(--accent-red); border-color: rgba(255,59,79,0.2); }
.stat-chip.safe { color: var(--accent-green); border-color: rgba(0,230,118,0.2); }

/* ── Findings Grid ── */
.findings-title {
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-dim);
  margin: 32px 0 16px;
}

.finding-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px 22px;
  margin-bottom: 10px;
  transition: all 0.15s;
  cursor: pointer;
}

.finding-card:hover { background: var(--bg-card-hover); border-color: var(--border-bright); }

.finding-card.vuln { border-left: 3px solid var(--accent-red); }
.finding-card.safe { border-left: 3px solid var(--accent-green); }
.finding-card.err { border-left: 3px solid var(--accent-yellow); }

.finding-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.finding-id {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  color: var(--text-dim);
  background: var(--bg-panel);
  padding: 3px 8px;
  border-radius: 4px;
}

.finding-name {
  font-family: var(--font-mono);
  font-size: 14px;
  font-weight: 600;
  flex: 1;
}

.finding-sev {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 1px;
  padding: 3px 10px;
  border-radius: 4px;
}

.finding-sev.CRITICAL { background: rgba(255,59,79,0.15); color: var(--accent-red); }
.finding-sev.HIGH { background: rgba(255,171,0,0.12); color: var(--accent-yellow); }
.finding-sev.MEDIUM { background: rgba(255,109,0,0.12); color: var(--accent-orange); }
.finding-sev.LOW { background: rgba(0,229,255,0.1); color: var(--accent-cyan); }
.finding-sev.INFO { background: rgba(122,129,153,0.1); color: var(--text-secondary); }

.finding-status {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  padding: 3px 8px;
  border-radius: 4px;
}

.finding-status.VULNERABLE { background: rgba(255,59,79,0.12); color: var(--accent-red); }
.finding-status.SAFE { background: rgba(0,230,118,0.1); color: var(--accent-green); }
.finding-status.ERROR { background: rgba(255,171,0,0.1); color: var(--accent-yellow); }

.finding-latency {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-dim);
}

.finding-details {
  display: none;
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px solid var(--border);
}

.finding-card.expanded .finding-details { display: block; }

.detail-label {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--text-dim);
  margin-bottom: 4px;
  margin-top: 10px;
}

.detail-label:first-child { margin-top: 0; }

.detail-text {
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.5;
}

.evidence-block {
  background: var(--bg-void);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--accent-yellow);
  white-space: pre-wrap;
  word-break: break-all;
  overflow-x: auto;
  margin-top: 4px;
}

.remediation-block {
  background: rgba(0,230,118,0.05);
  border: 1px solid rgba(0,230,118,0.15);
  border-radius: 6px;
  padding: 10px 14px;
  font-size: 12px;
  color: var(--accent-green);
  line-height: 1.5;
  margin-top: 4px;
}

/* ── Loading / Idle ── */
.state-msg {
  text-align: center;
  padding: 60px 20px;
  color: var(--text-dim);
  font-family: var(--font-mono);
  font-size: 14px;
}

.state-msg .spinner {
  width: 32px; height: 32px;
  border: 3px solid var(--border);
  border-top-color: var(--accent-red);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  margin: 0 auto 16px;
}

@keyframes spin { to { transform: rotate(360deg); } }

/* ── Footer ── */
.footer {
  text-align: center;
  padding: 40px 0 24px;
  font-size: 12px;
  color: var(--text-dim);
  font-family: var(--font-mono);
}

.footer a { color: var(--accent-red); text-decoration: none; }
.footer a:hover { text-decoration: underline; }

/* ── Responsive ── */
@media (max-width: 700px) {
  .risk-banner { flex-direction: column; text-align: center; }
  .scan-form { flex-direction: column; }
  .form-group { min-width: 100%; }
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo-text">☠ Claw Breaker</div>
    <div class="title">OpenClaw Security Scanner</div>
    <div class="subtitle">Automated pentesting for OpenClaw instances — 7 probe classes, 60 seconds, zero manual work</div>
  </div>

  <div class="scan-form">
    <div class="form-group">
      <label>Target URL</label>
      <input type="text" id="target" placeholder="http://localhost" value="http://localhost">
    </div>
    <div class="form-group" style="max-width:120px;">
      <label>Control Port</label>
      <input type="number" id="controlPort" value="18788">
    </div>
    <div class="form-group" style="max-width:120px;">
      <label>Gateway Port</label>
      <input type="number" id="gatewayPort" value="18789">
    </div>
    <button class="scan-btn" id="scanBtn" onclick="startScan()">▶ SCAN</button>
  </div>

  <div id="results">
    <div class="state-msg" id="idleMsg">
      Enter a target URL and hit SCAN to begin probing.
    </div>
  </div>
</div>

<div class="footer">
  Built by <a href="https://www.linkedin.com/in/a7medbakrr/" target="_blank">Ahmed Bakr</a> at Break OpenClaw Hack Night — St Patrick's Day 2026
  <br>Powered by <a href="https://blaxel.ai" target="_blank">Blaxel</a> sandboxes
</div>

<script>
const SEV_ORDER = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};

async function startScan() {
  const btn = document.getElementById('scanBtn');
  const results = document.getElementById('results');
  const target = document.getElementById('target').value.trim();
  const cp = document.getElementById('controlPort').value;
  const gp = document.getElementById('gatewayPort').value;

  if (!target) return;
  btn.disabled = true;
  btn.classList.add('scanning');
  btn.textContent = '⟳ SCANNING...';
  results.innerHTML = '<div class="state-msg"><div class="spinner"></div>Running 7 security probes against target...<br><small>This takes about 10-30 seconds</small></div>';

  try {
    const resp = await fetch(`/api/scan?target=${encodeURIComponent(target)}&control_port=${cp}&gateway_port=${gp}`);
    const data = await resp.json();
    renderReport(data);
  } catch(e) {
    results.innerHTML = `<div class="state-msg">Scan failed: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.classList.remove('scanning');
    btn.textContent = '▶ SCAN';
  }
}

function renderReport(report) {
  const s = report.summary;
  const results = document.getElementById('results');
  const ratingClass = s.risk_rating.toLowerCase();

  const circumference = 2 * Math.PI * 42;
  const offset = circumference - (s.risk_percentage / 100) * circumference;
  const strokeColor = s.risk_percentage >= 70 ? 'var(--accent-red)' :
                      s.risk_percentage >= 50 ? 'var(--accent-yellow)' :
                      s.risk_percentage >= 30 ? 'var(--accent-orange)' : 'var(--accent-green)';
  const pctColor = strokeColor;

  let html = `
    <div class="risk-banner ${ratingClass}">
      <div class="risk-ring">
        <svg viewBox="0 0 100 100">
          <circle class="track" cx="50" cy="50" r="42"/>
          <circle class="fill" cx="50" cy="50" r="42"
            stroke="${strokeColor}"
            stroke-dasharray="${circumference}"
            stroke-dashoffset="${offset}"/>
        </svg>
        <div class="risk-pct" style="color:${pctColor}">
          ${s.risk_percentage}%
          <small>risk</small>
        </div>
      </div>
      <div class="risk-meta">
        <h2>Risk Level: ${s.risk_rating}</h2>
        <p>Scanned in ${report.timing.duration_ms}ms — ${s.total_probes} probes executed</p>
        <div class="stats-row">
          <span class="stat-chip vuln">✗ ${s.vulnerable} vulnerable</span>
          <span class="stat-chip safe">✓ ${s.safe} safe</span>
          ${s.errors > 0 ? `<span class="stat-chip">⚠ ${s.errors} errors</span>` : ''}
        </div>
      </div>
    </div>

    <div class="findings-title">Findings (${report.findings.length})</div>
  `;

  const sorted = [...report.findings].sort((a,b) => {
    if (a.status === 'VULNERABLE' && b.status !== 'VULNERABLE') return -1;
    if (b.status === 'VULNERABLE' && a.status !== 'VULNERABLE') return 1;
    return (SEV_ORDER[a.severity]||5) - (SEV_ORDER[b.severity]||5);
  });

  for (const f of sorted) {
    const cardClass = f.status === 'VULNERABLE' ? 'vuln' : f.status === 'SAFE' ? 'safe' : 'err';
    html += `
      <div class="finding-card ${cardClass}" onclick="this.classList.toggle('expanded')">
        <div class="finding-header">
          <span class="finding-id">${f.probe_id}</span>
          <span class="finding-name">${f.probe_name}</span>
          <span class="finding-sev ${f.severity}">${f.severity}</span>
          <span class="finding-status ${f.status}">${f.status}</span>
          <span class="finding-latency">${f.latency_ms.toFixed(0)}ms</span>
        </div>
        <div class="finding-details">
          <div class="detail-label">Description</div>
          <div class="detail-text">${f.description}</div>
          ${f.evidence ? `<div class="detail-label">Evidence</div><div class="evidence-block">${escapeHtml(f.evidence)}</div>` : ''}
          ${f.remediation ? `<div class="detail-label">Remediation</div><div class="remediation-block">${f.remediation}</div>` : ''}
          ${f.cwe ? `<div class="detail-label">CWE</div><div class="detail-text">${f.cwe}</div>` : ''}
        </div>
      </div>
    `;
  }

  results.innerHTML = html;
}

function escapeHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Auto-load latest report if available
fetch('/api/latest').then(r=>r.json()).then(d=>{
  if(d.status==='complete' && d.data) renderReport(d.data);
}).catch(()=>{});
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return DASHBOARD_HTML


@app.get("/api/scan")
async def scan_endpoint(target: str = "http://localhost", control_port: int = 18788, gateway_port: int = 18789):
    """Run a scan and return results."""
    global latest_report
    latest_report = {"status": "scanning", "data": None}

    base = target.rstrip("/")
    if "localhost" in base or "127.0.0.1" in base:
        gateway_url = f"{base}:{gateway_port}"
        control_url = f"{base}:{control_port}"
    else:
        gateway_url = f"{base}:{gateway_port}"
        control_url = f"{base}:{control_port}"

    # Run scan in thread to not block
    loop = asyncio.get_event_loop()
    report = await loop.run_in_executor(None, run_scan, gateway_url, control_url)
    report_dict = report.to_dict()

    latest_report = {"status": "complete", "data": report_dict}

    # Also save to file
    with open("/tmp/claw_breaker_report.json", "w") as f:
        json.dump(report_dict, f, indent=2)

    return JSONResponse(report_dict)


@app.get("/api/latest")
async def latest():
    """Return the latest scan report."""
    return JSONResponse(latest_report)


@app.get("/api/health")
async def health():
    return {"ok": True, "service": "claw-breaker", "probes": len(PROBES)}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"\n☠  Claw Breaker Dashboard → http://localhost:{port}\n")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
