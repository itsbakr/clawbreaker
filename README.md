# ☠ Claw Breaker — Automated OpenClaw Security Scanner

**Built live at Break OpenClaw Hack Night (St Patrick's Day 2026)**  
**By [Ahmed Bakr](https://www.linkedin.com/in/a7medbakrr/) — Founder of [Awn AI](https://getawn.ai)**

## What is this?

Claw Breaker is an automated pentesting agent that probes OpenClaw instances for **7 real vulnerability classes** discovered during the Break OpenClaw CTF. It runs inside a [Blaxel](https://blaxel.ai) sandbox for isolated, safe execution.

## The 7 Probe Classes

| # | Probe | Severity | CWE | What it finds |
|---|-------|----------|-----|---------------|
| P1 | Skills Status Secret Leak | HIGH | CWE-200 | Secrets exposed in `/api/skills/status` without auth |
| P2 | Local File Inclusion (LFI) | CRITICAL | CWE-22 | Arbitrary file read via `/media?path=` endpoint |
| P3 | Unauth Config Mutation | CRITICAL | CWE-306 | `POST /api/config` accepts changes without auth |
| P4 | Auth Token Exfiltration | CRITICAL | CWE-918 | Server leaks gateway token to attacker-supplied URL |
| P5 | Browser State Exposure | HIGH | CWE-200 | `/api/browser/state` exposes stored secrets |
| P6 | Control UI XSS | HIGH | CWE-79 | Injected scripts in Control UI HTML set malicious cookies |
| P7 | Log Secret Leakage | MEDIUM | CWE-532 | Secrets exposed in status/MOTD responses |

All 7 probes are based on **real vulnerabilities** exploited during the Break OpenClaw CTF to achieve a perfect 4,950 point score (21/21 flags).

## Quick Start

### Run locally (no Blaxel)
```bash
pip install requests fastapi uvicorn
python claw_breaker.py --target http://localhost --output report.json
```

### Run with dashboard
```bash
python report_server.py
# Open http://localhost:8080
```

### Run inside Blaxel sandbox (recommended)
```bash
pip install blaxel
blaxel login
python run_on_blaxel.py --target http://your-openclaw-host --serve
```

## Architecture

```
┌─────────────────────────────────────────┐
│         Blaxel Perpetual Sandbox         │
│  (Isolated microVM, scale-to-zero,       │
│   25ms resume, full state preserved)     │
│                                          │
│  ┌──────────────────────────────────┐   │
│  │   Claw Breaker Scanner Engine     │   │
│  │   7 probes × target instance      │   │
│  └──────────┬───────────────────────┘   │
│             ↓                            │
│  ┌──────────────────────────────────┐   │
│  │   FastAPI Dashboard (port 8080)   │   │
│  │   Live visual security report     │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
              ↓ Preview URL
    https://claw-breaker.blaxel.app
```

## Why Blaxel?

Pentesting agents execute against potentially hostile targets. Running the scanner inside a Blaxel sandbox means:
- **Isolation**: Even if the target sends malicious responses, the host is protected
- **Perpetual standby**: Sandbox stays warm for re-scans without cold start
- **Scale-to-zero**: Pay nothing when idle, instant resume at 25ms
- **Reproducible**: Same environment every time, shareable via preview URL

## Context: NemoClaw + GTC 2026

This tool was built the same day NVIDIA announced **NemoClaw** at GTC 2026 — their enterprise security stack for OpenClaw. NemoClaw adds OpenShell sandboxing and YAML-based policies. But as the CTF proved, **the control plane above the sandbox is where most vulnerabilities live** (unauth APIs, LFI, XSS, secret leakage). Claw Breaker tests exactly those layers.

## Tech Stack

- **Scanner**: Python + requests (zero heavy deps)
- **Dashboard**: FastAPI + vanilla JS (single-file, no build step)
- **Sandbox**: Blaxel perpetual sandboxes (microVM isolation)
- **Observability**: Compatible with Opik tracing (add `opik` decorator)

## License

MIT — Built at a hackathon, shared with the community.
