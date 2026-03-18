#!/usr/bin/env python3
"""
Claw Breaker — Blaxel Sandbox Runner

Deploys the scanner inside a Blaxel perpetual sandbox for isolated execution.
The pentesting agent runs in full isolation — even if it encounters malicious
responses, the host machine is protected.

Usage:
  python run_on_blaxel.py --target http://localhost --control-port 18788

Prerequisites:
  pip install blaxel requests
  blaxel login
"""

import asyncio
import argparse
import json
import os
import sys
from pathlib import Path

try:
    from blaxel.core import SandboxInstance
    HAS_BLAXEL = True
except ImportError:
    HAS_BLAXEL = False


SANDBOX_NAME = "claw-breaker"
SANDBOX_IMAGE = "blaxel/prod-python:latest"
SANDBOX_MEMORY = 2048
SANDBOX_REGION = "us-pdx-1"

# Files to upload to the sandbox
PROJECT_FILES = [
    "claw_breaker.py",
    "report_server.py",
]


async def run_in_blaxel(target: str, control_port: int, gateway_port: int, serve: bool = False):
    """Deploy and run Claw Breaker inside a Blaxel sandbox."""

    print("\n╔══════════════════════════════════════════╗")
    print("║  ☠  CLAW BREAKER — Blaxel Deployment     ║")
    print("╚══════════════════════════════════════════╝\n")

    # ── 1. Create or get sandbox ──
    print(f"[1/5] Creating Blaxel sandbox '{SANDBOX_NAME}'...")
    sandbox = await SandboxInstance.create_if_not_exists({
        "name": SANDBOX_NAME,
        "image": SANDBOX_IMAGE,
        "memory": SANDBOX_MEMORY,
        "region": SANDBOX_REGION,
        "ports": [
            {"target": 8080, "protocol": "HTTP"},
        ],
        "labels": {
            "project": "claw-breaker",
            "type": "security-scanner",
            "event": "break-openclaw-ctf",
        },
    })
    print(f"       ✓ Sandbox ready: {SANDBOX_NAME}")

    # ── 2. Upload project files ──
    print("[2/5] Uploading scanner files...")
    project_dir = Path(__file__).parent

    for filename in PROJECT_FILES:
        filepath = project_dir / filename
        if filepath.exists():
            content = filepath.read_text()
            await sandbox.filesystem.write(f"/app/{filename}", content)
            print(f"       ✓ Uploaded {filename}")
        else:
            print(f"       ⚠ Missing {filename}, skipping")

    # ── 3. Install dependencies ──
    print("[3/5] Installing dependencies...")
    result = await sandbox.process.exec({
        "command": "pip install requests fastapi uvicorn --quiet",
        "working_dir": "/app",
        "wait_for_completion": True,
        "timeout": 60000,
    })
    print("       ✓ Dependencies installed")

    # ── 4. Run the scan ──
    print(f"[4/5] Running scan against {target}...")
    scan_cmd = (
        f"python claw_breaker.py "
        f"--target {target} "
        f"--control-port {control_port} "
        f"--gateway-port {gateway_port} "
        f"--output /app/report.json"
    )
    result = await sandbox.process.exec({
        "command": scan_cmd,
        "working_dir": "/app",
        "wait_for_completion": True,
        "timeout": 120000,
    })

    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    # ── 5. Serve dashboard (optional) ──
    if serve:
        print("[5/5] Starting dashboard server...")
        await sandbox.process.exec({
            "command": "python report_server.py &",
            "working_dir": "/app",
            "wait_for_completion": False,
        })

        # Create preview URL
        preview = await sandbox.previews.create_if_not_exists({
            "metadata": {"name": "claw-breaker-dashboard"},
            "spec": {
                "port": 8080,
                "public": True,
                "prefix_url": "claw-breaker",
            },
        })
        print(f"\n  ☠  Dashboard live at: {preview.url}")
        print(f"     Share this URL to show the security report!\n")
    else:
        print("[5/5] Dashboard skipped (use --serve to enable)")

        # Read and print the JSON report
        try:
            report_content = await sandbox.filesystem.read("/app/report.json")
            report = json.loads(report_content)
            s = report.get("summary", {})
            print(f"\n  ════════════════════════════")
            print(f"  Risk: {s.get('risk_rating', '?')} ({s.get('risk_percentage', 0)}%)")
            print(f"  Vulnerable: {s.get('vulnerable', 0)}")
            print(f"  Safe: {s.get('safe', 0)}")
            print(f"  ════════════════════════════\n")
        except Exception:
            print("\n  Report saved to /app/report.json inside sandbox.\n")

    return sandbox


async def run_locally(target: str, control_port: int, gateway_port: int, serve: bool = False):
    """Run without Blaxel — direct local execution (fallback)."""
    print("\n╔══════════════════════════════════════════╗")
    print("║  ☠  CLAW BREAKER — Local Mode            ║")
    print("╚══════════════════════════════════════════╝\n")
    print("  Blaxel SDK not found. Running locally.\n")

    # Import and run directly
    sys.path.insert(0, str(Path(__file__).parent))
    from claw_breaker import run_scan, print_banner, print_report

    base = target.rstrip("/")
    gateway_url = f"{base}:{gateway_port}"
    control_url = f"{base}:{control_port}"

    print_banner()
    report = run_scan(gateway_url, control_url)
    print_report(report)

    report_dict = report.to_dict()
    with open("report.json", "w") as f:
        json.dump(report_dict, f, indent=2)
    print(f"  Report saved to report.json\n")

    if serve:
        print(f"  Starting dashboard on http://localhost:8080 ...\n")
        import uvicorn
        from report_server import app
        uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")


async def main():
    parser = argparse.ArgumentParser(description="Claw Breaker — Blaxel Runner")
    parser.add_argument("--target", default="http://localhost",
                       help="Target OpenClaw host URL")
    parser.add_argument("--control-port", type=int, default=18788,
                       help="Control UI port (default: 18788)")
    parser.add_argument("--gateway-port", type=int, default=18789,
                       help="Gateway port (default: 18789)")
    parser.add_argument("--serve", action="store_true",
                       help="Start the dashboard server after scanning")
    parser.add_argument("--local", action="store_true",
                       help="Force local execution (skip Blaxel)")
    args = parser.parse_args()

    if args.local or not HAS_BLAXEL:
        await run_locally(args.target, args.control_port, args.gateway_port, args.serve)
    else:
        await run_in_blaxel(args.target, args.control_port, args.gateway_port, args.serve)


if __name__ == "__main__":
    asyncio.run(main())
