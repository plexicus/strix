from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Any
import httpx
import tenacity

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel



# Global variables set by main()
WEBHOOK_URL: str | None = None
REQUEST_TIMEOUT: int = 120


def main() -> None:
    """Main entry point for the HTTP server."""
    http_server_enabled = os.getenv("HTTP_SERVER", "false").lower() == "true"
    if not http_server_enabled:
        raise RuntimeError("HTTP server should only run when HTTP_SERVER=true")

    parser = argparse.ArgumentParser(description="Start Strix HTTP server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")  # nosec
    parser.add_argument("--port", type=int, default=8089, help="Port to bind to")
    parser.add_argument(
        "--webhook-url",
        type=str,
        default=os.getenv("WEBHOOK_URL"),
        help="Webhook URL to send scan results to",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Hard timeout in seconds for each request execution (default: 120)",
    )
    args = parser.parse_args()

    # Set global variables
    global WEBHOOK_URL, REQUEST_TIMEOUT
    WEBHOOK_URL = args.webhook_url
    REQUEST_TIMEOUT = args.timeout

    # Start the server
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


app = FastAPI()


class ScanRequest(BaseModel):
    repo_url: str
    app_url: str


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str | None = None


def clone_repository(repo_url: str, dest_dir: Path) -> Path:
    """Clone a git repository to a temporary directory."""
    git_executable = shutil.which("git")
    if git_executable is None:
        raise HTTPException(
            status_code=500,
            detail="Git executable not found in PATH"
        )

    repo_name = Path(repo_url).stem if repo_url.endswith(".git") else Path(repo_url).name
    clone_path = dest_dir / repo_name

    if clone_path.exists():
        shutil.rmtree(clone_path)

    try:
        result = subprocess.run(
            [
                git_executable,
                "clone",
                repo_url,
                str(clone_path),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return clone_path
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() if e.stderr else e.stdout.strip()
        raise HTTPException(
            status_code=400,
            detail=f"Failed to clone repository: {error_msg}"
        ) from e


def run_strix_scan(repo_path: Path, app_url: str, scan_id: str, cwd: Path | None = None) -> dict[str, Any]:
    """Run strix scan with both repository and web application targets."""
    # Prepare environment variables for strix
    env = os.environ.copy()
    env.setdefault("STRIX_RUNTIME_BACKEND", "docker")
    # Ensure sandbox mode is true (we're already in container with tool server)
    env["STRIX_SANDBOX_MODE"] = "true"

    if cwd is None:
        cwd = Path(os.getcwd())

    # Run strix command with two targets
    cmd = [
        sys.executable, "-m", "strix.interface.main",
        "--target", str(repo_path),
        "--target", app_url,
        "--non-interactive",
        "--scan-mode", "standard"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=REQUEST_TIMEOUT,
            cwd=str(cwd),
            env=env,
        )

        # Find the latest strix run directory
        strix_runs_dir = cwd / "strix_runs"
        latest_run = None
        latest_mtime = 0
        if strix_runs_dir.exists():
            for entry in strix_runs_dir.iterdir():
                if entry.is_dir():
                    mtime = entry.stat().st_mtime
                    if mtime > latest_mtime:
                        latest_mtime = mtime
                        latest_run = entry

        vulnerabilities_csv = None
        penetration_test_report = None
        if latest_run:
            vulnerabilities_csv = latest_run / "vulnerabilities.csv"
            penetration_test_report = latest_run / "penetration_test_report.md"
            if not vulnerabilities_csv.exists():
                vulnerabilities_csv = None
            if not penetration_test_report.exists():
                penetration_test_report = None

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "vulnerabilities_csv": vulnerabilities_csv,
            "penetration_test_report": penetration_test_report,
            "results_dir": latest_run,
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408,
            detail=f"Scan timed out after {REQUEST_TIMEOUT} seconds"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Scan execution failed: {str(e)}"
        ) from e


async def send_webhook_results(scan_id: str, scan_results: dict[str, Any]) -> None:
    """Send scan results to webhook URL with retry logic."""
    if not WEBHOOK_URL:
        return

    payload = {
        "scan_id": scan_id,
        "status": "completed" if scan_results["returncode"] == 0 else "failed",
        "vulnerabilities_csv_exists": scan_results["vulnerabilities_csv"] is not None,
        "penetration_test_report_exists": scan_results["penetration_test_report"] is not None,
        "stdout_snippet": scan_results["stdout"][-1000:],  # last 1000 chars
        "stderr_snippet": scan_results["stderr"][-1000:],
    }

    retryer = tenacity.AsyncRetrying(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_exponential(multiplier=1, min=1, max=10),
        retry=tenacity.retry_if_exception_type(
            (httpx.RequestError, httpx.HTTPStatusError)
        ),
        before_sleep=tenacity.before_sleep_log(logger=None, log_level=10),
        reraise=True,
    )

    try:
        async for attempt in retryer:
            with attempt:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.post(WEBHOOK_URL, json=payload)
                    response.raise_for_status()
    except tenacity.RetryError as e:
        # Log error but don't fail the request
        print(f"Webhook delivery failed after retries: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Webhook delivery failed: {e}", file=sys.stderr)


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    """Endpoint to trigger a strix scan."""
    scan_id = os.urandom(8).hex()

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        try:
            # Clone repository
            repo_path = clone_repository(request.repo_url, temp_path)

            # Run strix scan
            scan_results = run_strix_scan(repo_path, request.app_url, scan_id, cwd=temp_path)

            # Send results via webhook (async, fire-and-forget)
            asyncio.create_task(send_webhook_results(scan_id, scan_results))

            return ScanResponse(
                scan_id=scan_id,
                status="completed",
                message=f"Scan completed with return code {scan_results['returncode']}"
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Scan failed: {str(e)}"
            ) from e


@app.get("/health")
async def health_check() -> dict[str, Any]:
    return {
        "status": "healthy",
        "http_server_enabled": os.getenv("HTTP_SERVER", "false").lower() == "true",
        "webhook_configured": WEBHOOK_URL is not None,
    }


def signal_handler(_signum: int, _frame: Any) -> None:
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    sys.exit(0)


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":
    main()