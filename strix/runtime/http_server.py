from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

WEBHOOK_URL: str | None = None

app = FastAPI()


class ScanRequest(BaseModel):
    provider: str
    deployment_name: str | None = None
    api_key: str
    api_base: str | None = None
    url: str
    authorization: dict | None = None
    token: str
    request_id: str
    repository_id: str
    first_time_scan: bool = False
    custom_prompt: str | None = None


def _normalize_severity(sev: str) -> str:
    mapping = {"info": "Informational", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
    return mapping.get(sev.lower(), "Medium")


def _extract_cwe(content: str) -> list[str]:
    match = re.search(r"CWE-(\d+)", content)
    return [f"CWE-{match.group(1)}"] if match else []


def _process_vulnerability(vuln: dict) -> dict:
    content = vuln.get("content", "")
    return {
        "original_line": 0,
        "actual_line": 0,
        "category": "Application",
        "cve": vuln.get("cve_id"),
        "cvssv3_vector": vuln.get("cvss_vector"),
        "cwe": _extract_cwe(content),
        "date": {"$date": vuln.get("timestamp") or datetime.now(timezone.utc).isoformat()},
        "description": content,
        "references": vuln.get("references", []),
        "scanner_report_code": vuln.get("proof_of_concept", ""),
        "severity": _normalize_severity(vuln.get("severity", "medium")),
        "start_column": 0,
        "tags": vuln.get("tags", ["DAST", "AI-Validated"]),
        "title": vuln.get("title", "Security Vulnerability"),
        "tool": "strix",
        "tool_id": vuln.get("id", "strix-dast"),
        "type": "DAST",
        "confidence": 85,
        "mitigation": vuln.get("mitigation", "Refer to PoC for remediation context."),
    }


def _load_vulnerabilities(run_dir: Path) -> list[dict]:
    for name in ("vulnerabilities.json", "report.json"):
        json_path = run_dir / name
        if json_path.exists():
            data = json.loads(json_path.read_text())
            vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
            return [_process_vulnerability(v) for v in vulns]

    csv_path = run_dir / "vulnerabilities.csv"
    if csv_path.exists():
        with csv_path.open() as f:
            return [_process_vulnerability(row) for row in csv.DictReader(f)]

    return []


def _find_latest_run(cwd: Path) -> Path | None:
    strix_runs_dir = cwd / "strix_runs"
    if not strix_runs_dir.exists():
        return None
    latest_run = None
    latest_mtime = 0.0
    for entry in strix_runs_dir.iterdir():
        if entry.is_dir():
            mtime = entry.stat().st_mtime
            if mtime > latest_mtime:
                latest_mtime = mtime
                latest_run = entry
    return latest_run


def _process_assessment_vulnerability(vuln: dict) -> dict:
    sev = _normalize_severity(str(vuln.get("severity", "medium")))
    title = vuln.get("title", "Security Vulnerability")
    endpoint = vuln.get("endpoint") or (vuln.get("endpoints") or [""])[0]
    impact = vuln.get("impact", "")
    evidence = vuln.get("evidence", {})
    desc_parts = [impact]
    if evidence:
        desc_parts.append(f"Evidence: {json.dumps(evidence)}")
    description = " | ".join(p for p in desc_parts if p)
    poc = "\n".join(vuln.get("reproduction") or [])
    return {
        "original_line": 0,
        "actual_line": 0,
        "category": "Application",
        "cve": None,
        "cvssv3_vector": None,
        "cwe": [],
        "date": {"$date": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()},
        "description": description,
        "references": [],
        "scanner_report_code": poc,
        "severity": sev,
        "start_column": 0,
        "tags": ["DAST", "AI-Validated"],
        "title": title,
        "tool": "strix",
        "tool_id": vuln.get("id", "strix-dast"),
        "type": "DAST",
        "confidence": 85,
        "mitigation": "",
        "endpoint": endpoint,
    }


def _load_workspace_assessment(cwd: Path) -> list[dict]:
    for name in ("juice_shop_assessment.json", "assessment.json", "findings.json"):
        assessment_path = cwd / name
        if assessment_path.exists():
            data = json.loads(assessment_path.read_text())
            if isinstance(data, dict):
                vulns = data.get("vulnerabilities", [])
            else:
                vulns = data
            return [_process_assessment_vulnerability(v) for v in vulns if isinstance(v, dict)]
    return []


def _find_best_workspace_report() -> tuple[str, str] | tuple[None, None]:
    from strix.tools.reporting.workspace_parser import parse_workspace_markdown

    workspace = Path("/workspace")
    if not workspace.exists():
        return None, None
    best_count = 0
    best_name: str | None = None
    best_content: str | None = None
    for md_file in sorted(workspace.glob("*.md")):
        try:
            content = md_file.read_text(encoding="utf-8", errors="replace")
            count = len(parse_workspace_markdown(content))
            if count > best_count:
                best_count = count
                best_name = md_file.name
                best_content = content
        except OSError:
            continue
    return best_name, best_content


def _load_workspace_markdown_reports() -> list[dict]:
    from strix.tools.reporting.workspace_parser import parse_workspace_markdown

    _, content = _find_best_workspace_report()
    if not content:
        return []
    return [_process_vulnerability(v) for v in parse_workspace_markdown(content)]


def _run_strix_sync(request: ScanRequest, cwd: Path) -> list[dict]:
    env = os.environ.copy()
    env["STRIX_SANDBOX_MODE"] = "true"
    env["LLM_API_KEY"] = request.api_key
    env["OPENAI_API_KEY"] = request.api_key
    deployment = request.deployment_name or "gpt-4o"
    if request.api_base:
        env["LLM_API_BASE"] = request.api_base
        env["OPENAI_API_BASE"] = request.api_base
        if "cognitiveservices.azure.com" in request.api_base or "openai.azure.com" in request.api_base:
            env["AZURE_OPENAI_ENDPOINT"] = request.api_base
    if request.deployment_name:
        env["OPENAI_API_MODEL"] = request.deployment_name
        env["AZURE_OPENAI_DEPLOYMENT_ID"] = request.deployment_name
    # Map platform provider + base URL to litellm model prefix for STRIX_LLM
    if request.api_base and ("cognitiveservices.azure.com" in request.api_base or "openai.azure.com" in request.api_base):
        env["STRIX_LLM"] = f"azure/{deployment}"
    elif request.provider == "deepseek":
        env["STRIX_LLM"] = f"deepseek/{deployment}"
    elif request.provider:
        env["STRIX_LLM"] = f"{request.provider}/{deployment}"
    else:
        env["STRIX_LLM"] = f"openai/{deployment}"

    timeout = int(os.getenv("STRIX_SANDBOX_EXECUTION_TIMEOUT", "3600"))
    subprocess.run(
        [sys.executable, "-m", "strix.interface.main", "--target", request.url, "--non-interactive"],
        cwd=str(cwd),
        env=env,
        timeout=timeout,
        check=False,
    )

    latest_run = _find_latest_run(cwd)
    if latest_run:
        findings = _load_vulnerabilities(latest_run)
        if findings:
            return findings
    # Fallback: check workspace-level assessment JSON files
    findings = _load_workspace_assessment(cwd)
    if findings:
        return findings
    # Final fallback: parse markdown vulnerability reports written by the agent to /workspace/
    return _load_workspace_markdown_reports()


async def _post_results(request: ScanRequest, findings: list[dict]) -> None:
    webhook_url = WEBHOOK_URL
    if not webhook_url:
        print("No WEBHOOK_URL configured — scan results not delivered", file=sys.stderr)
        return

    scan_uuid = str(uuid.uuid4())
    extra_data: dict[str, Any] = {
        "repository_id": request.repository_id,
        "first_time_scan": request.first_time_scan,
        "external_tools": [],
    }
    report_name, report_content = _find_best_workspace_report()
    if report_name and report_content:
        extra_data["pentest_report"] = {"name": report_name, "content": report_content}

    payload = {
        "request_id": request.request_id,
        "results": {
            "tool": "strix",
            "scan_name": f"strix_{scan_uuid}_1",
            "issues": findings,
            "extra_data": extra_data,
        },
    }
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {request.token}"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(webhook_url, json=payload, headers=headers)
        response.raise_for_status()


@app.post("/scan", status_code=202)
async def scan(request: ScanRequest) -> dict[str, str]:
    async def run_and_callback() -> None:
        try:
            cwd = Path(os.getcwd())
            loop = asyncio.get_running_loop()
            findings = await loop.run_in_executor(None, _run_strix_sync, request, cwd)
            await _post_results(request, findings)
        except Exception as e:
            print(f"Strix scan error for request_id={request.request_id}: {e}", file=sys.stderr)

    asyncio.create_task(run_and_callback())
    return {"status": "accepted", "request_id": request.request_id}


@app.get("/health")
async def health_check() -> dict[str, Any]:
    return {"status": "healthy", "webhook_configured": WEBHOOK_URL is not None}


def main() -> None:
    http_server_enabled = os.getenv("HTTP_SERVER", "false").lower() == "true"
    if not http_server_enabled:
        raise RuntimeError("HTTP server should only run when HTTP_SERVER=true")

    parser = argparse.ArgumentParser(description="Start Strix HTTP server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")  # nosec
    parser.add_argument("--port", type=int, default=8089, help="Port to bind to")
    parser.add_argument("--webhook-url", type=str, default=os.getenv("MESSAGE_URL"), help="Callback URL for scan results")
    args = parser.parse_args()

    global WEBHOOK_URL
    WEBHOOK_URL = args.webhook_url

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
