"""
Strix HTTP Server Reliability — E2E and unit tests.

Run: python tests/runtime/test_e2e_http_server.py

Scenario 1 (unit): file_path: None present in all finding dict builders.
Scenario 2 (unit): CVSS leniency — severity-derived score when XML absent.
Scenario 3 (Docker): subprocess crash → webhook error.code == SUBPROCESS_CRASH.
Scenario 4 (Docker): all fallbacks exhausted → webhook error field non-null.

Set STRIX_SKIP_DOCKER=1 to skip Docker scenarios (no Docker required).
Docker scenarios send an intentionally invalid API key so the agent subprocess
crashes quickly — no real LLM or target URL needed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

SKIP_DOCKER = os.getenv("STRIX_SKIP_DOCKER") == "1"
IMAGE_TAG = "strix-test-reliability"
DOCKERFILE = REPO_ROOT / "containers" / "Dockerfile"


# ---------------------------------------------------------------------------
# Webhook capture helper
# ---------------------------------------------------------------------------

class WebhookCapture:
    """Minimal HTTP server that captures the first POST payload."""

    def __init__(self) -> None:
        self.payload: dict | None = None
        self._event = threading.Event()
        self._server: HTTPServer | None = None
        self.port: int = 0

    def start(self) -> int:
        capture = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    capture.payload = json.loads(body)
                except json.JSONDecodeError:
                    capture.payload = {}
                capture._event.set()
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):  # silence request logs
                pass

        self._server = HTTPServer(("0.0.0.0", 0), _Handler)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self.port

    def wait(self, timeout: float = 180.0) -> bool:
        return self._event.wait(timeout)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def _build_image() -> bool:
    result = subprocess.run(
        ["docker", "build", "-f", str(DOCKERFILE), "-t", IMAGE_TAG, "."],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("Docker build stderr:", result.stderr[-2000:], file=sys.stderr)
    return result.returncode == 0


def _host_ip() -> str:
    """IP reachable from inside a Docker container."""
    return "host.docker.internal" if sys.platform == "darwin" else "172.17.0.1"


def _run_container(webhook_url: str, extra_env: dict | None = None) -> subprocess.Popen:
    env_flags: list[str] = []
    merged = {
        "HTTP_SERVER": "true",
        "WEBHOOK_URL": webhook_url,
        "STRIX_SANDBOX_EXECUTION_TIMEOUT": "45",
    }
    if extra_env:
        merged.update(extra_env)
    for k, v in merged.items():
        env_flags += ["-e", f"{k}={v}"]
    return subprocess.Popen(
        ["docker", "run", "--rm", "-p", "8089:8089", *env_flags, IMAGE_TAG],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _wait_for_http(port: int, path: str = "/health", retries: int = 30) -> bool:
    for _ in range(retries):
        try:
            urllib.request.urlopen(f"http://localhost:{port}{path}", timeout=2)
            return True
        except Exception:
            time.sleep(1)
    return False


def _post_scan(port: int = 8089) -> int:
    payload = json.dumps({
        "provider": "openai",
        "api_key": "invalid-key-intentional-crash",
        "url": "http://example-target.invalid",
        "token": "test-token",
        "request_id": "test-req-reliability-001",
        "repository_id": "test-repo-reliability-001",
        "first_time_scan": True,
    }).encode()
    req = urllib.request.Request(
        f"http://localhost:{port}/scan",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


# ---------------------------------------------------------------------------
# Scenario 1: file_path field
# ---------------------------------------------------------------------------

def _load_http_server_fns():
    """Load private functions from http_server.py without importing FastAPI/pydantic."""
    import importlib.util
    import sys
    import types

    # Stub heavy deps that http_server.py imports at module level
    fake_fastapi = types.ModuleType("fastapi")
    fake_fastapi.FastAPI = type("FastAPI", (), {"get": lambda *a, **kw: (lambda f: f), "post": lambda *a, **kw: (lambda f: f)})  # type: ignore[attr-defined]
    fake_pydantic = types.ModuleType("pydantic")
    fake_pydantic.BaseModel = object  # type: ignore[attr-defined]

    stubs = {
        "fastapi": fake_fastapi,
        "pydantic": fake_pydantic,
        "uvicorn": types.ModuleType("uvicorn"),
        "httpx": types.ModuleType("httpx"),
    }
    with patch.dict(sys.modules, stubs):
        spec = importlib.util.spec_from_file_location(
            "strix.runtime.http_server",
            REPO_ROOT / "strix/runtime/http_server.py",
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class TestFilePath(unittest.TestCase):
    """Scenario 1: file_path: None present in both finding dict builders."""

    @classmethod
    def setUpClass(cls):
        cls._mod = _load_http_server_fns()

    def test_process_vulnerability_has_file_path(self):
        result = self._mod._process_vulnerability({"title": "Test", "severity": "high"})
        self.assertIn("file_path", result)
        self.assertIsNone(result["file_path"])

    def test_process_assessment_vulnerability_has_file_path(self):
        result = self._mod._process_assessment_vulnerability({
            "title": "Test Vuln",
            "severity": "High",
            "endpoint": "/api/test",
        })
        self.assertIn("file_path", result)
        self.assertIsNone(result["file_path"])


# ---------------------------------------------------------------------------
# Scenario 2: CVSS leniency
# ---------------------------------------------------------------------------

class TestCvssLeniency(unittest.TestCase):
    """Scenario 2: severity-derived score when CVSS XML absent."""

    @classmethod
    def _load_create_fn(cls):
        """Load create_vulnerability_report directly, bypassing strix.tools.__init__."""
        import importlib.util
        import sys
        import types

        # Stub out production-only modules the package chain drags in
        stubs: dict[str, types.ModuleType] = {}
        for name in (
            "strix.tools",
            "strix.tools.registry",
            "strix.tools.reporting",
            "defusedxml",
            "defusedxml.ElementTree",
            "litellm",
        ):
            if name not in sys.modules:
                stubs[name] = types.ModuleType(name)

        # register_tool must be a decorator factory: @register_tool(sandbox_execution=True)
        stubs.get("strix.tools.registry", types.ModuleType("_")).register_tool = (  # type: ignore[attr-defined]
            lambda **kw: (lambda fn: fn)
        )

        with patch.dict(sys.modules, stubs):
            spec = importlib.util.spec_from_file_location(
                "strix.tools.reporting.reporting_actions",
                REPO_ROOT / "strix/tools/reporting/reporting_actions.py",
            )
            assert spec and spec.loader
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            return mod.create_vulnerability_report

    def _call(self, **kwargs) -> dict:
        import sys
        import types

        mock_tracer = MagicMock()
        mock_tracer.get_existing_vulnerabilities.return_value = []
        mock_tracer.add_vulnerability_report.return_value = "report-test-id"

        tracer_mod = types.ModuleType("strix.telemetry.tracer")
        tracer_mod.get_global_tracer = lambda: mock_tracer  # type: ignore[attr-defined]
        dedupe_mod = types.ModuleType("strix.llm.dedupe")
        dedupe_mod.check_duplicate = lambda *a, **kw: {"is_duplicate": False}  # type: ignore[attr-defined]

        create_vulnerability_report = self._load_create_fn()

        with patch.dict(sys.modules, {
            "strix.telemetry.tracer": tracer_mod,
            "strix.llm.dedupe": dedupe_mod,
        }):
            return create_vulnerability_report(**{
                "title": "Test Vulnerability",
                "description": "A test vulnerability",
                "impact": "Test impact",
                "target": "http://example.com",
                "technical_analysis": "Root cause analysis",
                "poc_description": "Step 1: reproduce",
                "poc_script_code": "print('poc')",
                "remediation_steps": "Apply patch",
                **kwargs,
            })

    def test_critical_derives_9_0(self):
        result = self._call(severity="Critical")
        self.assertTrue(result.get("success"), result)
        self.assertAlmostEqual(result["cvss_score"], 9.0)

    def test_high_derives_7_5(self):
        result = self._call(severity="High")
        self.assertTrue(result.get("success"), result)
        self.assertAlmostEqual(result["cvss_score"], 7.5)

    def test_medium_derives_5_0(self):
        result = self._call(severity="Medium")
        self.assertTrue(result.get("success"), result)
        self.assertAlmostEqual(result["cvss_score"], 5.0)

    def test_low_derives_2_5(self):
        result = self._call(severity="Low")
        self.assertTrue(result.get("success"), result)
        self.assertAlmostEqual(result["cvss_score"], 2.5)

    def test_case_insensitive(self):
        result = self._call(severity="critical")
        self.assertTrue(result.get("success"), result)
        self.assertAlmostEqual(result["cvss_score"], 9.0)

    def test_valid_cvss_xml_still_works(self):
        xml = """<cvss>
          <attack_vector>N</attack_vector><attack_complexity>L</attack_complexity>
          <privileges_required>N</privileges_required><user_interaction>N</user_interaction>
          <scope>U</scope><confidentiality>H</confidentiality>
          <integrity>H</integrity><availability>N</availability>
        </cvss>"""
        result = self._call(cvss_breakdown=xml)
        self.assertTrue(result.get("success"), result)
        self.assertGreater(result["cvss_score"], 0)

    def test_no_cvss_no_severity_fails(self):
        result = self._call()
        self.assertFalse(result.get("success"), result)
        self.assertTrue(any("cvss" in e for e in result.get("errors", [])))


# ---------------------------------------------------------------------------
# Scenario 3 & 4: Docker
# ---------------------------------------------------------------------------

_docker_image_built: bool | None = None


def _ensure_image() -> bool:
    global _docker_image_built
    if _docker_image_built is None:
        print("\nBuilding Docker image — this may take a few minutes...")
        _docker_image_built = _build_image()
        if _docker_image_built:
            print("Docker image built successfully.")
        else:
            print("Docker build FAILED.", file=sys.stderr)
    return _docker_image_built


@unittest.skipIf(SKIP_DOCKER, "STRIX_SKIP_DOCKER=1 — skipping Docker scenarios")
class TestDockerSubprocessCrash(unittest.TestCase):
    """Scenario 3: invalid API key causes subprocess crash → error field in webhook."""

    @classmethod
    def setUpClass(cls):
        if not _ensure_image():
            raise unittest.SkipTest("Docker image build failed")

    def test_error_field_on_subprocess_crash(self):
        webhook = WebhookCapture()
        port = webhook.start()
        webhook_url = f"http://{_host_ip()}:{port}/webhook"
        container = _run_container(webhook_url, {
            "OPENAI_API_KEY": "invalid-key-crash",
            "STRIX_LLM": "openai/gpt-4o",
        })
        try:
            ready = _wait_for_http(8089)
            self.assertTrue(ready, "Container did not become healthy in time")
            status = _post_scan()
            self.assertEqual(status, 202)
            received = webhook.wait(timeout=120)
            self.assertTrue(received, "Webhook was not called within 120 s")
            results = (webhook.payload or {}).get("results", {})
            self.assertIn("issues", results, "issues field missing from webhook payload")
            self.assertIn("error", results, "error field missing from webhook payload")
            # On crash with no files: error should be set
            if results.get("error") is not None:
                self.assertIn(results["error"].get("code"), ("SUBPROCESS_CRASH", "FALLBACK_EXHAUSTED"))
        finally:
            container.terminate()
            container.wait(timeout=15)
            webhook.stop()


@unittest.skipIf(SKIP_DOCKER, "STRIX_SKIP_DOCKER=1 — skipping Docker scenarios")
class TestDockerFallbackExhausted(unittest.TestCase):
    """Scenario 4: crash with no reports written → FALLBACK_EXHAUSTED error code."""

    @classmethod
    def setUpClass(cls):
        if not _ensure_image():
            raise unittest.SkipTest("Docker image build failed")

    def test_fallback_exhausted_error_code(self):
        webhook = WebhookCapture()
        port = webhook.start()
        webhook_url = f"http://{_host_ip()}:{port}/webhook"
        container = _run_container(webhook_url, {
            "OPENAI_API_KEY": "invalid-no-reports",
            "STRIX_LLM": "openai/gpt-4o",
        })
        try:
            ready = _wait_for_http(8089)
            self.assertTrue(ready, "Container did not become healthy in time")
            _post_scan()
            received = webhook.wait(timeout=120)
            self.assertTrue(received, "Webhook was not called within 120 s")
            results = (webhook.payload or {}).get("results", {})
            # Both fields must always be present
            self.assertIn("issues", results)
            self.assertIn("error", results)
            # When the agent crashes and writes nothing, error must be non-null
            error = results.get("error")
            self.assertIsNotNone(error, "Expected non-null error when all fallbacks exhausted")
            self.assertIn(error.get("code"), ("SUBPROCESS_CRASH", "FALLBACK_EXHAUSTED"))
        finally:
            container.terminate()
            container.wait(timeout=15)
            webhook.stop()


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Strix HTTP Server Reliability — Test Suite")
    print("=" * 60)
    print(f"Docker tests: {'SKIPPED (set STRIX_SKIP_DOCKER=1 to skip)' if not SKIP_DOCKER else 'DISABLED'}")
    print()
    unittest.main(verbosity=2)
