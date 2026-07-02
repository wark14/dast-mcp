import os
import json
import unittest
import requests
from scan_engine import DASTScanEngine
from agents import ReconAgent, ScanAgent, ValidationAgent, ReportAgent, PDFReportGenerator


def zap_available():
    """True only if a real ZAP daemon is already reachable (no auto-start here)."""
    url = os.environ.get("ZAP_API_URL", "http://localhost:8080").rstrip("/")
    try:
        return requests.get(f"{url}/JSON/core/view/version/", timeout=3).status_code == 200
    except Exception:
        return False


# A small, realistic ZAP-shaped findings fixture so unit tests do not depend on
# running a live scan (and never rely on fabricated findings).
SAMPLE_FINDINGS = [
    {
        "id": "f-sqli", "alert": "SQL Injection", "risk": "Critical", "confidence": "High",
        "url": "https://example.com/search", "parameter": "q",
        "description": "SQL injection in the 'q' parameter.",
        "solution": "Use parameterized queries.", "evidence": "MySQL syntax error",
        "wascid": "19", "cweid": "89",
        "request_header": "POST /search HTTP/1.1\nHost: example.com", "request_body": "q=1'",
        "response_header": "HTTP/1.1 500", "response_body": "SQL error", "other": ""
    },
    {
        "id": "f-xss", "alert": "Reflected Cross-Site Scripting (XSS)", "risk": "High",
        "confidence": "High", "url": "https://example.com/q", "parameter": "q",
        "description": "Reflected XSS.", "solution": "Encode output.",
        "evidence": "<script>alert(1)</script>", "wascid": "8", "cweid": "79",
        "request_header": "GET /q HTTP/1.1", "request_body": "",
        "response_header": "HTTP/1.1 200", "response_body": "<script>alert(1)</script>", "other": ""
    },
    {
        "id": "f-csp", "alert": "CSP Header Not Set", "risk": "Medium", "confidence": "High",
        "url": "https://example.com/", "parameter": "",
        "description": "Missing Content-Security-Policy.", "solution": "Set CSP header.",
        "evidence": "No CSP header", "wascid": "15", "cweid": "693",
        "request_header": "", "request_body": "", "response_header": "", "response_body": "", "other": ""
    },
    {
        "id": "f-info", "alert": "Server Version Disclosure", "risk": "Low", "confidence": "Medium",
        "url": "https://example.com/", "parameter": "",
        "description": "Server banner exposed.", "solution": "Suppress banner.",
        "evidence": "Server: Apache/2.4", "wascid": "13", "cweid": "200",
        "request_header": "", "request_body": "", "response_header": "", "response_body": "", "other": ""
    },
]

SAMPLE_SCAN_CONFIG = {
    "target_url": "https://example.com",
    "frameworks": ["Web Server: Apache", "Frontend: React"],
    "detected_forms_count": 2,
    "scan_profile": "SPA/Ajax Focused Profile",
    "use_ajax_spider": True,
    "pages_to_scan": ["https://example.com", "https://example.com/search"],
}


class TestDASTPipeline(unittest.TestCase):
    def setUp(self):
        self.target_url = "https://example.com"

    def test_recon_agent(self):
        print("\n[TEST] Running Recon Agent Test...")
        recon = ReconAgent(self.target_url)
        config = recon.run()

        self.assertIn("target_url", config)
        self.assertEqual(config["target_url"], self.target_url)
        self.assertIn("frameworks", config)
        self.assertIn("scan_profile", config)
        self.assertIn("pages_to_scan", config)

    def test_no_simulated_fallback(self):
        """The fabricated 'local fallback' scanner must not exist — no fake findings, ever."""
        print("\n[TEST] Verifying the simulated fallback scanner is gone...")
        self.assertFalse(
            hasattr(DASTScanEngine, "_run_local_fallback_scan"),
            "Fabricated fallback scan must be removed; ZAP is required."
        )

    def test_scan_requires_zap(self):
        """With ZAP unreachable and not a local instance, scanning must raise (never fake it)."""
        print("\n[TEST] Verifying ZAP is required (no fallback)...")
        original = os.environ.get("ZAP_API_URL")
        # TEST-NET-2 address: unreachable and non-local, so no bundled ZAP boot is attempted.
        os.environ["ZAP_API_URL"] = "http://198.51.100.1:8080"
        try:
            engine = DASTScanEngine(self.target_url)
            with self.assertRaises(RuntimeError):
                engine.ensure_zap_running(startup_timeout=1)
        finally:
            if original is None:
                os.environ.pop("ZAP_API_URL", None)
            else:
                os.environ["ZAP_API_URL"] = original

    def test_validation_agent_no_key(self):
        print("\n[TEST] Running Validation Agent (No API Key) Test...")
        # When no API key is present, the agent skips AI validation and returns an empty list.
        validator = ValidationAgent(SAMPLE_FINDINGS, api_key=None)
        validated = validator.run()
        self.assertEqual(len(validated), 0, "Validation should return [] when no API key is specified")

    def test_validation_agent_mock_key(self):
        print("\n[TEST] Running Validation Agent (Mock API Key) Test...")
        validator = ValidationAgent(SAMPLE_FINDINGS, api_key="MOCK_API_KEY")

        high_crit = [f for f in SAMPLE_FINDINGS if f["risk"] in ["Critical", "High"]]
        mock_findings = [{
            "id": f["id"],
            "is_false_positive": (f["risk"] == "High"),
            "confidence": 0.4 if f["risk"] == "High" else 0.95,
            "reasoning": "Mock test reasoning",
            "solution": "Mock test solution",
            "is_duplicate": False,
            "duplicate_of_id": None,
        } for f in high_crit]

        validator._validate_with_llm = lambda findings: mock_findings
        validated = validator.run()

        self.assertEqual(len(validated), len(high_crit))
        xss = next((v for v in validated if v["id"] == "f-xss"), None)
        self.assertIsNotNone(xss)
        self.assertTrue(xss["is_false_positive"])

    def test_mcp_validation_via_client_sampling(self):
        """
        Over MCP with no Gemini key, validate_findings must run on the connected client's
        own model via MCP sampling (this is how Claude Desktop validates without any key).
        """
        print("\n[TEST] Running MCP client-sampling validation test...")
        import asyncio
        from fastmcp import Client
        import mcp_server

        mock_validation = [
            {"id": "f-sqli", "is_false_positive": False, "confidence": 0.92,
             "reasoning": "Genuine SQLi.", "solution": "Use parameterized queries.",
             "is_duplicate": False, "duplicate_of_id": None},
            {"id": "f-xss", "is_false_positive": True, "confidence": 0.30,
             "reasoning": "Likely false positive.", "solution": "Encode output.",
             "is_duplicate": False, "duplicate_of_id": None},
        ]

        # Stand in for the client LLM (e.g. Claude); returns deterministic JSON.
        async def sampling_handler(messages, params, context):
            return json.dumps(mock_validation)

        async def call():
            async with Client(mcp_server.mcp, sampling_handler=sampling_handler) as client:
                return await client.call_tool(
                    "validate_findings",
                    {"findings_json": json.dumps(SAMPLE_FINDINGS)},  # no api_key
                )

        # Make sure no ambient Gemini key diverts to the Gemini path.
        original = os.environ.pop("GEMINI_API_KEY", None)
        try:
            res = asyncio.run(call())
        finally:
            if original is not None:
                os.environ["GEMINI_API_KEY"] = original

        text = res.content[0].text if getattr(res, "content", None) else res.data
        data = json.loads(text)
        self.assertEqual(len(data), 2)
        self.assertEqual({d["id"] for d in data}, {"f-sqli", "f-xss"})
        xss = next(d for d in data if d["id"] == "f-xss")
        self.assertTrue(xss["is_false_positive"])

    def test_report_and_pdf_generation(self):
        print("\n[TEST] Running Report & PDF Generation Test...")
        # ZAP-only mode: empty validated findings (no AI).
        reporter = ReportAgent(self.target_url, SAMPLE_SCAN_CONFIG, list(SAMPLE_FINDINGS), [])
        report_data = reporter.run()

        self.assertIn("risk_score", report_data)
        self.assertIn("executive_summary", report_data)
        self.assertIn("stats", report_data)
        self.assertIn("scan_profile", report_data)
        self.assertIn("pages_crawled", report_data)
        self.assertFalse(report_data["ai_used"])
        # active_scan defaults to True when not specified in the scan config.
        self.assertTrue(report_data["active_scan"])
        self.assertEqual(report_data["stats"]["critical"], 1)
        self.assertEqual(report_data["stats"]["high"], 1)

        pdf_gen = PDFReportGenerator(report_data)
        exec_pdf, tech_pdf = pdf_gen.run()

        self.assertTrue(os.path.exists(exec_pdf))
        self.assertTrue(os.path.exists(tech_pdf))

        # Cleanup
        for path in [exec_pdf, tech_pdf, "executive_report.json",
                     "technical_va_report.json", "findings_severity_chart.png"]:
            if os.path.exists(path):
                os.remove(path)

    def test_active_scan_toggle_flows_to_report(self):
        """The active_scan choice on the scan config propagates into the report."""
        print("\n[TEST] Verifying active_scan toggle propagates...")
        passive_config = dict(SAMPLE_SCAN_CONFIG, active_scan=False)
        report = ReportAgent(self.target_url, passive_config, list(SAMPLE_FINDINGS), []).run()
        self.assertFalse(report["active_scan"])
        for path in ["Executive_Report.pdf", "Technical_VA_Report.pdf", "executive_report.json",
                     "technical_va_report.json", "findings_severity_chart.png"]:
            if os.path.exists(path):
                os.remove(path)

    @unittest.skipUnless(zap_available(), "requires a running OWASP ZAP daemon")
    def test_zap_scan_integration(self):
        """End-to-end scan against a real ZAP daemon (only runs when ZAP is already up)."""
        print("\n[TEST] Running live ZAP scan integration test...")
        config = ReconAgent(self.target_url).run()
        results = ScanAgent(config).run()
        self.assertIn("scan_id", results)
        self.assertIn("findings", results)
        if os.path.exists(f"scan_results_{results['scan_id']}.json"):
            os.remove(f"scan_results_{results['scan_id']}.json")


if __name__ == "__main__":
    unittest.main()
