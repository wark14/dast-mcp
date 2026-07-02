import os
import json
import unittest
from scan_engine import DASTScanEngine
from agents import ReconAgent, ScanAgent, ValidationAgent, ReportAgent, PDFReportGenerator

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

    def test_scan_agent(self):
        print("\n[TEST] Running Scan Agent Test...")
        recon = ReconAgent(self.target_url)
        config = recon.run()
        
        scan = ScanAgent(config)
        results = scan.run()
        
        self.assertIn("scan_id", results)
        self.assertIn("findings", results)
        self.assertGreaterEqual(len(results["findings"]), 1)
        
        alerts = [f["alert"] for f in results["findings"]]
        self.assertTrue(any("SQL Injection" in a for a in alerts), "Should contain SQL Injection finding")
        self.assertTrue(any("Cross-Site Scripting" in a for a in alerts), "Should contain XSS finding")

    def test_validation_agent_no_key(self):
        print("\n[TEST] Running Validation Agent (No API Key) Test...")
        recon = ReconAgent(self.target_url)
        config = recon.run()
        scan = ScanAgent(config)
        results = scan.run()
        
        # When no API key is present, validation agent should skip and return an empty list
        validator = ValidationAgent(results["findings"], api_key=None)
        validated = validator.run()
        self.assertEqual(len(validated), 0, "Validation should return an empty list if no API key is specified")

    def test_validation_agent_mock_key(self):
        print("\n[TEST] Running Validation Agent (Mock API Key) Test...")
        recon = ReconAgent(self.target_url)
        config = recon.run()
        scan = ScanAgent(config)
        results = scan.run()
        
        # When an API key is specified, we test that the Validation Agent runs LLM request flow.
        # We can temporarily patch the _validate_with_llm method to return a mock validation list to check logic.
        validator = ValidationAgent(results["findings"], api_key="MOCK_API_KEY")
        
        mock_findings = []
        for f in results["findings"]:
            if f["risk"] in ["Critical", "High"]:
                mock_findings.append({
                    "id": f["id"],
                    "is_false_positive": "rce" in f["alert"].lower(),
                    "confidence": 0.35 if "rce" in f["alert"].lower() else 0.95,
                    "reasoning": "Mock test reasoning",
                    "solution": "Mock test solution",
                    "is_duplicate": False,
                    "duplicate_of_id": None
                })
                
        validator._validate_with_llm = lambda findings: mock_findings
        validated = validator.run()
        
        self.assertEqual(len(validated), len([f for f in results["findings"] if f["risk"] in ["Critical", "High"]]))
        
        # RCE is mock classified as false positive
        rce_validated = next((v for v in validated if "rce" in next(f["alert"].lower() for f in results["findings"] if f["id"] == v["id"])), None)
        if rce_validated:
            self.assertTrue(rce_validated["is_false_positive"])

    def test_report_and_pdf_generation(self):
        print("\n[TEST] Running Report & PDF Generation Test...")
        recon = ReconAgent(self.target_url)
        config = recon.run()
        scan = ScanAgent(config)
        results = scan.run()
        
        # We run the report with empty validated findings (representing ZAP only mode)
        reporter = ReportAgent(self.target_url, config, results["findings"], [])
        report_data = reporter.run()
        
        self.assertIn("risk_score", report_data)
        self.assertIn("executive_summary", report_data)
        self.assertIn("stats", report_data)
        self.assertFalse(report_data["ai_used"])
        
        pdf_gen = PDFReportGenerator(report_data)
        exec_pdf, tech_pdf = pdf_gen.run()
        
        self.assertTrue(os.path.exists(exec_pdf))
        self.assertTrue(os.path.exists(tech_pdf))
        
        # Cleanup
        if os.path.exists(exec_pdf):
            os.remove(exec_pdf)
        if os.path.exists(tech_pdf):
            os.remove(tech_pdf)
        if os.path.exists("executive_report.json"):
            os.remove("executive_report.json")
        if os.path.exists("technical_va_report.json"):
            os.remove("technical_va_report.json")
        if os.path.exists(f"scan_results_{results['scan_id']}.json"):
            os.remove(f"scan_results_{results['scan_id']}.json")

if __name__ == "__main__":
    unittest.main()
