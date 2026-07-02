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
        
        # Check that we generated the simulated SQLi and XSS findings
        alerts = [f["alert"] for f in results["findings"]]
        self.assertTrue(any("SQL Injection" in a for a in alerts), "Should contain SQL Injection finding")
        self.assertTrue(any("Cross-Site Scripting" in a for a in alerts), "Should contain XSS finding")

    def test_validation_agent(self):
        print("\n[TEST] Running Validation Agent Test...")
        recon = ReconAgent(self.target_url)
        config = recon.run()
        scan = ScanAgent(config)
        results = scan.run()
        
        # Run validation
        validator = ValidationAgent(results["findings"], api_key=None) # test fallback mode
        validated = validator.run()
        
        self.assertEqual(len(validated), len([f for f in results["findings"] if f["risk"] in ["Critical", "High"]]))
        
        # Test false positive identification logic for RCE finding
        rce_validated = next((v for v in validated if "rce" in next(f["alert"].lower() for f in results["findings"] if f["id"] == v["id"])), None)
        if rce_validated:
            self.assertTrue(rce_validated["is_false_positive"], "The RCE finding should be classified as a False Positive")
            self.assertLess(rce_validated["confidence"], 0.5, "Confidence for False Positive should be low")

    def test_report_and_pdf_generation(self):
        print("\n[TEST] Running Report & PDF Generation Test...")
        recon = ReconAgent(self.target_url)
        config = recon.run()
        scan = ScanAgent(config)
        results = scan.run()
        
        validator = ValidationAgent(results["findings"], api_key=None)
        validated = validator.run()
        
        reporter = ReportAgent(self.target_url, config, results["findings"], validated)
        report_data = reporter.run()
        
        self.assertIn("risk_score", report_data)
        self.assertIn("executive_summary", report_data)
        self.assertIn("stats", report_data)
        
        # Generate PDFs
        pdf_gen = PDFReportGenerator(report_data)
        exec_pdf, tech_pdf = pdf_gen.run()
        
        self.assertTrue(os.path.exists(exec_pdf), "Executive PDF file should be generated")
        self.assertTrue(os.path.exists(tech_pdf), "Technical PDF file should be generated")
        
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
