import sys
import argparse
import json
import logging
from agents import ReconAgent, ScanAgent, ValidationAgent, ReportAgent, PDFReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("DASTOrchestrator")

def run_orchestrator(target_url, api_key=None, active_scan=True):
    print("=" * 60)
    print("      AI-POWERED 1-CLICK DAST SECURITY TESTING AGENT      ")
    print("=" * 60)
    print(f"Target URL: {target_url}\n")

    # Step 1: Recon Agent
    print("[+] Phase 1: Launching Recon Agent...")
    recon = ReconAgent(target_url)
    scan_config = recon.run()
    scan_config["active_scan"] = active_scan
    print(f"    - Frameworks Detected: {scan_config['frameworks']}")
    print(f"    - Pages to Scan: {len(scan_config['pages_to_scan'])}")
    print(f"    - Forms Found: {scan_config['detected_forms_count']}")
    print(f"    - Profile Selected: {scan_config['scan_profile']}")
    print(f"    - Active Scan: {'ENABLED (intrusive)' if active_scan else 'DISABLED (passive only)'}\n")

    # Step 2: Scan Agent (OWASP ZAP Emulator)
    print("[+] Phase 2: Launching Scan Agent (DAST Scanning)...")
    scan = ScanAgent(scan_config)
    scan_results = scan.run()
    print(f"    - Total RAW findings generated: {len(scan_results['findings'])}\n")

    # Step 3: Validation Agent (Token Optimized - High & Critical only)
    print("[+] Phase 3: Launching Validation Agent (AI False Positive Optimization)...")
    validator = ValidationAgent(scan_results["findings"], api_key=api_key)
    validated_findings = validator.run()
    
    # Print brief summary of validation results
    for vf in validated_findings:
        finding_id = vf.get("id")
        orig = next((x for x in scan_results["findings"] if x["id"] == finding_id), None)
        if orig:
            title = orig.get("alert")
            fp_status = "FALSE POSITIVE" if vf.get("is_false_positive") else "TRUE POSITIVE"
            conf = int(vf.get("confidence", 0.0) * 100)
            print(f"    - Finding: {title}")
            print(f"      Status: {fp_status} (Confidence: {conf}%)")
            print(f"      AI Reasoning snippet: {vf.get('reasoning')[:120]}...\n")

    # Step 4: Report Agent
    print("[+] Phase 4: Launching Report Agent...")
    reporter = ReportAgent(
        target_url=target_url,
        scan_config=scan_config,
        raw_findings=scan_results["findings"],
        validated_findings=validated_findings
    )
    report_data = reporter.run()
    print(f"    - Risk Score Calculated: {report_data['risk_score']}/100")
    print(f"    - Risk Profile: {report_data['risk_desc']}\n")

    # Step 5: PDF Generator
    print("[+] Phase 5: Launching PDF Generator...")
    pdf_gen = PDFReportGenerator(report_data)
    exec_pdf, tech_pdf = pdf_gen.run()
    
    print("\n" + "=" * 60)
    print("                  SECURITY SCAN COMPLETED                 ")
    print("=" * 60)
    print(f"[SUCCESS] Executive Report: {exec_pdf}")
    print(f"[SUCCESS] Technical Report: {tech_pdf}")
    print("=" * 60)

    return exec_pdf, tech_pdf

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI DAST Orchestrator Command Line Tool")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL to scan")
    parser.add_argument("--api-key", help="Gemini API Key for validation")
    parser.add_argument(
        "--no-active-scan", dest="active_scan", action="store_false",
        help="Disable the ZAP active scanner (run a safe, passive-only scan: spider + response analysis)"
    )
    parser.set_defaults(active_scan=True)
    args = parser.parse_args()

    run_orchestrator(args.url, api_key=args.api_key, active_scan=args.active_scan)
