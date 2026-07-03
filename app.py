import os
import threading
import time
import logging
from flask import Flask, jsonify, request, send_file, render_template_string
from agents import ReconAgent, ScanAgent, ValidationAgent, ReportAgent, PDFReportGenerator

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DAST-WebApp")

app = Flask(__name__)

# In-memory storage for the active scan state
scan_state = {
    "status": "idle",       # idle, running, completed, failed
    "progress": 0,          # 0 to 100
    "logs": [],
    "target_url": "",
    "error_message": "",
    "results": None,
    "exec_pdf": None,       # actual path of the generated Executive PDF (scan-id suffixed)
    "tech_pdf": None        # actual path of the generated Technical PDF (scan-id suffixed)
}

scan_lock = threading.Lock()

def add_log(message):
    timestamp = time.strftime("%H:%M:%S")
    scan_state["logs"].append(f"[{timestamp}] {message}")

def run_dast_pipeline_thread(target_url, api_key, active_scan=True):
    global scan_state
    
    try:
        with scan_lock:
            scan_state["status"] = "running"
            scan_state["progress"] = 5
            scan_state["logs"] = []
            scan_state["target_url"] = target_url
            scan_state["error_message"] = ""
            scan_state["results"] = None
        
        add_log(f"Starting Orchestrator for target: {target_url}")
        
        # Step 1: Recon Agent
        scan_state["progress"] = 15
        add_log("Invoking Recon Agent...")
        recon = ReconAgent(target_url)
        scan_config = recon.run()
        scan_config["active_scan"] = active_scan
        add_log(f"Recon completed. Detected framework(s): {', '.join(scan_config['frameworks'] or ['Generic Web App'])}")
        add_log(f"Recon profile selected: {scan_config['scan_profile']}")
        add_log(f"Recon discovered {len(scan_config['pages_to_scan'])} unique application endpoints.")
        
        # Step 2: Scan Agent
        scan_state["progress"] = 35
        add_log(f"Invoking Scan Agent (OWASP ZAP, {'active + passive scan' if active_scan else 'passive-only scan'})...")
        scan = ScanAgent(scan_config)
        scan_results = scan.run()
        crit_count = sum(1 for f in scan_results['findings'] if f.get('risk', '').lower() == 'critical')
        high_count = sum(1 for f in scan_results['findings'] if f.get('risk', '').lower() == 'high')
        add_log(f"Scan Agent completed. Found {len(scan_results['findings'])} raw security alerts (Severity counts: {crit_count} Critical, {high_count} High).")
        
        # Step 3: Validation Agent
        scan_state["progress"] = 60
        if api_key:
            add_log(f"Invoking Validation Agent (Filtering High & Critical findings for AI verification)...")
        else:
            add_log("Invoking Validation Agent (No API Key specified - skipping AI check)...")
        validator = ValidationAgent(scan_results["findings"], api_key=api_key)
        validated_findings = validator.run()
        if api_key:
            tp_crit = sum(1 for f in validated_findings if not f.get('is_false_positive') and next((x.get('risk','').lower() for x in scan_results['findings'] if x['id'] == f['id']), '') == 'critical')
            tp_high = sum(1 for f in validated_findings if not f.get('is_false_positive') and next((x.get('risk','').lower() for x in scan_results['findings'] if x['id'] == f['id']), '') == 'high')
            fp_crit = sum(1 for f in validated_findings if f.get('is_false_positive') and next((x.get('risk','').lower() for x in scan_results['findings'] if x['id'] == f['id']), '') == 'critical')
            fp_high = sum(1 for f in validated_findings if f.get('is_false_positive') and next((x.get('risk','').lower() for x in scan_results['findings'] if x['id'] == f['id']), '') == 'high')
            add_log(f"Validation Agent completed. AI verified {tp_crit} Critical / {tp_high} High as True Positives, and flagged {fp_crit} Critical / {fp_high} High as False Positives.")
        else:
            add_log("Validation Agent completed. Dynamic AI verification skipped.")
        
        # Step 4: Report Agent
        scan_state["progress"] = 80
        add_log("Invoking Report Agent to compile findings and compute risk metrics...")
        reporter = ReportAgent(target_url, scan_config, scan_results["findings"], validated_findings, scan_id=scan_results.get("scan_id"))
        report_data = reporter.run()
        add_log(f"Risk analysis complete. Calculated risk score: {report_data['risk_score']}/100 ({report_data['risk_desc']}).")
        
        # Step 5: PDF Generator
        scan_state["progress"] = 95
        add_log(f"Invoking PDF Generator (Compiling Executive and Technical PDFs for scan: {scan_results.get('scan_id')})...")
        pdf_gen = PDFReportGenerator(report_data)
        exec_pdf, tech_pdf = pdf_gen.run()
        add_log(f"PDF reports successfully written to workspace: {exec_pdf} and {tech_pdf}")

        # Done
        with scan_lock:
            scan_state["progress"] = 100
            scan_state["status"] = "completed"
            scan_state["results"] = report_data
            # Record the actual (scan-id suffixed) PDF paths so /download serves the
            # right files — the generator names them Executive_Report_<scan_id>.pdf.
            scan_state["exec_pdf"] = exec_pdf
            scan_state["tech_pdf"] = tech_pdf
        add_log("AI DAST security pipeline completed successfully. Ready for download.")
            
    except Exception as e:
        logger.exception("Error in pipeline thread")
        with scan_lock:
            scan_state["status"] = "failed"
            scan_state["error_message"] = str(e)
        add_log(f"CRITICAL ERROR in orchestrator pipeline: {str(e)}")

# Gorgeous SPA HTML template embedding
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI DAST Security Agent Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #090D16;
            --bg-card: #0F172A;
            --bg-border: #1E293B;
            --primary: #4F46E5;
            --primary-light: #6366F1;
            --primary-glow: rgba(79, 70, 229, 0.15);
            --accent: #06B6D4;
            --text-main: #F1F5F9;
            --text-muted: #94A3B8;
            
            --critical: #EF4444;
            --high: #F97316;
            --medium: #EAB308;
            --low: #3B82F6;
            --info: #64748B;
            
            --critical-bg: rgba(239, 68, 68, 0.1);
            --high-bg: rgba(249, 115, 22, 0.1);
            --medium-bg: rgba(234, 179, 8, 0.1);
            --low-bg: rgba(59, 130, 246, 0.1);
            --info-bg: rgba(100, 116, 139, 0.1);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
            position: relative;
        }

        body::before {
            content: '';
            position: absolute;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, var(--primary-glow) 0%, transparent 70%);
            top: -100px;
            right: -100px;
            z-index: 0;
            pointer-events: none;
        }

        body::after {
            content: '';
            position: absolute;
            width: 450px;
            height: 450px;
            background: radial-gradient(circle, rgba(6, 182, 212, 0.08) 0%, transparent 70%);
            bottom: -150px;
            left: -150px;
            z-index: 0;
            pointer-events: none;
        }

        header {
            position: relative;
            z-index: 10;
            border-bottom: 1px solid var(--bg-border);
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(12px);
            padding: 1.25rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo-container {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .logo-icon {
            width: 2.25rem;
            height: 2.25rem;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border-radius: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 1.25rem;
            box-shadow: 0 0 15px var(--primary-glow);
        }

        .logo-text {
            font-weight: 700;
            font-size: 1.25rem;
            letter-spacing: -0.025em;
            background: linear-gradient(to right, #FFF, var(--text-muted));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .logo-tag {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--accent);
            border: 1px solid rgba(6, 182, 212, 0.3);
            background: rgba(6, 182, 212, 0.05);
            padding: 0.15rem 0.5rem;
            border-radius: 100px;
        }

        main {
            position: relative;
            z-index: 10;
            flex: 1;
            max-width: 1400px;
            width: 100%;
            margin: 0 auto;
            padding: 2rem;
            display: grid;
            grid-template-columns: 360px 1fr;
            gap: 2rem;
        }

        @media (max-width: 1024px) {
            main {
                grid-template-columns: 1fr;
            }
        }

        .sidebar {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .card {
            background-color: var(--bg-card);
            border: 1px solid var(--bg-border);
            border-radius: 1rem;
            padding: 1.5rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .card:hover {
            border-color: rgba(79, 70, 229, 0.3);
            box-shadow: 0 8px 30px rgba(79, 70, 229, 0.05);
        }

        .card-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .form-group {
            margin-bottom: 1.25rem;
        }

        .form-label {
            display: block;
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
            font-weight: 500;
        }

        .toggle-row {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-size: 0.85rem;
            color: var(--text-main);
            font-weight: 500;
            cursor: pointer;
            user-select: none;
        }

        .toggle-row input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: var(--primary);
            cursor: pointer;
            flex-shrink: 0;
        }

        .form-input {
            width: 100%;
            background-color: var(--bg-dark);
            border: 1px solid var(--bg-border);
            border-radius: 0.5rem;
            padding: 0.75rem 1rem;
            color: var(--text-main);
            font-family: inherit;
            font-size: 0.95rem;
            outline: none;
            transition: all 0.2s;
        }

        .form-input:focus {
            border-color: var(--primary-light);
            box-shadow: 0 0 0 2px var(--primary-glow);
        }

        .btn {
            width: 100%;
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            color: white;
            border: none;
            border-radius: 0.5rem;
            padding: 0.85rem 1.5rem;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.25);
        }

        .btn:hover:not(:disabled) {
            transform: translateY(-1px);
            box-shadow: 0 6px 16px rgba(79, 70, 229, 0.4);
            filter: brightness(1.1);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            box-shadow: none;
        }

        .terminal-container {
            display: flex;
            flex-direction: column;
            flex: 1;
        }

        .terminal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .terminal-dots {
            display: flex;
            gap: 0.35rem;
        }

        .dot {
            width: 0.65rem;
            height: 0.65rem;
            border-radius: 50%;
        }
        .dot-red { background-color: #EF4444; }
        .dot-yellow { background-color: #F59E0B; }
        .dot-green { background-color: #10B981; }

        .terminal {
            background-color: #05070C;
            border: 1px solid var(--bg-border);
            border-radius: 0.75rem;
            padding: 1.25rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            color: #10B981;
            height: 200px;
            overflow-y: auto;
            box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.8);
        }

        .terminal-line {
            margin-bottom: 0.35rem;
            word-break: break-all;
        }

        .progress-bar-wrapper {
            margin-top: 1.5rem;
            display: none;
        }

        .progress-meta {
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            margin-bottom: 0.5rem;
        }

        .progress-bg {
            background-color: var(--bg-dark);
            height: 0.5rem;
            border-radius: 100px;
            overflow: hidden;
            border: 1px solid var(--bg-border);
        }

        .progress-fill {
            background: linear-gradient(to right, var(--primary), var(--accent));
            height: 100%;
            width: 0%;
            transition: width 0.4s ease-out;
            box-shadow: 0 0 10px var(--primary);
        }

        .dashboard-content {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 1rem;
        }

        .stat-card {
            background-color: var(--bg-card);
            border: 1px solid var(--bg-border);
            border-radius: 0.75rem;
            padding: 1.25rem 1rem;
            text-align: center;
            position: relative;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
        }

        .stat-card.critical::before { background-color: var(--critical); }
        .stat-card.high::before { background-color: var(--high); }
        .stat-card.medium::before { background-color: var(--medium); }
        .stat-card.low::before { background-color: var(--low); }
        .stat-card.info::before { background-color: var(--info); }

        .stat-num {
            font-size: 2.25rem;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 0.25rem;
            letter-spacing: -0.03em;
        }

        .stat-card.critical .stat-num { color: var(--critical); }
        .stat-card.high .stat-num { color: var(--high); }
        .stat-card.medium .stat-num { color: var(--medium); }
        .stat-card.low .stat-num { color: var(--low); }
        .stat-card.info .stat-num { color: var(--info); }

        .stat-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
        }

        .stat-sub {
            font-size: 0.65rem;
            color: var(--text-muted);
            margin-top: 0.15rem;
        }

        .summary-banner {
            display: grid;
            grid-template-columns: 1fr 220px;
            gap: 1.5rem;
            align-items: center;
        }

        @media (max-width: 768px) {
            .summary-banner {
                grid-template-columns: 1fr;
            }
        }

        .summary-text-block {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .risk-badge {
            display: inline-block;
            align-self: flex-start;
            padding: 0.25rem 0.75rem;
            border-radius: 100px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.05em;
        }

        .risk-badge.critical { background-color: var(--critical-bg); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.3); }
        .risk-badge.high { background-color: var(--high-bg); color: var(--high); border: 1px solid rgba(249, 115, 22, 0.3); }
        .risk-badge.medium { background-color: var(--medium-bg); color: var(--medium); border: 1px solid rgba(234, 179, 8, 0.3); }
        .risk-badge.low { background-color: var(--low-bg); color: var(--low); border: 1px solid rgba(59, 130, 246, 0.3); }
        .risk-badge.minimal { background-color: var(--info-bg); color: var(--info); border: 1px solid rgba(100, 116, 139, 0.3); }

        .summary-description {
            font-size: 0.95rem;
            line-height: 1.6;
            color: var(--text-muted);
        }

        .score-circle-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        .score-svg-wrapper {
            position: relative;
            width: 120px;
            height: 120px;
        }

        .score-circle-bg {
            fill: none;
            stroke: var(--bg-border);
            stroke-width: 8;
        }

        .score-circle-val {
            fill: none;
            stroke: var(--primary);
            stroke-width: 8;
            stroke-linecap: round;
            stroke-dasharray: 339;
            stroke-dashoffset: 339;
            transform: rotate(-90deg);
            transform-origin: 50% 50%;
            transition: stroke-dashoffset 1s ease-out;
        }

        .score-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        .score-num {
            font-size: 1.85rem;
            font-weight: 800;
            line-height: 1;
        }

        .score-label {
            font-size: 0.65rem;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
        }

        .framework-wrapper {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }

        .framework-badge {
            background-color: var(--bg-border);
            color: var(--text-main);
            font-size: 0.75rem;
            padding: 0.2rem 0.65rem;
            border-radius: 100px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .tabs-header {
            display: flex;
            border-bottom: 1px solid var(--bg-border);
            gap: 1.5rem;
        }

        .tab-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            font-family: inherit;
            font-size: 0.95rem;
            font-weight: 600;
            padding-bottom: 0.75rem;
            cursor: pointer;
            position: relative;
            transition: color 0.2s;
        }

        .tab-btn:hover {
            color: var(--text-main);
        }

        .tab-btn.active {
            color: var(--primary-light);
        }

        .tab-btn.active::after {
            content: '';
            position: absolute;
            bottom: -1px;
            left: 0;
            width: 100%;
            height: 2px;
            background-color: var(--primary-light);
        }

        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            margin-top: 1rem;
        }

        .finding-item {
            background-color: var(--bg-card);
            border: 1px solid var(--bg-border);
            border-radius: 0.75rem;
            overflow: hidden;
            transition: all 0.2s;
        }

        .finding-top {
            padding: 1rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }

        .finding-meta {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .severity-badge {
            font-size: 0.7rem;
            font-weight: 700;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .severity-badge.critical { background-color: var(--critical-bg); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.2); }
        .severity-badge.high { background-color: var(--high-bg); color: var(--high); border: 1px solid rgba(249, 115, 22, 0.2); }
        .severity-badge.medium { background-color: var(--medium-bg); color: var(--medium); border: 1px solid rgba(234, 179, 8, 0.2); }
        .severity-badge.low { background-color: var(--low-bg); color: var(--low); border: 1px solid rgba(59, 130, 246, 0.2); }
        .severity-badge.info { background-color: var(--info-bg); color: var(--info); border: 1px solid rgba(100, 116, 139, 0.2); }

        .ai-badge {
            background: linear-gradient(135deg, rgba(79, 70, 229, 0.2), rgba(6, 182, 212, 0.2));
            color: #C084FC;
            border: 1px solid rgba(192, 132, 252, 0.3);
            font-size: 0.65rem;
            font-weight: 700;
            padding: 0.15rem 0.5rem;
            border-radius: 100px;
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        .finding-title {
            font-weight: 600;
            font-size: 0.95rem;
        }

        .finding-arrow {
            color: var(--text-muted);
            transition: transform 0.2s;
        }

        .finding-item.open .finding-arrow {
            transform: rotate(180deg);
        }

        .finding-bottom {
            padding: 0 1.25rem 1.25rem 1.25rem;
            display: none;
            border-top: 1px solid var(--bg-border);
            background-color: rgba(5, 7, 12, 0.2);
        }

        .finding-item.open .finding-bottom {
            display: block;
        }

        .detail-row {
            margin-top: 1rem;
        }

        .detail-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            margin-bottom: 0.25rem;
        }

        .detail-val {
            font-size: 0.9rem;
            line-height: 1.5;
            color: var(--text-main);
        }

        .code-box {
            background-color: #05070C;
            border: 1px solid var(--bg-border);
            border-radius: 0.35rem;
            padding: 0.75rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: var(--text-muted);
            overflow-x: auto;
            margin-top: 0.25rem;
            white-space: pre-wrap;
        }

        .ai-analysis-block {
            background: linear-gradient(135deg, rgba(79, 70, 229, 0.05), rgba(6, 182, 212, 0.05));
            border: 1px solid rgba(79, 70, 229, 0.2);
            border-radius: 0.5rem;
            padding: 1rem;
            margin-top: 1rem;
        }

        .ai-analysis-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .ai-analysis-title {
            font-size: 0.8rem;
            font-weight: 700;
            color: #C084FC;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        .ai-conf-score {
            font-size: 0.75rem;
            font-weight: 600;
        }

        .reports-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
        }

        @media (max-width: 576px) {
            .reports-grid {
                grid-template-columns: 1fr;
            }
        }

        .report-card {
            background-color: var(--bg-card);
            border: 1px solid var(--bg-border);
            border-radius: 0.75rem;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            position: relative;
        }

        .report-card-title {
            font-weight: 600;
            font-size: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .report-card-desc {
            font-size: 0.8rem;
            color: var(--text-muted);
            line-height: 1.4;
            flex: 1;
        }

        .download-btn {
            background: linear-gradient(135deg, var(--accent), #0891B2);
            box-shadow: 0 4px 12px rgba(6, 182, 212, 0.2);
        }

        .empty-state {
            text-align: center;
            padding: 4rem 2rem;
            color: var(--text-muted);
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
        }

        .empty-icon {
            font-size: 3rem;
            opacity: 0.3;
        }

        .spinner {
            width: 1.25rem;
            height: 1.25rem;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-top-color: white;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .payload-collapsible {
            margin-top: 0.75rem;
            border: 1px solid var(--bg-border);
            border-radius: 0.5rem;
            overflow: hidden;
        }

        .payload-header {
            background-color: rgba(30, 41, 59, 0.5);
            padding: 0.5rem 1rem;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            user-select: none;
        }

        .payload-body {
            display: none;
            padding: 0.75rem;
            background-color: #05070C;
        }

        .payload-collapsible.open .payload-body {
            display: block;
        }
    </style>
</head>
<body>

    <header>
        <div class="logo-container">
            <div class="logo-icon">🛡️</div>
            <div class="logo-text">AI DAST SECURITY SCANNER</div>
            <div class="logo-tag">Agentic Core</div>
        </div>
        <div style="font-size: 0.85rem; color: var(--text-muted);">
            Local Orchestrator Status: <span id="server-status" style="color: #10B981; font-weight: 600;">ACTIVE</span>
        </div>
    </header>

    <main>
        <!-- SIDEBAR -->
        <div class="sidebar">
            <div class="card">
                <div class="card-title">🚀 Configure Security Scan</div>
                <div class="form-group">
                    <label class="form-label" for="target-url">Target URL to Scan</label>
                    <input class="form-input" type="url" id="target-url" placeholder="https://example.com" value="https://example.com">
                </div>
                <div class="form-group">
                    <label class="form-label" for="api-key">Gemini API Key (Required for AI Check)</label>
                    <input class="form-input" type="password" id="api-key" placeholder="Enter API Key">
                    <p style="font-size: 0.65rem; color: var(--text-muted); margin-top: 0.25rem;">
                        Provide a Gemini API Key to enable the Validation Agent. If empty, the scanning engine will report ZAP findings directly without mock AI status badges.
                    </p>
                </div>
                <div class="form-group">
                    <label class="toggle-row" for="active-scan">
                        <input type="checkbox" id="active-scan" checked>
                        <span>Enable Active Scan <span style="color: var(--high); font-weight: 600;">(intrusive)</span></span>
                    </label>
                    <p style="font-size: 0.65rem; color: var(--text-muted); margin-top: 0.25rem;">
                        Active scan sends real attack payloads (SQLi, XSS, etc.) — only run it against targets you are authorized to test. Uncheck for a safe <strong>passive-only</strong> scan (spider + response analysis, no attacks).
                    </p>
                </div>

                <button class="btn" id="scan-btn" onclick="startScan()">
                    <span>Start 1-Click Scan</span>
                </button>

                <div class="progress-bar-wrapper" id="progress-wrapper">
                    <div class="progress-meta">
                        <span id="progress-status-text">Recon Agent running...</span>
                        <span id="progress-pct">0%</span>
                    </div>
                    <div class="progress-bg">
                        <div class="progress-fill" id="progress-fill"></div>
                    </div>
                </div>
            </div>

            <div class="terminal-container">
                <div class="terminal-header">
                    <div class="terminal-dots">
                        <div class="dot dot-red"></div>
                        <div class="dot dot-yellow"></div>
                        <div class="dot dot-green"></div>
                    </div>
                    <div style="font-size: 0.75rem; color: var(--text-muted); font-weight: 500; font-family: monospace;">Orchestrator Logs</div>
                </div>
                <div class="terminal" id="log-terminal">
                    <div class="terminal-line">[00:00:00] Ready. Enter target URL and trigger the 1-click pipeline.</div>
                </div>
            </div>
        </div>

        <!-- MAIN DASHBOARD CONTENT -->
        <div class="dashboard-content">
            <div class="card" id="empty-dashboard">
                <div class="empty-state">
                    <div class="empty-icon">🔍</div>
                    <h3>No Scan Active</h3>
                    <p>Enter a website URL in the left-hand panel and click "Start 1-Click Scan" to launch the multi-agent security pipeline.</p>
                </div>
            </div>

            <div id="results-dashboard" style="display: none; flex-direction: column; gap: 1.5rem;">

                <!-- MAIN TABS: RECON / SCAN -->
                <div class="card" style="padding-bottom: 0;">
                    <div class="tabs-header">
                        <button class="tab-btn active" id="maintab-recon" onclick="switchMainTab('recon')">🔎 Recon</button>
                        <button class="tab-btn" id="maintab-scan" onclick="switchMainTab('scan')">🛡️ Scan</button>
                    </div>
                </div>

                <!-- RECON PANEL -->
                <div id="recon-panel" style="display: flex; flex-direction: column; gap: 1.5rem;">
                    <div class="card">
                        <div class="card-title">🔎 Reconnaissance Summary</div>
                        <div class="stats-grid" style="margin-bottom: 1.25rem;">
                            <div class="stat-card">
                                <span class="stat-num" id="recon-pages">0</span>
                                <span class="stat-label">Pages Crawled</span>
                                <span class="stat-sub">Recon Agent</span>
                            </div>
                            <div class="stat-card">
                                <span class="stat-num" id="recon-forms">0</span>
                                <span class="stat-label">Forms Found</span>
                                <span class="stat-sub">Attack surface</span>
                            </div>
                            <div class="stat-card">
                                <span class="stat-num" id="recon-tech">0</span>
                                <span class="stat-label">Technologies</span>
                                <span class="stat-sub">Detected</span>
                            </div>
                        </div>
                        <div class="detail-row">
                            <div class="detail-label">Target</div>
                            <div class="detail-val"><code id="recon-target">-</code></div>
                        </div>
                        <div class="detail-row">
                            <div class="detail-label">Selected Scan Profile</div>
                            <div class="detail-val" id="recon-profile">-</div>
                        </div>
                        <div class="detail-row">
                            <div class="detail-label">Scan Mode</div>
                            <div class="detail-val" id="recon-scanmode">-</div>
                        </div>
                        <div class="detail-row">
                            <div class="detail-label">Detected Technology Stack</div>
                            <div class="framework-wrapper" id="recon-frameworks"></div>
                        </div>
                        <div class="detail-row">
                            <div class="detail-label">Crawled Endpoints</div>
                            <div class="code-box" id="recon-endpoints" style="max-height: 260px; overflow:auto;">-</div>
                        </div>
                    </div>
                </div>

                <!-- SCAN PANEL -->
                <div id="scan-panel" style="display: none; flex-direction: column; gap: 1.5rem;">

                <!-- SUMMARY BANNER -->
                <div class="card">
                    <div class="summary-banner">
                        <div class="summary-text-block">
                            <span class="risk-badge" id="risk-badge">MEDIUM RISK</span>
                            <h2 style="font-size: 1.5rem; font-weight: 700; margin-top: 0.5rem;" id="results-target-title">Target: example.com</h2>
                            <p class="summary-description" id="risk-summary">
                                Scan summary description will be generated and placed here by the Report Agent.
                            </p>
                            <div class="framework-wrapper" id="frameworks-container">
                            </div>
                        </div>

                        <div class="score-circle-container">
                            <div class="score-svg-wrapper">
                                <svg width="120" height="120">
                                    <circle class="score-circle-bg" cx="60" cy="60" r="54"></circle>
                                    <circle class="score-circle-val" id="score-circle" cx="60" cy="60" r="54"></circle>
                                </svg>
                                <div class="score-text">
                                    <span class="score-num" id="risk-score-num">0</span>
                                    <span class="score-label">Risk Score</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- STATS ROW -->
                <div class="stats-grid">
                    <div class="stat-card critical">
                        <span class="stat-num" id="stat-crit">0</span>
                        <span class="stat-label">Critical</span>
                        <span class="stat-sub" id="stat-crit-val">0 Validated</span>
                    </div>
                    <div class="stat-card high">
                        <span class="stat-num" id="stat-high">0</span>
                        <span class="stat-label">High</span>
                        <span class="stat-sub" id="stat-high-val">0 Validated</span>
                    </div>
                    <div class="stat-card medium">
                        <span class="stat-num" id="stat-med">0</span>
                        <span class="stat-label">Medium</span>
                        <span class="stat-sub">ZAP Scan</span>
                    </div>
                    <div class="stat-card low">
                        <span class="stat-num" id="stat-low">0</span>
                        <span class="stat-label">Low</span>
                        <span class="stat-sub">ZAP Scan</span>
                    </div>
                    <div class="stat-card info">
                        <span class="stat-num" id="stat-info">0</span>
                        <span class="stat-label">Info</span>
                        <span class="stat-sub">ZAP Scan</span>
                    </div>
                </div>

                <!-- REPORTS DOWNLOAD -->
                <div class="card" id="reports-section" style="display: none;">
                    <div class="card-title">📄 Download PDF Security Reports</div>
                    <div class="reports-grid">
                        <div class="report-card">
                            <div class="report-card-title">📊 Executive Summary Report</div>
                            <div class="report-card-desc">
                                High-level summary designed for business stakeholders and managers. Highlights risk profile, operational impact, and strategic recommendations.
                            </div>
                            <a href="/download/executive" class="btn download-btn">Download Executive PDF</a>
                        </div>
                        <div class="report-card">
                            <div class="report-card-title">💻 Technical Vulnerability Report</div>
                            <div class="report-card-desc">
                                Comprehensive vulnerability breakdown for engineering teams. Contains full evidence, confidence scores, and AI validation analysis for every alert.
                            </div>
                            <a href="/download/technical" class="btn download-btn">Download Technical PDF</a>
                        </div>
                    </div>
                </div>

                <!-- DETAILED FINDINGS TABS -->
                <div class="card">
                    <div class="tabs-header">
                        <button class="tab-btn active" id="tab-validated" onclick="switchTab('validated')">High & Critical Alerts</button>
                        <button class="tab-btn" id="tab-all" onclick="switchTab('all')">All Raw Findings</button>
                    </div>

                    <div class="findings-list" id="findings-container">
                    </div>
                </div>

                </div>
                <!-- /SCAN PANEL -->

            </div>
        </div>
    </main>

    <script>
        let currentTab = 'validated';
        let scanResultsData = null;
        let pollInterval = null;

        // Escape ALL scan-derived text before injecting via innerHTML. ZAP evidence and
        // HTTP response bodies routinely contain raw HTML (e.g. <script>, </div>); injecting
        // it unescaped corrupts the page DOM (the dashboard's background/layout vanished when
        // opening "All Raw Findings") and is an XSS vector. Renders such content as literal text.
        function escapeHtml(s) {
            if (s === null || s === undefined) return '';
            return String(s)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function startScan() {
            const urlInput = document.getElementById('target-url').value;
            const apiKeyInput = document.getElementById('api-key').value;
            const activeScan = document.getElementById('active-scan').checked;

            if (!urlInput) {
                alert("Please enter a valid target URL");
                return;
            }

            document.getElementById('scan-btn').disabled = true;
            document.getElementById('scan-btn').innerHTML = '<div class="spinner"></div> Running Scan...';
            document.getElementById('progress-wrapper').style.display = 'block';
            document.getElementById('log-terminal').innerHTML = '';
            
            document.getElementById('empty-dashboard').style.display = 'none';
            document.getElementById('results-dashboard').style.display = 'flex';
            document.getElementById('reports-section').style.display = 'none';
            switchMainTab('recon');
            document.getElementById('results-target-title').innerText = "Scanning: " + urlInput;
            document.getElementById('risk-summary').innerText = "The Orchestrator is running. Recon and vulnerability checks are active...";
            
            fetch('/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlInput, api_key: apiKeyInput, active_scan: activeScan })
            })
            .then(res => res.json())
            .then(data => {
                if (pollInterval) clearInterval(pollInterval);
                pollInterval = setInterval(pollScanStatus, 1000);
            })
            .catch(err => {
                console.error("Scan launch failed:", err);
                resetScanButton();
            });
        }

        function pollScanStatus() {
            fetch('/status')
            .then(res => res.json())
            .then(state => {
                const terminal = document.getElementById('log-terminal');
                const wasScrolledDown = terminal.scrollHeight - terminal.clientHeight <= terminal.scrollTop + 10;
                
                terminal.innerHTML = state.logs.map(log => `<div class="terminal-line">${escapeHtml(log)}</div>`).join('');
                if (wasScrolledDown) {
                    terminal.scrollTop = terminal.scrollHeight;
                }

                document.getElementById('progress-pct').innerText = state.progress + "%";
                document.getElementById('progress-fill').style.width = state.progress + "%";
                
                let stepMsg = "Orchestrator running...";
                if (state.progress < 20) stepMsg = "Recon Agent analyzing framework...";
                else if (state.progress < 50) stepMsg = "Scan Agent running DAST scanner...";
                else if (state.progress < 75) stepMsg = "Validation Agent verifying High/Critical findings...";
                else if (state.progress < 90) stepMsg = "Report Agent calculating Risk Metrics...";
                else if (state.progress < 100) stepMsg = "PDF Generator building reports...";
                else stepMsg = "Scan completed successfully.";
                
                document.getElementById('progress-status-text').innerText = stepMsg;

                if (state.status === 'completed') {
                    clearInterval(pollInterval);
                    scanResultsData = state.results;
                    renderScanResults();
                    resetScanButton();
                    document.getElementById('reports-section').style.display = 'block';
                } else if (state.status === 'failed') {
                    clearInterval(pollInterval);
                    alert("Scan failed: " + state.error_message);
                    resetScanButton();
                }
            });
        }

        function resetScanButton() {
            document.getElementById('scan-btn').disabled = false;
            document.getElementById('scan-btn').innerHTML = 'Start 1-Click Scan';
        }

        function renderScanResults() {
            if (!scanResultsData) return;

            document.getElementById('results-target-title').innerText = "Target: " + scanResultsData.target_url;
            document.getElementById('risk-summary').innerText = scanResultsData.executive_summary;

            const score = scanResultsData.risk_score;
            document.getElementById('risk-score-num').innerText = score;
            const circle = document.getElementById('score-circle');
            const offset = 339 - (score / 100) * 339;
            circle.style.strokeDashoffset = offset;
            
            let circleColor = "var(--low)";
            if (score >= 80) circleColor = "var(--critical)";
            else if (score >= 55) circleColor = "var(--high)";
            else if (score >= 30) circleColor = "var(--medium)";
            circle.style.stroke = circleColor;

            const badge = document.getElementById('risk-badge');
            badge.innerText = scanResultsData.risk_desc;
            badge.className = "risk-badge " + scanResultsData.risk_desc.split(' ')[0].toLowerCase();

            document.getElementById('stat-crit').innerText = scanResultsData.stats.critical;
            document.getElementById('stat-crit-val').innerText = (scanResultsData.ai_used ? scanResultsData.stats.critical_validated : scanResultsData.stats.critical) + (scanResultsData.ai_used ? " Validated" : " Active");
            
            document.getElementById('stat-high').innerText = scanResultsData.stats.high;
            document.getElementById('stat-high-val').innerText = (scanResultsData.ai_used ? scanResultsData.stats.high_validated : scanResultsData.stats.high) + (scanResultsData.ai_used ? " Validated" : " Active");
            
            document.getElementById('stat-med').innerText = scanResultsData.stats.medium;
            document.getElementById('stat-low').innerText = scanResultsData.stats.low;
            document.getElementById('stat-info').innerText = scanResultsData.stats.informational;

            const fwContainer = document.getElementById('frameworks-container');
            fwContainer.innerHTML = scanResultsData.frameworks.map(fw => `<span class="framework-badge">${escapeHtml(fw)}</span>`).join('');

            renderReconResults();
            renderFindingsList();
        }

        function switchMainTab(name) {
            document.getElementById('maintab-recon').className = name === 'recon' ? 'tab-btn active' : 'tab-btn';
            document.getElementById('maintab-scan').className = name === 'scan' ? 'tab-btn active' : 'tab-btn';
            document.getElementById('recon-panel').style.display = name === 'recon' ? 'flex' : 'none';
            document.getElementById('scan-panel').style.display = name === 'scan' ? 'flex' : 'none';
        }

        function renderReconResults() {
            if (!scanResultsData) return;
            document.getElementById('recon-target').innerText = scanResultsData.target_url;
            document.getElementById('recon-profile').innerText = scanResultsData.scan_profile || 'Standard Profile';
            document.getElementById('recon-scanmode').innerHTML = (scanResultsData.active_scan === false)
                ? 'Passive only <span style="color:var(--text-muted);">(spider + response analysis, no attack payloads)</span>'
                : 'Active + Passive <span style="color:var(--high);">(intrusive attack payloads)</span>';
            document.getElementById('recon-pages').innerText = scanResultsData.pages_crawled_count || 0;
            document.getElementById('recon-forms').innerText = scanResultsData.forms_found_count || 0;

            const fws = scanResultsData.frameworks || [];
            document.getElementById('recon-tech').innerText = fws.length;
            document.getElementById('recon-frameworks').innerHTML = fws.length
                ? fws.map(fw => `<span class="framework-badge">${escapeHtml(fw)}</span>`).join('')
                : '<span style="color:var(--text-muted);">None detected</span>';

            const pages = scanResultsData.pages_crawled || [];
            document.getElementById('recon-endpoints').innerText = pages.length
                ? pages.join('\\n')
                : 'No endpoints recorded.';
        }

        function switchTab(tabName) {
            document.getElementById('tab-validated').className = tabName === 'validated' ? 'tab-btn active' : 'tab-btn';
            document.getElementById('tab-all').className = tabName === 'all' ? 'tab-btn active' : 'tab-btn';
            currentTab = tabName;
            renderFindingsList();
        }

        function renderFindingsList() {
            if (!scanResultsData) return;

            const container = document.getElementById('findings-container');
            container.innerHTML = '';

            let list = [];
            if (currentTab === 'validated') {
                list = scanResultsData.findings.filter(f => (f.risk.toLowerCase() === 'critical' || f.risk.toLowerCase() === 'high') && !f.is_duplicate);
            } else {
                list = scanResultsData.findings.filter(f => !f.is_duplicate);
            }

            if (list.length === 0) {
                container.innerHTML = `<div class="empty-state" style="padding:2rem;"><p>No findings found matching this tab.</p></div>`;
                return;
            }

            list.forEach(finding => {
                const isAIEnriched = scanResultsData.ai_used && ('ai_confidence' in finding);
                const fpText = finding.is_false_positive ? 'Probable False Positive' : 'Verified True Positive';
                
                const item = document.createElement('div');
                item.className = 'finding-item';
                
                const isFpClass = (scanResultsData.ai_used && finding.is_false_positive) ? 'info' : finding.risk.toLowerCase();
                const sevName = (scanResultsData.ai_used && finding.is_false_positive) ? 'FP' : finding.risk;
                
                let aiBadgeHTML = '';
                if (isAIEnriched) {
                    aiBadgeHTML = `
                        <div class="ai-badge">
                            ✨ AI Checked
                        </div>
                    `;
                }

                let httpAuditsHTML = '';
                if (finding.request_header || finding.response_header) {
                    httpAuditsHTML = `
                        <div class="detail-row">
                            <div class="detail-label">HTTP Transaction Audit Payloads</div>
                            
                            ${finding.request_header ? `
                            <div class="payload-collapsible">
                                <div class="payload-header" onclick="this.parentElement.classList.toggle('open')">
                                    <span>🌐 HTTP Request Headers & Body</span>
                                    <span>▼</span>
                                </div>
                                <div class="payload-body">
                                    <div class="code-box">${escapeHtml(finding.request_header)}\n\n${escapeHtml(finding.request_body || '')}</div>
                                </div>
                            </div>
                            ` : ''}

                            ${finding.response_header ? `
                            <div class="payload-collapsible">
                                <div class="payload-header" onclick="this.parentElement.classList.toggle('open')">
                                    <span>📥 HTTP Response Headers & Preview</span>
                                    <span>▼</span>
                                </div>
                                <div class="payload-body">
                                    <div class="code-box">${escapeHtml(finding.response_header)}\n\n${escapeHtml(finding.response_body || '')}</div>
                                </div>
                            </div>
                            ` : ''}
                        </div>
                    `;
                }

                // Title prefix for False Positives
                const isFp = scanResultsData.ai_used && finding.is_false_positive;
                const titlePrefix = isFp ? '<span style="color:var(--text-muted);">[FALSE POSITIVE]</span> ' : '';

                item.innerHTML = `
                    <div class="finding-top" onclick="this.parentElement.classList.toggle('open')">
                        <div class="finding-meta">
                            <span class="severity-badge ${isFpClass}">${escapeHtml(sevName)}</span>
                            <span class="finding-title">${titlePrefix}${escapeHtml(finding.alert)}</span>
                            ${aiBadgeHTML}
                        </div>
                        <div class="finding-arrow">▼</div>
                    </div>
                    <div class="finding-bottom">
                        <div class="detail-row">
                            <div class="detail-label">Vulnerable Endpoint / Parameter</div>
                            <div class="detail-val">
                                ${finding.affected_urls && finding.affected_urls.length > 1 ? `
                                    <ul style="margin: 0; padding-left: 1.2rem;">
                                        ${finding.affected_urls.map(u => `<li><code>${escapeHtml(u)}</code></li>`).join('')}
                                    </ul>
                                ` : `
                                    <code>${escapeHtml(finding.url)}</code>
                                `}
                                ${finding.parameter ? `(Parameter: <code>${escapeHtml(finding.parameter)}</code>)` : ''}
                            </div>
                        </div>

                        ${finding.cwe_full ? `
                        <div class="detail-row">
                            <div class="detail-label">CWE Classification</div>
                            <div class="detail-val">${escapeHtml(finding.cwe_full)}</div>
                        </div>
                        ` : ''}

                        ${finding.owasp_full ? `
                        <div class="detail-row">
                            <div class="detail-label">OWASP Top 10 Category</div>
                            <div class="detail-val">${escapeHtml(finding.owasp_full)}</div>
                        </div>
                        ` : ''}

                        ${finding.cve_full && finding.cve_full !== 'N/A' ? `
                        <div class="detail-row">
                            <div class="detail-label">CVE Reference</div>
                            <div class="detail-val">${escapeHtml(finding.cve_full)}</div>
                        </div>
                        ` : ''}

                        <div class="detail-row">
                            <div class="detail-label">Vulnerability Description</div>
                            <div class="detail-val">${escapeHtml(finding.description)}</div>
                        </div>

                        ${finding.evidence ? `
                        <div class="detail-row">
                            <div class="detail-label">Scan Evidence</div>
                            <div class="code-box">${escapeHtml(finding.evidence)}</div>
                        </div>
                        ` : ''}

                        <div class="detail-row">
                            <div class="detail-label">Remediation Action</div>
                            <div class="detail-val">${escapeHtml(finding.solution)}</div>
                        </div>

                        ${httpAuditsHTML}

                        ${isAIEnriched ? `
                        <div class="ai-analysis-block">
                            <div class="ai-analysis-header">
                                <span class="ai-analysis-title">✨ Validation Agent Analysis</span>
                                <span class="ai-conf-score" style="color: ${finding.is_false_positive ? 'var(--info)' : 'var(--primary-light)'}">
                                    AI Confidence: ${Math.round(finding.ai_confidence * 100)}% (${fpText})
                                </span>
                            </div>
                            <div class="detail-val" style="font-style: italic; color: #E2E8F0;">
                                "${escapeHtml(finding.ai_reasoning)}"
                            </div>
                        </div>
                        ` : ''}
                    </div>
                `;
                container.appendChild(item);
            });
        }
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route("/scan", methods=["POST"])
def scan():
    global scan_state
    
    with scan_lock:
        if scan_state["status"] == "running":
            return jsonify({"error": "A scan is already active."}), 400
            
    payload = request.json or {}
    url = payload.get("url", "https://example.com").strip()
    api_key = payload.get("api_key", "").strip() or None
    active_scan = bool(payload.get("active_scan", True))

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    t = threading.Thread(target=run_dast_pipeline_thread, args=(url, api_key, active_scan))
    t.daemon = True
    t.start()
    
    return jsonify({"message": "DAST scanner started successfully.", "target_url": url})

@app.route("/status")
def status():
    with scan_lock:
        return jsonify({
            "status": scan_state["status"],
            "progress": scan_state["progress"],
            "logs": scan_state["logs"],
            "target_url": scan_state["target_url"],
            "error_message": scan_state["error_message"],
            "results": scan_state["results"]
        })

@app.route("/download/<report_type>")
def download(report_type):
    with scan_lock:
        filepath = scan_state.get("exec_pdf") if report_type == "executive" else scan_state.get("tech_pdf")

    if filepath and os.path.exists(filepath):
        # Serve under a clean, stable download name regardless of the scan-id suffix.
        download_name = "Executive_Report.pdf" if report_type == "executive" else "Technical_VA_Report.pdf"
        return send_file(filepath, as_attachment=True, download_name=download_name)
    else:
        return "Report file not found. Run a scan first.", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
