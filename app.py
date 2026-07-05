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

        pipeline_start = time.time()
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
            # Build a safe id -> risk lookup once. Tolerate malformed AI output
            # (missing 'id') so counting never crashes the pipeline after a
            # validation that otherwise succeeded.
            risk_by_id = {x.get('id'): str(x.get('risk', '')).lower() for x in scan_results['findings']}
            def _count(is_fp, sev):
                return sum(
                    1 for f in validated_findings
                    if bool(f.get('is_false_positive')) == is_fp
                    and risk_by_id.get(f.get('id'), '') == sev
                )
            tp_crit, tp_high = _count(False, 'critical'), _count(False, 'high')
            fp_crit, fp_high = _count(True, 'critical'), _count(True, 'high')
            if validated_findings:
                add_log(f"Validation Agent completed. AI verified {tp_crit} Critical / {tp_high} High as True Positives, and flagged {fp_crit} Critical / {fp_high} High as False Positives.")
            else:
                add_log("Validation Agent completed, but AI validation returned no results (e.g. API timeout or error) — findings reported straight from ZAP. See server logs.")
        else:
            add_log("Validation Agent completed. Dynamic AI verification skipped.")

        # Step 4: Report Agent
        scan_state["progress"] = 80
        add_log("Invoking Report Agent to compile findings and compute risk metrics...")
        reporter = ReportAgent(target_url, scan_config, scan_results["findings"], validated_findings, scan_id=scan_results.get("scan_id"), api_key=api_key)
        report_data = reporter.run()
        report_data["scan_duration_seconds"] = int(time.time() - pipeline_start)
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


# Dashboard SPA — a security console with explicit scanner-vs-AI provenance.
DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI DAST Security Report</title>
    <style>
        :root {
            --bg: #0A0E17;
            --surface: #111a2b;
            --surface-2: #0d1524;
            --raise: #162134;
            --border: #223049;
            --border-soft: #1a2740;
            --text: #E7EDF8;
            --muted: #8a97af;
            --faint: #5f6d86;

            --accent: #6d78f2;
            --ai: #a78bfa;
            --ai-strong: #8b5cf6;
            --ai-soft: rgba(167,139,250,.14);
            --ai-line: rgba(167,139,250,.34);

            --crit: #f04e63;
            --high: #f5934a;
            --med:  #e2b53c;
            --low:  #57a0f5;
            --info: #77869f;

            --tp: #38b98a;
            --tp-soft: rgba(56,185,138,.13);
            --fp: #d09a34;
            --fp-soft: rgba(208,154,52,.13);

            --ok: #38b98a;

            --font-sans: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --font-mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;

            --r: 14px;
            --r-sm: 9px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: var(--font-sans);
            background:
                radial-gradient(900px 500px at 88% -8%, color-mix(in srgb, var(--ai) 12%, transparent), transparent 60%),
                radial-gradient(760px 460px at -6% 4%, color-mix(in srgb, var(--accent) 10%, transparent), transparent 55%),
                var(--bg);
            color: var(--text);
            min-height: 100vh;
            line-height: 1.55;
            -webkit-font-smoothing: antialiased;
        }
        .mono { font-family: var(--font-mono); font-variant-numeric: tabular-nums; }
        a { color: var(--accent); text-decoration: none; }
        :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }

        /* ---- header ---- */
        header {
            border-bottom: 1px solid var(--border);
            background: color-mix(in srgb, var(--surface) 60%, transparent);
            backdrop-filter: blur(12px);
            padding: 1rem 1.75rem;
            display: flex; justify-content: space-between; align-items: center; gap: 1rem;
            position: sticky; top: 0; z-index: 20;
        }
        .brand { display: flex; align-items: center; gap: .8rem; }
        .brand .mark {
            width: 38px; height: 38px; border-radius: 10px; display: grid; place-items: center; font-size: 19px;
            background: linear-gradient(140deg, var(--accent), var(--ai-strong));
            box-shadow: 0 6px 20px -6px color-mix(in srgb, var(--ai) 60%, transparent);
        }
        .brand h1 { font-size: 14px; letter-spacing: .04em; font-weight: 700; }
        .brand p { font-size: 11.5px; color: var(--muted); }
        .status-tag { font-size: .8rem; color: var(--muted); }
        .status-tag b { color: var(--ok); font-weight: 600; }

        main {
            max-width: 1360px; margin: 0 auto; padding: 1.75rem;
            display: grid; grid-template-columns: 340px 1fr; gap: 1.5rem; align-items: start;
        }
        @media (max-width: 1024px) { main { grid-template-columns: 1fr; } }

        /* ---- shared card ---- */
        .card {
            background: linear-gradient(180deg, var(--surface), var(--surface-2));
            border: 1px solid var(--border); border-radius: var(--r); padding: 1.25rem;
        }
        .card-label { font-size: 11px; letter-spacing: .12em; text-transform: uppercase; color: var(--faint); font-weight: 700; margin-bottom: .9rem; }

        /* ---- sidebar ---- */
        .sidebar { display: flex; flex-direction: column; gap: 1.25rem; position: sticky; top: 90px; }
        .form-group { margin-bottom: 1rem; }
        .form-label { display: block; font-size: .82rem; color: var(--muted); margin-bottom: .4rem; font-weight: 500; }
        .form-input {
            width: 100%; background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--r-sm);
            padding: .7rem .85rem; color: var(--text); font-family: inherit; font-size: .9rem; outline: none; transition: border-color .15s, box-shadow .15s;
        }
        .form-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 22%, transparent); }
        .hint { font-size: .68rem; color: var(--faint); margin-top: .35rem; line-height: 1.45; }
        .toggle-row { display: flex; align-items: center; gap: .55rem; font-size: .85rem; font-weight: 500; cursor: pointer; user-select: none; }
        .toggle-row input { width: 17px; height: 17px; accent-color: var(--accent); cursor: pointer; }
        .btn {
            width: 100%; border: none; border-radius: var(--r-sm); padding: .8rem 1.25rem; font-size: .9rem; font-weight: 650;
            cursor: pointer; color: #fff; font-family: inherit; display: flex; align-items: center; justify-content: center; gap: .5rem;
            background: linear-gradient(135deg, var(--accent), var(--ai-strong));
            box-shadow: 0 6px 18px -6px color-mix(in srgb, var(--accent) 70%, transparent); transition: filter .15s, transform .1s;
        }
        .btn:hover:not(:disabled) { filter: brightness(1.08); transform: translateY(-1px); }
        .btn:disabled { opacity: .6; cursor: not-allowed; }

        .progress-wrapper { margin-top: 1.1rem; display: none; }
        .progress-meta { display: flex; justify-content: space-between; font-size: .78rem; color: var(--muted); margin-bottom: .4rem; }
        .progress-bg { height: 7px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 100px; overflow: hidden; }
        .progress-fill { height: 100%; width: 0%; background: linear-gradient(90deg, var(--accent), var(--ai)); transition: width .4s ease; }

        .terminal-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: .5rem; }
        .dots { display: flex; gap: .3rem; }
        .dot { width: .6rem; height: .6rem; border-radius: 50%; }
        .dot-r { background: var(--crit); } .dot-y { background: var(--med); } .dot-g { background: var(--ok); }
        .terminal {
            background: #05070c; border: 1px solid var(--border); border-radius: var(--r-sm); padding: .9rem;
            font-family: var(--font-mono); font-size: .78rem; line-height: 1.5; color: var(--ok); height: 200px; overflow-y: auto;
        }
        .terminal-line { margin-bottom: .3rem; word-break: break-word; }

        /* ---- content ---- */
        .content { display: flex; flex-direction: column; gap: 1.5rem; min-width: 0; }
        .empty-state { text-align: center; padding: 4rem 2rem; color: var(--muted); display: flex; flex-direction: column; align-items: center; gap: .8rem; }
        .empty-icon { font-size: 2.6rem; opacity: .35; }

        /* main tabs */
        .maintabs { display: flex; gap: 1.5rem; border-bottom: 1px solid var(--border); }
        .maintab { background: none; border: none; color: var(--muted); font-family: inherit; font-size: .95rem; font-weight: 600; padding: 0 0 .7rem; cursor: pointer; position: relative; }
        .maintab.active { color: var(--text); }
        .maintab.active::after { content: ""; position: absolute; bottom: -1px; left: 0; right: 0; height: 2px; background: var(--accent); }

        /* ---- overview ---- */
        .overview { display: grid; grid-template-columns: 290px 1fr; gap: 1rem; }
        @media (max-width: 720px) { .overview { grid-template-columns: 1fr; } }
        .risk-card { display: flex; flex-direction: column; align-items: center; text-align: center; }
        .dial { position: relative; width: 160px; height: 160px; }
        .dial svg { transform: rotate(-90deg); }
        .dial .track { fill: none; stroke: var(--border); stroke-width: 11; }
        .dial .val { fill: none; stroke-width: 11; stroke-linecap: round; transition: stroke-dashoffset 1s ease, stroke .4s; }
        .dial .center { position: absolute; inset: 0; display: grid; place-content: center; }
        .dial .num { font-size: 42px; font-weight: 800; letter-spacing: -.02em; font-variant-numeric: tabular-nums; line-height: 1; }
        .dial .den { font-size: 11px; color: var(--muted); }
        .risk-band { margin-top: 1rem; font-size: 11.5px; font-weight: 700; letter-spacing: .07em; text-transform: uppercase; padding: 5px 14px; border-radius: 100px; }
        .risk-note { font-size: 12.5px; color: var(--muted); margin-top: .9rem; }

        .ov-right { display: grid; grid-template-rows: auto auto; gap: 1rem; }
        .ai-summary { border-color: var(--ai-line); background: linear-gradient(180deg, color-mix(in srgb, var(--ai) 9%, var(--surface)), var(--surface-2)); }
        .ai-summary .card-label { color: var(--ai); }
        .ai-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: .9rem; }
        @media (max-width: 560px) { .ai-stats { grid-template-columns: repeat(2, 1fr); } }
        .ai-stat .n { font-size: 24px; font-weight: 800; font-variant-numeric: tabular-nums; letter-spacing: -.02em; }
        .ai-stat .l { font-size: 11px; color: var(--muted); margin-top: 1px; }
        .ai-stat.reviewed .n { color: var(--ai); } .ai-stat.tp .n { color: var(--tp); } .ai-stat.fp .n { color: var(--fp); }
        .ai-none { font-size: 13px; color: var(--muted); }
        .ai-none b { color: var(--ai); }

        .dist { display: grid; gap: .65rem; }
        .dist-row { display: grid; grid-template-columns: 74px 1fr 26px; align-items: center; gap: .7rem; }
        .dist-name { font-size: 11.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; }
        .dist-track { height: 8px; background: var(--border-soft); border-radius: 100px; overflow: hidden; }
        .dist-fill { height: 100%; border-radius: 100px; transition: width .5s ease; }
        .dist-n { font-size: 12.5px; font-weight: 700; text-align: right; font-variant-numeric: tabular-nums; }
        .sev-crit { background: var(--crit); } .sev-high { background: var(--high); } .sev-med { background: var(--med); } .sev-low { background: var(--low); } .sev-info { background: var(--info); }
        .c-crit { color: var(--crit); } .c-high { color: var(--high); } .c-med { color: var(--med); } .c-low { color: var(--low); } .c-info { color: var(--info); }

        /* strip: owasp + coverage */
        .strip { display: grid; grid-template-columns: 1fr 330px; gap: 1rem; }
        @media (max-width: 720px) { .strip { grid-template-columns: 1fr; } }
        .owasp-row { display: grid; grid-template-columns: 1fr auto; gap: .6rem; align-items: center; padding: .55rem 0; border-bottom: 1px solid var(--border-soft); }
        .owasp-row:last-child { border-bottom: 0; }
        .owasp-cat { font-size: 12.5px; }
        .owasp-cat .code { font-family: var(--font-mono); font-size: 11px; color: var(--faint); margin-right: .5rem; }
        .owasp-count { font-size: 11.5px; color: var(--muted); white-space: nowrap; font-variant-numeric: tabular-nums; }
        .coverage { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; background: var(--border-soft); border-radius: var(--r-sm); overflow: hidden; }
        .cov-tile { background: var(--surface); padding: .8rem .9rem; }
        .cov-tile .n { font-size: 19px; font-weight: 800; font-variant-numeric: tabular-nums; }
        .cov-tile .l { font-size: 11px; color: var(--muted); margin-top: 1px; }
        .cov-mode { grid-column: 1 / -1; display: flex; align-items: center; gap: .5rem; font-size: 12px; color: var(--muted); }
        .cov-mode .pill { font-size: 10.5px; font-weight: 700; letter-spacing: .03em; padding: 3px 8px; border-radius: 6px; }
        .pill-active { background: color-mix(in srgb, var(--high) 15%, transparent); color: var(--high); border: 1px solid color-mix(in srgb, var(--high) 30%, transparent); }
        .pill-passive { background: color-mix(in srgb, var(--low) 15%, transparent); color: var(--low); border: 1px solid color-mix(in srgb, var(--low) 30%, transparent); }

        /* recon */
        .recon-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 1rem; }
        @media (max-width: 560px) { .recon-grid { grid-template-columns: 1fr 1fr; } }
        .recon-tile { text-align: center; background: var(--surface-2); border: 1px solid var(--border-soft); border-radius: var(--r-sm); padding: 1rem; }
        .recon-tile .n { font-size: 26px; font-weight: 800; }
        .recon-tile .l { font-size: 11px; color: var(--muted); }
        .drow { margin-top: .9rem; }
        .dlabel { font-size: 11px; font-weight: 600; color: var(--faint); text-transform: uppercase; letter-spacing: .06em; margin-bottom: .3rem; }
        .dval { font-size: .9rem; }
        .code-box { background: #05070c; border: 1px solid var(--border-soft); border-radius: var(--r-sm); padding: .7rem; font-family: var(--font-mono); font-size: .78rem; color: var(--muted); white-space: pre-wrap; word-break: break-word; max-height: 240px; overflow: auto; }
        .fw-wrap { display: flex; flex-wrap: wrap; gap: .4rem; }
        .fw-badge { background: var(--raise); border: 1px solid var(--border-soft); border-radius: 100px; font-size: 11.5px; padding: .2rem .6rem; color: var(--text); }

        /* reports */
        .reports-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
        @media (max-width: 560px) { .reports-grid { grid-template-columns: 1fr; } }
        .report-card { background: var(--surface-2); border: 1px solid var(--border-soft); border-radius: var(--r-sm); padding: 1rem; display: flex; flex-direction: column; gap: .6rem; }
        .report-card .t { font-weight: 600; font-size: .95rem; }
        .report-card .d { font-size: .78rem; color: var(--muted); flex: 1; line-height: 1.45; }
        .dl-btn { background: linear-gradient(135deg, var(--accent), var(--ai-strong)); }

        /* provenance legend */
        .legend { display: flex; flex-wrap: wrap; gap: .5rem 1.4rem; align-items: center; font-size: 12px; color: var(--muted); margin-bottom: .25rem; }
        .legend .item { display: inline-flex; align-items: center; gap: .45rem; }
        .glyph { font-family: var(--font-mono); font-weight: 700; }
        .glyph.scan { color: var(--info); } .glyph.ai { color: var(--ai); }

        /* finding tabs */
        .ftabs { display: flex; gap: 1.2rem; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }
        .ftab { background: none; border: none; color: var(--muted); font-family: inherit; font-size: .9rem; font-weight: 600; padding: 0 0 .65rem; cursor: pointer; position: relative; }
        .ftab.active { color: var(--text); }
        .ftab.active::after { content: ""; position: absolute; bottom: -1px; left: 0; right: 0; height: 2px; background: var(--accent); }

        /* finding card */
        .findings { display: grid; gap: .9rem; }
        .finding {
            position: relative;
            background: linear-gradient(180deg, var(--surface), var(--surface-2));
            border: 1px solid var(--border);
            border-radius: var(--r);
            overflow: hidden;
            padding-left: 4px;
            display: block;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .finding[open] {
            border-color: var(--accent);
            box-shadow: 0 0 0 1px var(--accent);
        }
        .stripe {
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
        }
        .finding[data-sev="critical"] .stripe { background: var(--crit); }
        .finding[data-sev="high"] .stripe { background: var(--high); }
        .finding[data-sev="medium"] .stripe { background: var(--med); }
        .finding[data-sev="low"] .stripe { background: var(--low); }
        .finding[data-sev="informational"] .stripe { background: var(--info); }
        .finding.is-fp .stripe { background: var(--fp); }
        .fsummary {
            display: flex;
            cursor: pointer;
            user-select: none;
            outline: none;
            list-style: none;
        }
        .fsummary::-webkit-details-marker { display: none; }
        .fsummary-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
            width: 100%;
            padding: 1.1rem;
            gap: 1rem;
        }
        .fsummary-left {
            display: flex;
            align-items: center;
            gap: .75rem;
            min-width: 0;
            flex: 1;
        }
        .fsummary-right {
            display: flex;
            align-items: center;
            gap: .8rem;
            white-space: nowrap;
        }
        .fsummary-title {
            font-size: 15px;
            font-weight: 650;
            letter-spacing: -.01em;
            margin: 0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .fsummary-badge {
            font-size: 11px;
            color: var(--muted);
            background: var(--raise);
            border: 1px solid var(--border-soft);
            padding: 3px 8px;
            border-radius: 6px;
            font-family: var(--font-mono);
            white-space: nowrap;
        }
        .expand-icon {
            font-size: 11px;
            color: var(--faint);
            transition: transform 0.2s ease;
            font-family: var(--font-mono);
        }
        .finding[open] .expand-icon {
            transform: rotate(180deg);
        }
        .fdetails-body {
            padding: 0 1.1rem 1.1rem 1.1rem;
            border-top: 1px solid var(--border-soft);
        }

        /* report table styling */
        .report-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            color: var(--text);
            text-align: left;
            margin-top: 0.5rem;
        }
        .report-table th {
            background: var(--surface);
            border-bottom: 2px solid var(--border);
            padding: 10px 14px;
            font-weight: 700;
            color: var(--muted);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: .08em;
        }
        .report-table td {
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-soft);
        }
        .report-table tr:hover {
            background: color-mix(in srgb, var(--raise) 40%, transparent);
        }
        .report-table tr:last-child td {
            border-bottom: none;
        }
        .fhead { display: flex; align-items: center; justify-content: space-between; gap: .7rem; flex-wrap: wrap; margin-bottom: .9rem; }
        .fhead-l { display: flex; align-items: center; gap: .65rem; min-width: 0; }
        .sev-chip { font-size: 10.5px; font-weight: 800; letter-spacing: .06em; padding: 3px 8px; border-radius: 5px; text-transform: uppercase; white-space: nowrap; }
        .sev-chip.critical { color: var(--crit); background: color-mix(in srgb, var(--crit) 15%, transparent); }
        .sev-chip.high { color: var(--high); background: color-mix(in srgb, var(--high) 15%, transparent); }
        .sev-chip.medium { color: var(--med); background: color-mix(in srgb, var(--med) 15%, transparent); }
        .sev-chip.low { color: var(--low); background: color-mix(in srgb, var(--low) 15%, transparent); }
        .sev-chip.informational { color: var(--info); background: color-mix(in srgb, var(--info) 15%, transparent); }
        .fhead h3 { font-size: 15px; font-weight: 650; letter-spacing: -.01em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .verdict { display: inline-flex; align-items: center; gap: .4rem; font-size: 11.5px; font-weight: 700; padding: 4px 11px; border-radius: 100px; white-space: nowrap; }
        .verdict .vm { font-family: var(--font-mono); }
        .verdict.tp { color: var(--tp); background: var(--tp-soft); border: 1px solid color-mix(in srgb, var(--tp) 34%, transparent); }
        .verdict.fp { color: var(--fp); background: var(--fp-soft); border: 1px solid color-mix(in srgb, var(--fp) 34%, transparent); }
        .verdict.none { color: var(--faint); background: color-mix(in srgb, var(--info) 12%, transparent); border: 1px solid var(--border); }
        .verdict.pending { color: var(--ai); background: var(--ai-soft); border: 1px solid var(--ai-line); }

        .fgrid { display: grid; grid-template-columns: 1fr 1fr; gap: .9rem; }
        @media (max-width: 720px) { .fgrid { grid-template-columns: 1fr; } }
        .pane { border-radius: var(--r-sm); padding: .8rem .9rem; min-width: 0; }
        .pane.scanner { background: var(--surface-2); border: 1px solid var(--border-soft); }
        .pane.ai { background: var(--ai-soft); border: 1px solid var(--ai-line); }
        .pane.ai.muted-pane { background: var(--surface-2); border: 1px dashed var(--border); }
        .prov { font-size: 10.5px; font-weight: 800; letter-spacing: .11em; text-transform: uppercase; display: flex; align-items: center; gap: .45rem; margin-bottom: .7rem; }
        .prov.scan { color: var(--faint); } .prov.ai { color: var(--ai); } .prov.muted-prov { color: var(--faint); }

        dl.kv { display: grid; gap: .5rem; }
        dl.kv > div { display: grid; grid-template-columns: 88px 1fr; gap: .6rem; align-items: start; }
        dl.kv dt { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
        dl.kv dd { font-size: 12.5px; min-width: 0; word-break: break-word; }
        dl.kv dd.mono { font-family: var(--font-mono); font-size: 11.5px; }
        .ev { font-family: var(--font-mono); font-size: 11px; background: color-mix(in srgb, var(--crit) 9%, var(--bg)); border: 1px solid var(--border-soft); border-radius: 6px; padding: 5px 7px; color: var(--text); white-space: pre-wrap; word-break: break-word; display: block; }
        .tags { display: flex; flex-wrap: wrap; gap: .35rem; }
        .tag { font-family: var(--font-mono); font-size: 10.5px; color: var(--muted); background: var(--raise); border: 1px solid var(--border-soft); border-radius: 5px; padding: 2px 6px; }
        .url-list { margin: 0; padding-left: 1.1rem; }
        .url-list li { margin-bottom: .15rem; }

        .conf { margin: 0 0 .7rem; }
        .conf-top { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: .35rem; }
        .conf-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
        .conf-num { font-size: 14px; font-weight: 800; font-variant-numeric: tabular-nums; }
        .conf.tp .conf-num { color: var(--tp); } .conf.fp .conf-num { color: var(--fp); }
        .conf-track { height: 6px; border-radius: 100px; background: color-mix(in srgb, var(--info) 22%, transparent); overflow: hidden; }
        .conf-fill { height: 100%; border-radius: 100px; transition: width .6s ease; }
        .conf.tp .conf-fill { background: var(--tp); } .conf.fp .conf-fill { background: var(--fp); }
        .ai-reason { font-size: 12.5px; line-height: 1.5; }
        .ai-reason .lead { font-weight: 700; }
        .ai-reason.tp .lead { color: var(--tp); } .ai-reason.fp .lead { color: var(--fp); }
        .muted-pane .ai-reason { color: var(--muted); }
        .ai-cta { margin-top: .5rem; font-size: 11.5px; color: var(--ai); }

        details.http { margin-top: .8rem; border-top: 1px solid var(--border-soft); padding-top: .7rem; }
        details.http summary { cursor: pointer; font-size: 12px; color: var(--muted); font-weight: 600; list-style: none; display: flex; align-items: center; gap: .45rem; }
        details.http summary::-webkit-details-marker { display: none; }
        details.http summary::before { content: "▸"; color: var(--faint); transition: transform .15s; }
        details.http[open] summary::before { transform: rotate(90deg); }
        details.http .payload { margin-top: .6rem; }
        details.http pre { font-family: var(--font-mono); font-size: 11px; color: var(--muted); background: #05070c; border: 1px solid var(--border-soft); border-radius: 7px; padding: .7rem; margin-top: .4rem; overflow-x: auto; line-height: 1.5; white-space: pre-wrap; word-break: break-word; }

        .spinner { width: 1.1rem; height: 1.1rem; border: 2px solid rgba(255,255,255,.3); border-top-color: #fff; border-radius: 50%; animation: spin .8s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <div class="mark">🛡️</div>
            <div>
                <h1>AI DAST SECURITY SCANNER</h1>
                <p>OWASP ZAP · AI-validated findings</p>
            </div>
        </div>
        <div class="status-tag">Orchestrator: <b id="server-status">ACTIVE</b></div>
    </header>

    <main>
        <!-- SIDEBAR -->
        <div class="sidebar">
            <div class="card">
                <div class="card-label">Configure scan</div>
                <div class="form-group">
                    <label class="form-label" for="target-url">Target URL</label>
                    <input class="form-input" type="url" id="target-url" placeholder="https://example.com" value="https://example.com">
                </div>
                <div class="form-group">
                    <label class="form-label" for="api-key">Gemini API key <span style="color:var(--faint)">(optional)</span></label>
                    <input class="form-input" type="password" id="api-key" placeholder="Enables AI validation">
                    <p class="hint">Without a key, findings are reported directly from ZAP (no AI verdicts). Over MCP, validation runs on your linked model instead.</p>
                </div>
                <div class="form-group">
                    <label class="toggle-row" for="active-scan">
                        <input type="checkbox" id="active-scan" checked>
                        <span>Active scan <span style="color:var(--high);font-weight:600;">(intrusive)</span></span>
                    </label>
                    <p class="hint">Sends real attack payloads (SQLi, XSS…). Only scan targets you are authorized to test. Uncheck for a safe passive-only scan.</p>
                </div>
                <button class="btn" id="scan-btn" onclick="startScan()"><span>Start 1-Click Scan</span></button>
                <div class="progress-wrapper" id="progress-wrapper">
                    <div class="progress-meta"><span id="progress-status-text">Starting…</span><span id="progress-pct">0%</span></div>
                    <div class="progress-bg"><div class="progress-fill" id="progress-fill"></div></div>
                </div>
            </div>

            <div class="card">
                <div class="terminal-head">
                    <div class="dots"><div class="dot dot-r"></div><div class="dot dot-y"></div><div class="dot dot-g"></div></div>
                    <div style="font-size:.72rem;color:var(--muted);font-family:var(--font-mono);">Orchestrator logs</div>
                </div>
                <div class="terminal" id="log-terminal">
                    <div class="terminal-line">[00:00:00] Ready. Enter a target URL and start the pipeline.</div>
                </div>
            </div>
        </div>

        <!-- CONTENT -->
        <div class="content">
            <div class="card" id="empty-dashboard">
                <div class="empty-state">
                    <div class="empty-icon">🔍</div>
                    <h3>No scan active</h3>
                    <p>Enter a target URL and click “Start 1-Click Scan” to launch the multi-agent pipeline.</p>
                </div>
            </div>

            <div id="results-dashboard" style="display:none; flex-direction:column; gap:1.5rem;">
                <div class="card" style="padding-bottom:0;">
                    <div class="maintabs">
                        <button class="maintab active" id="maintab-recon" onclick="switchMainTab('recon')">🔎 Recon</button>
                        <button class="maintab" id="maintab-scan" onclick="switchMainTab('scan')">🛡️ Scan (Findings)</button>
                        <button class="maintab" id="maintab-exec-report" onclick="switchMainTab('exec-report')">📊 Executive Report</button>
                        <button class="maintab" id="maintab-va-report" onclick="switchMainTab('va-report')">💻 Technical VA Report</button>
                    </div>
                </div>

                <!-- RECON PANEL -->
                <div id="recon-panel" style="display:flex; flex-direction:column; gap:1.5rem;">
                    <div class="card">
                        <div class="card-label">Reconnaissance summary</div>
                        <div class="recon-grid">
                            <div class="recon-tile"><div class="n" id="recon-pages">0</div><div class="l">Pages crawled</div></div>
                            <div class="recon-tile"><div class="n" id="recon-forms">0</div><div class="l">Forms found</div></div>
                            <div class="recon-tile"><div class="n" id="recon-tech">0</div><div class="l">Technologies</div></div>
                        </div>
                        <div class="drow"><div class="dlabel">Target</div><div class="dval mono" id="recon-target">-</div></div>
                        <div class="drow"><div class="dlabel">Scan profile</div><div class="dval" id="recon-profile">-</div></div>
                        <div class="drow"><div class="dlabel">Scan mode</div><div class="dval" id="recon-scanmode">-</div></div>
                        <div class="drow"><div class="dlabel">Detected technology stack</div><div class="fw-wrap" id="recon-frameworks"></div></div>
                        <div class="drow"><div class="dlabel">Crawled endpoints</div><div class="code-box" id="recon-endpoints">-</div></div>
                    </div>
                </div>

                <!-- SCAN PANEL -->
                <div id="scan-panel" style="display:none; flex-direction:column; gap:1.5rem;">
                    <!-- overview -->
                    <div class="overview">
                        <div class="card risk-card">
                            <div class="card-label">Risk score</div>
                            <div class="dial">
                                <svg width="160" height="160" viewBox="0 0 160 160">
                                    <circle class="track" cx="80" cy="80" r="68"></circle>
                                    <circle class="val" id="dial-val" cx="80" cy="80" r="68" stroke-dasharray="427" stroke-dashoffset="427"></circle>
                                </svg>
                                <div class="center"><span class="num" id="risk-score-num">0</span><span class="den">/ 100</span></div>
                            </div>
                            <span class="risk-band" id="risk-band">—</span>
                            <p class="risk-note" id="risk-note"></p>
                        </div>
                        <div class="ov-right">
                            <div class="card ai-summary">
                                <div class="card-label">✦ AI validation summary</div>
                                <div id="ai-summary-body"></div>
                            </div>
                            <div class="card">
                                <div class="card-label">Severity distribution</div>
                                <div class="dist" id="severity-dist"></div>
                            </div>
                        </div>
                    </div>

                    <!-- owasp + coverage -->
                    <div class="strip">
                        <div class="card">
                            <div class="card-label">OWASP Top 10 (2021) breakdown</div>
                            <div id="owasp-breakdown"></div>
                        </div>
                        <div class="card">
                            <div class="card-label">Scan coverage</div>
                            <div class="coverage" id="coverage-tiles"></div>
                        </div>
                    </div>

                    <!-- reports -->
                    <div class="card" id="reports-section" style="display:none;">
                        <div class="card-label">Download PDF reports</div>
                        <div class="reports-grid">
                            <div class="report-card">
                                <div class="t">📊 Executive report</div>
                                <div class="d">High-level risk profile, business impact, and strategic recommendations for stakeholders.</div>
                                <a href="/download/executive" class="btn dl-btn">Download Executive PDF</a>
                            </div>
                            <div class="report-card">
                                <div class="t">💻 Technical report</div>
                                <div class="d">Full per-finding evidence, CWE/OWASP mapping, HTTP transactions, and AI validation analysis.</div>
                                <a href="/download/technical" class="btn dl-btn">Download Technical PDF</a>
                            </div>
                        </div>
                    </div>

                    <!-- findings -->
                    <div class="card">
                        <div class="legend">
                            <span class="item"><span class="glyph scan">◇</span> Scanner evidence — raw ZAP output</span>
                            <span class="item"><span class="glyph ai">✦</span> AI assessment — model-reviewed judgment</span>
                            <span class="item"><span class="verdict tp" style="padding:2px 9px"><span class="vm">✓</span> True positive</span></span>
                            <span class="item"><span class="verdict fp" style="padding:2px 9px"><span class="vm">≈</span> False positive</span></span>
                        </div>
                        <div class="ftabs">
                            <button class="ftab active" id="tab-validated" onclick="switchTab('validated')">High &amp; Critical</button>
                            <button class="ftab" id="tab-all" onclick="switchTab('all')">All findings</button>
                        </div>
                        <div class="findings" id="findings-container"></div>
                    </div>
                </div>

                <!-- EXECUTIVE REPORT PANEL -->
                <div id="exec-report-panel" style="display:none; flex-direction:column; gap:1.5rem;">
                    <div class="overview">
                        <div class="card risk-card">
                            <div class="card-label">Executive Risk Profile</div>
                            <div class="dial">
                                <svg width="160" height="160" viewBox="0 0 160 160">
                                    <circle class="track" cx="80" cy="80" r="68"></circle>
                                    <circle class="val" id="exec-dial-val" cx="80" cy="80" r="68" stroke-dasharray="427" stroke-dashoffset="427"></circle>
                                </svg>
                                <div class="center"><span class="num" id="exec-risk-score-num">0</span><span class="den">/ 100</span></div>
                            </div>
                            <span class="risk-band" id="exec-risk-band">—</span>
                            <div class="drow" style="margin-top: 1rem; width: 100%;">
                                <div class="dlabel">Target Scope</div>
                                <div class="dval mono" id="exec-target-url" style="font-size: 12px; word-break: break-all;">-</div>
                            </div>
                            <div class="drow" style="margin-top: 0.5rem; width: 100%;">
                                <div class="dlabel">Scan Date</div>
                                <div class="dval" id="exec-scan-date" style="font-size: 12px;">-</div>
                            </div>
                        </div>
                        <div class="ov-right">
                            <div class="card ai-summary" style="height: 100%; border-color: var(--accent); background: linear-gradient(180deg, color-mix(in srgb, var(--accent) 9%, var(--surface)), var(--surface-2));">
                                <div class="card-label" style="color: var(--accent)">📊 Executive Summary</div>
                                <p id="exec-summary-text" style="font-size: 13.5px; line-height: 1.6; color: var(--text);"></p>
                            </div>
                        </div>
                    </div>

                    <div class="grid-2col" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
                        <div class="card" style="border-color: var(--crit);">
                            <div class="card-label" style="color: var(--crit);">⚠️ Business &amp; Operational Impact</div>
                            <p id="exec-impact-text" style="font-size: 13.5px; line-height: 1.6; color: var(--text);"></p>
                        </div>
                        <div class="card" style="border-color: var(--ok);">
                            <div class="card-label" style="color: var(--ok);">🛡️ Strategic Recommendations</div>
                            <ul id="exec-recs-list" style="padding-left: 1.2rem; font-size: 13px; line-height: 1.6; display: flex; flex-direction: column; gap: 0.5rem;">
                            </ul>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-label">High &amp; Critical Findings Summary</div>
                        <div id="exec-findings-summary-table"></div>
                    </div>

                    <div class="card">
                        <div class="card-label">Export PDF Reports</div>
                        <div class="reports-grid">
                            <div class="report-card">
                                <div class="t">📊 Download Executive PDF</div>
                                <div class="d">High-level risk profile, business impact, and strategic recommendations for stakeholders.</div>
                                <a href="/download/executive" class="btn dl-btn">Download Executive PDF</a>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- VA REPORT PANEL -->
                <div id="va-report-panel" style="display:none; flex-direction:column; gap:1.5rem;">
                    <div class="card">
                        <div class="card-label">Technical Scan Coverage &amp; Tech Stack</div>
                        <div class="recon-grid" style="grid-template-columns: repeat(4, 1fr);">
                            <div class="recon-tile"><div class="n" id="va-pages-crawled">0</div><div class="l">Pages Crawled</div></div>
                            <div class="recon-tile"><div class="n" id="va-forms-found">0</div><div class="l">Forms Found</div></div>
                            <div class="recon-tile"><div class="n" id="va-total-alerts">0</div><div class="l">Total Alerts</div></div>
                            <div class="recon-tile"><div class="n" id="va-active-findings">0</div><div class="l">Active Findings</div></div>
                        </div>
                        <div class="drow"><div class="dlabel">Detected Technologies</div><div class="fw-wrap" id="va-tech-stack"></div></div>
                    </div>

                    <div class="strip">
                        <div class="card">
                            <div class="card-label">OWASP Top 10 Breakdown</div>
                            <div id="va-owasp-breakdown"></div>
                        </div>
                        <div class="card">
                            <div class="card-label">Security Findings Severity Breakdown</div>
                            <div class="dist" id="va-severity-dist"></div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-label">Detailed Vulnerability Matrix &amp; Remediation Plan</div>
                        <div id="va-remediation-table-container"></div>
                    </div>

                    <div class="card">
                        <div class="card-label">Export PDF Reports</div>
                        <div class="reports-grid">
                            <div class="report-card">
                                <div class="t">💻 Download Technical VA Report</div>
                                <div class="d">Full per-finding evidence, CWE/OWASP mapping, HTTP transactions, and AI validation analysis.</div>
                                <a href="/download/technical" class="btn dl-btn">Download Technical PDF</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        let currentTab = 'validated';
        let scanResultsData = null;
        let pollInterval = null;

        function escapeHtml(s) {
            if (s === null || s === undefined) return '';
            return String(s)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        function startScan() {
            const url = document.getElementById('target-url').value;
            const apiKey = document.getElementById('api-key').value;
            const activeScan = document.getElementById('active-scan').checked;
            if (!url) { alert("Please enter a valid target URL"); return; }

            document.getElementById('scan-btn').disabled = true;
            document.getElementById('scan-btn').innerHTML = '<div class="spinner"></div> Running…';
            document.getElementById('progress-wrapper').style.display = 'block';
            document.getElementById('log-terminal').innerHTML = '';
            document.getElementById('empty-dashboard').style.display = 'none';
            document.getElementById('results-dashboard').style.display = 'flex';
            document.getElementById('reports-section').style.display = 'none';
            switchMainTab('recon');

            fetch('/scan', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url, api_key: apiKey, active_scan: activeScan })
            })
            .then(res => res.json())
            .then(() => { if (pollInterval) clearInterval(pollInterval); pollInterval = setInterval(pollScanStatus, 1000); })
            .catch(err => { console.error("Scan launch failed:", err); resetScanButton(); });
        }

        function pollScanStatus() {
            fetch('/status').then(res => res.json()).then(state => {
                const terminal = document.getElementById('log-terminal');
                const atBottom = terminal.scrollHeight - terminal.clientHeight <= terminal.scrollTop + 10;
                terminal.innerHTML = state.logs.map(log => `<div class="terminal-line">${escapeHtml(log)}</div>`).join('');
                if (atBottom) terminal.scrollTop = terminal.scrollHeight;

                document.getElementById('progress-pct').innerText = state.progress + "%";
                document.getElementById('progress-fill').style.width = state.progress + "%";
                let step = "Running…";
                if (state.progress < 20) step = "Recon Agent analyzing…";
                else if (state.progress < 50) step = "Scan Agent running ZAP…";
                else if (state.progress < 75) step = "Validation Agent verifying…";
                else if (state.progress < 90) step = "Report Agent computing risk…";
                else if (state.progress < 100) step = "PDF Generator building…";
                else step = "Completed.";
                document.getElementById('progress-status-text').innerText = step;

                if (state.status === 'completed') {
                    clearInterval(pollInterval);
                    scanResultsData = state.results;
                    renderScanResults();
                    resetScanButton();
                    document.getElementById('reports-section').style.display = 'block';
                    switchMainTab('scan');
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

        function switchMainTab(name) {
            document.getElementById('maintab-recon').className = name === 'recon' ? 'maintab active' : 'maintab';
            document.getElementById('maintab-scan').className = name === 'scan' ? 'maintab active' : 'maintab';
            document.getElementById('maintab-exec-report').className = name === 'exec-report' ? 'maintab active' : 'maintab';
            document.getElementById('maintab-va-report').className = name === 'va-report' ? 'maintab active' : 'maintab';
            document.getElementById('recon-panel').style.display = name === 'recon' ? 'flex' : 'none';
            document.getElementById('scan-panel').style.display = name === 'scan' ? 'flex' : 'none';
            document.getElementById('exec-report-panel').style.display = name === 'exec-report' ? 'flex' : 'none';
            document.getElementById('va-report-panel').style.display = name === 'va-report' ? 'flex' : 'none';
        }

        function switchTab(name) {
            document.getElementById('tab-validated').className = name === 'validated' ? 'ftab active' : 'ftab';
            document.getElementById('tab-all').className = name === 'all' ? 'ftab active' : 'ftab';
            currentTab = name;
            renderFindingsList();
        }

        function fmtDuration(s) {
            s = parseInt(s || 0, 10);
            if (!s) return '—';
            const m = Math.floor(s / 60), sec = s % 60;
            return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
        }

        function renderScanResults() {
            if (!scanResultsData) return;
            const d = scanResultsData;
            const stats = d.stats || {};
            const aiUsed = d.ai_used;

            // risk dial
            const score = d.risk_score || 0;
            document.getElementById('risk-score-num').innerText = score;
            const dial = document.getElementById('dial-val');
            dial.style.strokeDashoffset = 427 - (score / 100) * 427;
            let col = 'var(--low)', band = 'low';
            if (score >= 80) { col = 'var(--crit)'; band = 'crit'; }
            else if (score >= 55) { col = 'var(--high)'; band = 'high'; }
            else if (score >= 30) { col = 'var(--med)'; band = 'med'; }
            dial.style.stroke = col;
            const bandEl = document.getElementById('risk-band');
            bandEl.innerText = d.risk_desc || '';
            bandEl.style.color = col;
            bandEl.style.background = `color-mix(in srgb, ${col} 14%, transparent)`;
            bandEl.style.border = `1px solid color-mix(in srgb, ${col} 34%, transparent)`;
            document.getElementById('risk-note').innerText = d.executive_summary || '';

            // AI summary
            const nondup = (d.findings || []).filter(f => !f.is_duplicate);
            const hc = nondup.filter(f => ['high', 'critical'].includes((f.risk || '').toLowerCase()));
            const aiBody = document.getElementById('ai-summary-body');
            if (aiUsed) {
                const reviewed = hc.filter(f => 'ai_confidence' in f).length;
                const tp = hc.filter(f => ('ai_confidence' in f) && !f.is_false_positive).length;
                const fp = hc.filter(f => ('ai_confidence' in f) && f.is_false_positive).length;
                const direct = nondup.length - hc.length;
                aiBody.innerHTML = `
                    <div class="ai-stats">
                        <div class="ai-stat reviewed"><div class="n">${reviewed}</div><div class="l">Reviewed by AI</div></div>
                        <div class="ai-stat tp"><div class="n">${tp}</div><div class="l">Verified true positives</div></div>
                        <div class="ai-stat fp"><div class="n">${fp}</div><div class="l">Flagged false positives</div></div>
                        <div class="ai-stat"><div class="n">${direct}</div><div class="l">Reported directly</div></div>
                    </div>`;
            } else {
                aiBody.innerHTML = `<p class="ai-none"><b>AI validation did not run.</b> ${hc.length} High/Critical finding(s) are reported straight from ZAP without a true/false-positive verdict. Add a Gemini API key, or link this server to an MCP client (e.g. Claude), to get AI verdicts and reasoning.</p>`;
            }

            // severity distribution
            const sev = [
                ['Critical', stats.critical || 0, 'crit'],
                ['High', stats.high || 0, 'high'],
                ['Medium', stats.medium || 0, 'med'],
                ['Low', stats.low || 0, 'low'],
                ['Info', stats.informational || 0, 'info'],
            ];
            const maxv = Math.max(1, ...sev.map(s => s[1]));
            document.getElementById('severity-dist').innerHTML = sev.map(([name, n, c]) => `
                <div class="dist-row">
                    <span class="dist-name c-${c}">${name}</span>
                    <div class="dist-track"><div class="dist-fill sev-${c}" style="width:${(n / maxv) * 100}%"></div></div>
                    <span class="dist-n c-${c}">${n}</span>
                </div>`).join('');

            // OWASP breakdown
            const owaspMap = {};
            nondup.forEach(f => {
                const cat = f.owasp_full || 'Uncategorized';
                if (!owaspMap[cat]) owaspMap[cat] = { total: 0, hc: 0 };
                owaspMap[cat].total++;
                if (['high', 'critical'].includes((f.risk || '').toLowerCase())) owaspMap[cat].hc++;
            });
            const owaspRows = Object.entries(owaspMap).sort((a, b) => b[1].total - a[1].total);
            const owaspEl = document.getElementById('owasp-breakdown');
            if (owaspRows.length) {
                owaspEl.innerHTML = owaspRows.map(([cat, v]) => {
                    const m = cat.match(/^(A\d{2}:\d{4})[-\s]*(.*)$/);
                    const code = m ? m[1] : '';
                    const label = m ? m[2] : cat;
                    return `<div class="owasp-row">
                        <span class="owasp-cat"><span class="code">${escapeHtml(code)}</span>${escapeHtml(label)}</span>
                        <span class="owasp-count">${v.total} finding${v.total !== 1 ? 's' : ''}${v.hc ? ' · ' + v.hc + ' High+' : ''}</span>
                    </div>`;
                }).join('');
            } else {
                owaspEl.innerHTML = `<p class="ai-none">No findings to categorize.</p>`;
            }

            // coverage
            const activeOn = d.active_scan !== false;
            document.getElementById('coverage-tiles').innerHTML = `
                <div class="cov-tile"><div class="n">${d.pages_crawled_count || 0}</div><div class="l">Pages crawled</div></div>
                <div class="cov-tile"><div class="n">${d.forms_found_count || 0}</div><div class="l">Forms found</div></div>
                <div class="cov-tile"><div class="n">${escapeHtml(d.scan_profile || 'Standard')}</div><div class="l">Scan profile</div></div>
                <div class="cov-tile"><div class="n">${fmtDuration(d.scan_duration_seconds)}</div><div class="l">Duration</div></div>
                <div class="cov-tile cov-mode">
                    <span class="pill ${activeOn ? 'pill-active' : 'pill-passive'}">${activeOn ? 'ACTIVE + PASSIVE' : 'PASSIVE ONLY'}</span>
                    <span>${activeOn ? 'Intrusive payloads sent' : 'Spider + response analysis'}</span>
                </div>`;

            renderReconResults();
            renderFindingsList();
            renderExecutiveReport();
            renderVAReport();
        }

        function renderReconResults() {
            if (!scanResultsData) return;
            const d = scanResultsData;
            document.getElementById('recon-target').innerText = d.target_url || '-';
            document.getElementById('recon-profile').innerText = d.scan_profile || 'Standard Profile';
            document.getElementById('recon-scanmode').innerHTML = (d.active_scan === false)
                ? 'Passive only <span style="color:var(--muted);">(spider + response analysis, no attack payloads)</span>'
                : 'Active + Passive <span style="color:var(--high);">(intrusive attack payloads)</span>';
            document.getElementById('recon-pages').innerText = d.pages_crawled_count || 0;
            document.getElementById('recon-forms').innerText = d.forms_found_count || 0;
            const fws = d.frameworks || [];
            document.getElementById('recon-tech').innerText = fws.length;
            document.getElementById('recon-frameworks').innerHTML = fws.length
                ? fws.map(fw => `<span class="fw-badge">${escapeHtml(fw)}</span>`).join('')
                : '<span style="color:var(--muted);">None detected</span>';
            const pages = d.pages_crawled || [];
            document.getElementById('recon-endpoints').innerText = pages.length ? pages.join('\n') : 'No endpoints recorded.';
        }

        function classificationTags(f) {
            const tags = [];
            const cwe = f.cwe_full ? f.cwe_full.split(' ')[0] : (f.cweid ? 'CWE-' + f.cweid : '');
            if (cwe) tags.push(cwe);
            if (f.owasp_full) tags.push(f.owasp_full);
            if (f.cve_full && f.cve_full !== 'N/A') tags.push(f.cve_full);
            if (f.wascid) tags.push('WASC-' + f.wascid);
            return tags.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('');
        }

        function scannerPane(f) {
            const urls = f.affected_urls || [];
            const endpoint = (urls.length > 1)
                ? `<ul class="url-list">${urls.slice(0, 8).map(u => `<li class="mono">${escapeHtml(u)}</li>`).join('')}${urls.length > 8 ? `<li style="color:var(--muted)">+ ${urls.length - 8} more</li>` : ''}</ul>`
                : `<span class="mono">${escapeHtml(f.url || 'N/A')}</span>`;
            return `
                <section class="pane scanner">
                    <div class="prov scan"><span class="glyph scan">◇</span> Scanner evidence</div>
                    <dl class="kv">
                        <div><dt>Endpoint</dt><dd>${endpoint}</dd></div>
                        ${f.parameter ? `<div><dt>Parameter</dt><dd class="mono">${escapeHtml(f.parameter)}</dd></div>` : ''}
                        ${f.evidence ? `<div><dt>Evidence</dt><dd><code class="ev">${escapeHtml(f.evidence)}</code></dd></div>` : ''}
                        <div><dt>Description</dt><dd>${escapeHtml(f.description || '')}</dd></div>
                        <div><dt>Remediation</dt><dd>${escapeHtml(f.solution || '')}</dd></div>
                        <div><dt>Classification</dt><dd><div class="tags">${classificationTags(f)}</div></dd></div>
                    </dl>
                </section>`;
        }

        function aiPane(f) {
            const aiUsed = scanResultsData.ai_used;
            const isHC = ['high', 'critical'].includes((f.risk || '').toLowerCase());
            const reviewed = aiUsed && ('ai_confidence' in f);

            if (reviewed) {
                const fp = f.is_false_positive;
                const conf = Math.round((f.ai_confidence || 0) * 100);
                const kind = fp ? 'fp' : 'tp';
                const lead = fp ? 'Likely false positive.' : 'Real &amp; exploitable.';
                return `
                    <section class="pane ai">
                        <div class="prov ai"><span class="glyph ai">✦</span> AI assessment</div>
                        <div class="conf ${kind}">
                            <div class="conf-top"><span class="conf-label">${fp ? 'Confidence real' : 'Confidence'}</span><span class="conf-num">${conf}%</span></div>
                            <div class="conf-track"><div class="conf-fill" style="width:${conf}%"></div></div>
                        </div>
                        <p class="ai-reason ${kind}"><span class="lead">${lead}</span> ${escapeHtml(f.ai_reasoning || 'No reasoning returned.')}</p>
                    </section>`;
            }
            if (isHC) {
                // High/Critical but no AI ran — explicit "AI not run" state.
                return `
                    <section class="pane ai muted-pane">
                        <div class="prov muted-prov">✦ AI assessment</div>
                        <p class="ai-reason"><b style="color:var(--ai)">AI validation not run.</b> This High/Critical finding has no true/false-positive verdict yet.</p>
                        <p class="ai-cta">Add a Gemini API key, or link over MCP, to get a verdict and reasoning.</p>
                    </section>`;
            }
            // Medium/Low/Info — not AI-reviewed by design.
            return `
                <section class="pane ai muted-pane">
                    <div class="prov muted-prov">Provenance</div>
                    <p class="ai-reason">Reported directly from OWASP ZAP. AI validation runs on <b>High &amp; Critical</b> findings only (to conserve tokens); ${escapeHtml(f.risk || 'this')} findings pass through unchanged — no AI verdict is claimed.</p>
                </section>`;
        }

        function httpDetails(f) {
            if (!f.request_header && !f.response_header) return '';
            let inner = '';
            if (f.request_header) inner += `<div class="payload"><div style="font-size:11px;color:var(--muted);font-weight:600;">🌐 Request</div><pre>${escapeHtml(f.request_header)}\n\n${escapeHtml(f.request_body || '')}</pre></div>`;
            if (f.response_header) inner += `<div class="payload"><div style="font-size:11px;color:var(--muted);font-weight:600;">📥 Response</div><pre>${escapeHtml(f.response_header)}\n\n${escapeHtml(f.response_body || '')}</pre></div>`;
            return `<details class="http"><summary>HTTP transaction</summary>${inner}</details>`;
        }

        function renderFindingsList() {
            if (!scanResultsData) return;
            const container = document.getElementById('findings-container');
            let list = (scanResultsData.findings || []).filter(f => !f.is_duplicate);
            if (currentTab === 'validated') {
                list = list.filter(f => ['critical', 'high'].includes((f.risk || '').toLowerCase()));
            }
            if (list.length === 0) {
                container.innerHTML = `<div class="empty-state" style="padding:2rem;"><p>No findings match this tab.</p></div>`;
                return;
            }

            container.innerHTML = list.map(f => {
                const sev = (f.risk || 'low').toLowerCase();
                const reviewed = scanResultsData.ai_used && ('ai_confidence' in f);
                const isFp = reviewed && f.is_false_positive;
                const endpointCount = (f.affected_urls || []).length || 1;

                let verdict;
                if (reviewed && !isFp) verdict = `<span class="verdict tp"><span class="vm">✓</span> AI verified · True positive</span>`;
                else if (isFp) verdict = `<span class="verdict fp"><span class="vm">≈</span> AI flagged · Likely false positive</span>`;
                else if (['high', 'critical'].includes(sev)) verdict = `<span class="verdict pending">✦ AI not run</span>`;
                else verdict = `<span class="verdict none">Not AI-reviewed</span>`;

                return `
                    <details class="finding ${isFp ? 'is-fp' : ''}" data-sev="${sev}">
                        <div class="stripe"></div>
                        <summary class="fsummary">
                            <div class="fsummary-content">
                                <div class="fsummary-left">
                                    <span class="sev-chip ${sev}">${escapeHtml(f.risk || 'Low')}</span>
                                    <h3 class="fsummary-title">${escapeHtml(f.alert || 'Finding')}</h3>
                                </div>
                                <div class="fsummary-right">
                                    <span class="fsummary-badge">${endpointCount} endpoint${endpointCount > 1 ? 's' : ''}</span>
                                    ${verdict}
                                    <span class="expand-icon">▼</span>
                                </div>
                            </div>
                        </summary>
                        <div class="fdetails-body">
                            <div class="fgrid">
                                ${scannerPane(f)}
                                ${aiPane(f)}
                            </div>
                            ${httpDetails(f)}
                        </div>
                    </details>`;
            }).join('');
        }

        function renderExecutiveReport() {
            if (!scanResultsData) return;
            const d = scanResultsData;
            
            const score = d.risk_score || 0;
            document.getElementById('exec-risk-score-num').innerText = score;
            const dial = document.getElementById('exec-dial-val');
            dial.style.strokeDashoffset = 427 - (score / 100) * 427;
            let col = 'var(--low)';
            if (score >= 80) col = 'var(--crit)';
            else if (score >= 55) col = 'var(--high)';
            else if (score >= 30) col = 'var(--med)';
            dial.style.stroke = col;
            
            const bandEl = document.getElementById('exec-risk-band');
            bandEl.innerText = d.risk_desc || '';
            bandEl.style.color = col;
            bandEl.style.background = `color-mix(in srgb, ${col} 14%, transparent)`;
            bandEl.style.border = `1px solid color-mix(in srgb, ${col} 34%, transparent)`;

            document.getElementById('exec-target-url').innerText = d.target_url || '-';
            document.getElementById('exec-scan-date').innerText = d.scan_date || '-';
            
            document.getElementById('exec-summary-text').innerText = d.executive_summary || 'No executive summary generated.';
            document.getElementById('exec-impact-text').innerText = d.business_impact || 'No business impact description available.';
            
            const recsList = document.getElementById('exec-recs-list');
            recsList.innerHTML = (d.strategic_recommendations || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');
            
            const tableDiv = document.getElementById('exec-findings-summary-table');
            const nondup = (d.findings || []).filter(f => !f.is_duplicate);
            const hc = nondup.filter(f => ['high', 'critical'].includes((f.risk || '').toLowerCase()));
            
            if (hc.length === 0) {
                tableDiv.innerHTML = `<p class="ai-none">No High or Critical vulnerabilities were identified during this scan.</p>`;
            } else {
                tableDiv.innerHTML = `
                    <table class="report-table">
                        <thead>
                            <tr>
                                <th>Vulnerability</th>
                                <th>Severity</th>
                                <th>Affected Endpoints</th>
                                <th>AI Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${hc.map(f => {
                                const sev = (f.risk || 'low').toLowerCase();
                                const reviewed = d.ai_used && ('ai_confidence' in f);
                                const isFp = reviewed && f.is_false_positive;
                                const urlCount = (f.affected_urls || []).length || 1;
                                
                                let status;
                                if (reviewed && !isFp) status = `<span style="color:var(--tp); font-weight:600;">✓ Verified True Positive</span>`;
                                else if (isFp) status = `<span style="color:var(--fp); font-weight:600;">≈ Flagged False Positive</span>`;
                                else status = `<span style="color:var(--muted);">Reported directly</span>`;
                                
                                return `
                                    <tr>
                                        <td style="font-weight:600;">${escapeHtml(f.alert || 'Finding')}</td>
                                        <td><span class="sev-chip ${sev}">${escapeHtml(f.risk)}</span></td>
                                        <td class="mono">${urlCount} page${urlCount > 1 ? 's' : ''}</td>
                                        <td>${status}</td>
                                    </tr>`;
                            }).join('')}
                        </tbody>
                    </table>`;
            }
        }

        function renderVAReport() {
            if (!scanResultsData) return;
            const d = scanResultsData;
            
            document.getElementById('va-pages-crawled').innerText = d.pages_crawled_count || 0;
            document.getElementById('va-forms-found').innerText = d.forms_found_count || 0;
            
            const rawFindings = d.findings || [];
            const nondup = rawFindings.filter(f => !f.is_duplicate);
            const activeFindings = nondup.filter(f => !f.is_false_positive);
            
            document.getElementById('va-total-alerts').innerText = rawFindings.length;
            document.getElementById('va-active-findings').innerText = activeFindings.length;
            
            const fws = d.frameworks || [];
            document.getElementById('va-tech-stack').innerHTML = fws.length
                ? fws.map(fw => `<span class="fw-badge">${escapeHtml(fw)}</span>`).join('')
                : '<span style="color:var(--muted);">Generic Web Application</span>';
                
            const owaspMap = {};
            nondup.forEach(f => {
                const cat = f.owasp_full || 'Uncategorized';
                if (!owaspMap[cat]) owaspMap[cat] = { total: 0, hc: 0 };
                owaspMap[cat].total++;
                if (['high', 'critical'].includes((f.risk || '').toLowerCase())) owaspMap[cat].hc++;
            });
            const owaspRows = Object.entries(owaspMap).sort((a, b) => b[1].total - a[1].total);
            const owaspEl = document.getElementById('va-owasp-breakdown');
            if (owaspRows.length) {
                owaspEl.innerHTML = owaspRows.map(([cat, v]) => {
                    const m = cat.match(/^(A\d{2}:\d{4})[-\s]*(.*)$/);
                    const code = m ? m[1] : '';
                    const label = m ? m[2] : cat;
                    return `<div class="owasp-row">
                        <span class="owasp-cat"><span class="code">${escapeHtml(code)}</span>${escapeHtml(label)}</span>
                        <span class="owasp-count">${v.total} finding${v.total !== 1 ? 's' : ''}${v.hc ? ' · ' + v.hc + ' High+' : ''}</span>
                    </div>`;
                }).join('');
            } else {
                owaspEl.innerHTML = `<p class="ai-none">No findings to categorize.</p>`;
            }

            const stats = d.stats || {};
            const total = (stats.critical || 0) + (stats.high || 0) + (stats.medium || 0) + (stats.low || 0) + (stats.informational || 0) || 1;
            const pct = n => Math.round(((n || 0) / total) * 100);
            
            document.getElementById('va-severity-dist').innerHTML = `
                <div class="dist-row">
                    <span class="dist-name c-crit">Critical</span>
                    <div class="dist-track"><div class="dist-fill sev-crit" style="width:${pct(stats.critical)}%"></div></div>
                    <span class="dist-n">${stats.critical || 0}</span>
                </div>
                <div class="dist-row">
                    <span class="dist-name c-high">High</span>
                    <div class="dist-track"><div class="dist-fill sev-high" style="width:${pct(stats.high)}%"></div></div>
                    <span class="dist-n">${stats.high || 0}</span>
                </div>
                <div class="dist-row">
                    <span class="dist-name c-med">Medium</span>
                    <div class="dist-track"><div class="dist-fill sev-med" style="width:${pct(stats.medium)}%"></div></div>
                    <span class="dist-n">${stats.medium || 0}</span>
                </div>
                <div class="dist-row">
                    <span class="dist-name c-low">Low</span>
                    <div class="dist-track"><div class="dist-fill sev-low" style="width:${pct(stats.low)}%"></div></div>
                    <span class="dist-n">${stats.low || 0}</span>
                </div>
                <div class="dist-row">
                    <span class="dist-name c-info">Info</span>
                    <div class="dist-track"><div class="dist-fill sev-info" style="width:${pct(stats.informational)}%"></div></div>
                    <span class="dist-n">${stats.informational || 0}</span>
                </div>`;

            const vaTableDiv = document.getElementById('va-remediation-table-container');
            if (nondup.length === 0) {
                vaTableDiv.innerHTML = `<p class="ai-none">No findings detected.</p>`;
            } else {
                vaTableDiv.innerHTML = `
                    <table class="report-table">
                        <thead>
                            <tr>
                                <th>Vulnerability Alert</th>
                                <th>Severity</th>
                                <th>CWE Mapping</th>
                                <th>Remediation Solution</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${nondup.map(f => {
                                const sev = (f.risk || 'low').toLowerCase();
                                const cwe = f.cwe_full ? f.cwe_full : (f.cweid ? 'CWE-' + f.cweid : 'N/A');
                                
                                return `
                                    <tr>
                                        <td style="font-weight:600;">${escapeHtml(f.alert || 'Finding')}</td>
                                        <td><span class="sev-chip ${sev}">${escapeHtml(f.risk)}</span></td>
                                        <td class="mono" style="font-size:11px;">${escapeHtml(cwe)}</td>
                                        <td style="font-size:12px; color:var(--muted);">${escapeHtml(f.solution || 'No specific solution provided.')}</td>
                                    </tr>`;
                            }).join('')}
                        </tbody>
                    </table>`;
            }
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
