import os
import json
import logging
from fastmcp import FastMCP
from scan_engine import DASTScanEngine
from agents import ValidationAgent, ReportAgent, PDFReportGenerator

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DAST-MCP-Server")

# Initialize FastMCP Server
mcp = FastMCP(
    "DAST-Security-Testing-Server",
    dependencies=["requests", "reportlab", "beautifulsoup4", "matplotlib"]
)

# Active scan cache database
SCANS_DB = {}

@mcp.tool()
def fetch_homepage(url: str) -> str:
    """
    Fetches the HTML raw content and cookies from the target homepage URL.
    
    Args:
        url: The website URL.
    """
    import requests
    try:
        response = requests.get(url, timeout=10, headers={"User-Agent": "AI-DAST-Agent/1.0"})
        return json.dumps({
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "cookies": [{c.name: c.value} for c in response.cookies],
            "html_preview": response.text[:2000]
        }, indent=2)
    except Exception as e:
        return f"Error fetching homepage: {str(e)}"

@mcp.tool()
def crawl_site(url: str) -> str:
    """
    Performs a lightweight crawl of the target website to discover internal links and forms.
    
    Args:
        url: The website URL.
    """
    engine = DASTScanEngine(url)
    crawled_urls = engine.crawl_site(max_pages=15)
    return json.dumps({
        "target_url": url,
        "crawled_pages_count": len(crawled_urls),
        "pages": crawled_urls,
        "forms_found": len(engine.forms_found)
    }, indent=2)

@mcp.tool()
def detect_framework(url: str) -> str:
    """
    Analyzes response headers, source code patterns, and cookies to detect frameworks, CMSs, and tech stack details.
    
    Args:
        url: The website URL.
    """
    engine = DASTScanEngine(url)
    frameworks = engine.detect_framework()
    return json.dumps({
        "target_url": url,
        "detected_frameworks": frameworks
    }, indent=2)

@mcp.tool()
def run_zap_scan(url: str) -> str:
    """
    Triggers a full DAST scan simulation on the target URL (crawling, framework detection, and vulnerability testing).
    Saves the result to the scan database cache.
    
    Args:
        url: The target website URL.
    """
    logger.info(f"Triggering scan for target: {url}")
    engine = DASTScanEngine(url)
    scan_results = engine.run_dast_scan()
    scan_id = scan_results["scan_id"]
    SCANS_DB[scan_id] = scan_results
    return json.dumps({
        "message": "DAST scan completed successfully.",
        "scan_id": scan_id,
        "findings_count": len(scan_results["findings"])
    }, indent=2)

@mcp.tool()
def get_scan_results(scan_id: str) -> str:
    """
    Retrieves the raw JSON scan results from the database cache.
    
    Args:
        scan_id: The unique identifier of the completed scan.
    """
    if scan_id in SCANS_DB:
        return json.dumps(SCANS_DB[scan_id], indent=2)
    
    # Try reading from disk cache
    import glob
    matching_files = glob.glob(f"scan_results_{scan_id}.json")
    if matching_files:
        with open(matching_files[0], "r") as f:
            data = json.load(f)
            SCANS_DB[scan_id] = data
            return json.dumps(data, indent=2)
            
    return json.dumps({"error": f"Scan ID {scan_id} not found in database cache."}, indent=2)

@mcp.tool()
def validate_findings(findings_json: str, api_key: str = None) -> str:
    """
    Token-optimized finding validator. Reviews only High and Critical findings using LLM verification.
    
    Args:
        findings_json: A JSON string list representing the raw ZAP findings.
        api_key: Optional Gemini API Key override.
    """
    try:
        findings = json.loads(findings_json)
    except Exception as e:
        return f"Invalid findings JSON: {str(e)}"
        
    validator = ValidationAgent(findings, api_key=api_key)
    validated = validator.run()
    return json.dumps(validated, indent=2)

@mcp.tool()
def generate_report(data_json: str) -> str:
    """
    Synthesizes finding details, enrichment fields, and raw ZAP results to build the final JSON report structure.
    Calculates overall risk score and writes reports.
    
    Args:
        data_json: A JSON string containing 'target_url', 'scan_config', 'raw_findings', and 'validated_findings'.
    """
    try:
        data = json.loads(data_json)
    except Exception as e:
        return f"Invalid input data JSON: {str(e)}"
        
    reporter = ReportAgent(
        target_url=data.get("target_url"),
        scan_config=data.get("scan_config", {}),
        raw_findings=data.get("raw_findings", []),
        validated_findings=data.get("validated_findings", [])
    )
    report_data = reporter.run()
    return json.dumps(report_data, indent=2)

@mcp.tool()
def generate_pdf(report_json: str) -> str:
    """
    Generates downloadable PDF Executive and Technical reports from the JSON report data.
    
    Args:
        report_json: The report JSON string.
    """
    try:
        report_data = json.loads(report_json)
    except Exception as e:
        return f"Invalid report JSON: {str(e)}"
        
    pdf_gen = PDFReportGenerator(report_data)
    exec_pdf, tech_pdf = pdf_gen.run()
    return json.dumps({
        "message": "Reports compiled successfully.",
        "executive_report_pdf": exec_pdf,
        "technical_report_pdf": tech_pdf
    }, indent=2)

@mcp.tool()
def create_graphs(data_json: str) -> str:
    """
    Generates graphical charts showing the breakdown of security findings by severity and exports them as PNGs.
    
    Args:
        data_json: A JSON string representing the scan stats.
    """
    import matplotlib.pyplot as plt
    try:
        data = json.loads(data_json)
        stats = data.get("stats", {})
    except Exception as e:
        return f"Invalid stats JSON: {str(e)}"

    severities = ["Critical", "High", "Medium", "Low", "Info"]
    counts = [
        stats.get("critical", 0),
        stats.get("high", 0),
        stats.get("medium", 0),
        stats.get("low", 0),
        stats.get("informational", 0)
    ]
    colors_list = ["#742A2A", "#C53030", "#DD6B20", "#3182CE", "#4A5568"]

    plt.figure(figsize=(6, 4))
    plt.bar(severities, counts, color=colors_list)
    plt.title("Vulnerabilities by Severity Level")
    plt.xlabel("Severity")
    plt.ylabel("Number of Findings")
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    chart_path = "findings_severity_chart.png"
    plt.tight_layout()
    plt.savefig(chart_path, dpi=150)
    plt.close()
    
    return json.dumps({
        "message": "Chart generated successfully.",
        "chart_image_path": chart_path
    }, indent=2)

if __name__ == "__main__":
    mcp.run()
