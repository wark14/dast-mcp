import os
import json
import logging
from fastmcp import FastMCP, Context
from scan_engine import DASTScanEngine
from agents import ValidationAgent, ReportAgent, PDFReportGenerator
from pdf_generator import create_severity_chart

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DAST-MCP-Server")

# Initialize FastMCP Server
mcp = FastMCP(
    "DAST-Security-Testing-Server",
    instructions=(
        "AI-orchestrated DAST security testing toolkit. To run a full 1-click assessment, "
        "chain the tools in this order: detect_framework -> crawl_site (reconnaissance), "
        "run_zap_scan -> get_scan_results (scanning), validate_findings (AI review of High/Critical "
        "findings ONLY, for false-positive reduction — this runs on your own model via MCP sampling, "
        "no external API key required), then generate_report -> create_graphs -> "
        "generate_pdf (Executive_Report.pdf and Technical_VA_Report.pdf). Only High and Critical "
        "findings should be sent to validate_findings to conserve tokens; Medium/Low/Informational "
        "findings pass through to the reports unchanged."
    )
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
def run_zap_scan(url: str, active_scan: bool = True) -> str:
    """
    Runs a real OWASP ZAP DAST scan on the target URL (crawling, framework detection, and
    vulnerability testing). Auto-starts the bundled ZAP daemon. Saves the result to the cache.

    Args:
        url: The target website URL.
        active_scan: When True (default), run ZAP's active scanner, which sends intrusive
            attack payloads (SQLi, XSS, etc.) — only use on targets you are authorized to test.
            When False, run a safe passive-only scan (spider + response analysis, no attacks).
    """
    logger.info(f"Triggering scan for target: {url} (active_scan={active_scan})")
    engine = DASTScanEngine(url)
    scan_results = engine.run_dast_scan(active_scan=active_scan)
    scan_id = scan_results["scan_id"]
    SCANS_DB[scan_id] = scan_results
    filename = f"scan_results_{scan_id}.json"
    logger.info(f"DAST scan completed successfully. Results saved to {filename}")
    return json.dumps({
        "message": "DAST scan completed successfully.",
        "scan_id": scan_id,
        "findings_count": len(scan_results["findings"]),
        "results_file": filename
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
async def validate_findings(findings_json: str, ctx: Context, api_key: str = None) -> str:
    """
    Token-optimized finding validator. Reviews ONLY High and Critical findings.

    Chooses the LLM automatically:
      - If a Gemini key is available (the `api_key` arg or the GEMINI_API_KEY env var),
        validation runs via Google Gemini.
      - Otherwise it runs via the connected MCP client's own model (e.g. Claude) using
        MCP sampling — no external API key is required.

    Args:
        findings_json: A JSON string list representing the raw ZAP findings.
        api_key: Optional Gemini API Key override.
    """
    try:
        findings = json.loads(findings_json)
    except Exception as e:
        return f"Invalid findings JSON: {str(e)}"

    agent = ValidationAgent(findings, api_key=api_key)
    high_crit = agent.filter_high_critical()
    logger.info(f"Validating {len(high_crit)} High/Critical findings out of {len(findings)} total.")
    if not high_crit:
        return json.dumps([], indent=2)

    # Prefer an explicit Gemini key when one is configured (arg or env).
    if agent.api_key:
        return json.dumps(agent.run(), indent=2)

    # No Gemini key -> ask the connected client model (Claude) to validate via MCP sampling.
    try:
        result = await ctx.sample(
            agent.build_prompt(high_crit),
            system_prompt=ValidationAgent.SYSTEM_PROMPT,
            temperature=0.2,
        )
        validated = ValidationAgent.parse_validation_response(result.text)
        logger.info(f"Validated {len(validated)} findings via MCP client sampling.")
        return json.dumps(validated, indent=2)
    except Exception as e:
        logger.error(f"MCP client sampling unavailable: {e}")
        return json.dumps({
            "error": "AI validation needs either a GEMINI_API_KEY or an MCP client that supports "
                     "sampling; neither was available. Scan/report tools still work without it.",
            "detail": str(e),
        }, indent=2)

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
        validated_findings=data.get("validated_findings", []),
        scan_id=data.get("scan_id") or data.get("scan_config", {}).get("scan_id")
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
    try:
        data = json.loads(data_json)
        stats = data.get("stats", {})
    except Exception as e:
        return f"Invalid stats JSON: {str(e)}"

    chart_path = create_severity_chart(stats)

    return json.dumps({
        "message": "Chart generated successfully.",
        "chart_image_path": chart_path
    }, indent=2)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DAST Security Testing MCP Server")
    parser.add_argument(
        "--transport",
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
        choices=["stdio", "http", "streamable-http", "sse"],
        help="MCP transport to serve on. Default 'stdio' (for Claude Desktop / local clients). "
             "Use 'http' to expose a networked Streamable HTTP endpoint. Env: MCP_TRANSPORT.",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MCP_HOST", "127.0.0.1"),
        help="Host/interface to bind for HTTP transports (default: 127.0.0.1). Env: MCP_HOST.",
    )
    parser.add_argument(
        "--port", type=int,
        default=int(os.environ.get("MCP_PORT", "8000")),
        help="Port to bind for HTTP transports (default: 8000). Env: MCP_PORT.",
    )
    parser.add_argument(
        "--path",
        default=os.environ.get("MCP_PATH", "/mcp"),
        help="URL path for the HTTP MCP endpoint (default: /mcp). Env: MCP_PATH.",
    )
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run()
    else:
        logger.info(
            f"Starting DAST MCP server over {args.transport} at "
            f"http://{args.host}:{args.port}{args.path}"
        )
        mcp.run(transport=args.transport, host=args.host, port=args.port, path=args.path)
