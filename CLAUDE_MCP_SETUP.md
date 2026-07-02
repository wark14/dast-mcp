# 🛡️ Claude Desktop MCP Integration Guide

This guide outlines how to integrate the AI DAST MCP server with Claude Desktop. Once connected, Claude can directly execute vulnerability audits, detect web frameworks, run OWASP ZAP scanners, and compile PDF reports.

---

## 🛠️ Exposed MCP Tools

The server registers the following tools via FastMCP:

| Tool Name | Arguments | Description |
| :--- | :--- | :--- |
| `detect_framework` | `url` (string) | Inspects cookies, headers, and scripts to determine web frameworks (e.g. React, Laravel). |
| `crawl_site` | `url` (string) | Performs a fast crawl to index internal paths and state-changing forms. |
| `run_zap_scan` | `url` (string) | Connects to OWASP ZAP (or fallback) to execute spidering and active vulnerability checks. |
| `get_scan_results` | `scan_id` (string) | Retrieves parsed vulnerability data including request/response HTTP buffers. |
| `validate_findings` | `findings_json` (string), `api_key` (string, opt) | Runs LLM checks on High/Critical alerts for false positive reduction. |
| `generate_report` | `data_json` (string) | Compiles finding tables, computes risk scores (0-100), and outputs report schemas. |
| `generate_pdf` | `report_json` (string) | Triggers ReportLab to render `Executive_Report.pdf` and `Technical_VA_Report.pdf`. |
| `create_graphs` | `data_json` (string) | Generates severity breakdown bar-charts as PNGs. |

---

## ⚙️ Configuration File Locations

Claude Desktop reads configurations from the following system-specific locations:

- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

---

## 📝 Setup Step-by-Step

1. Open your system's `claude_desktop_config.json` file in a text editor.
2. In the `mcpServers` object, register this server with the absolute paths. Replace `/path/to/dast-mcp` with your actual workspace path:

```json
{
  "mcpServers": {
    "dast-security-testing-agent": {
      "command": "/path/to/dast-mcp/venv/bin/python3",
      "args": [
        "/path/to/dast-mcp/mcp_server.py"
      ],
      "env": {
        "GEMINI_API_KEY": "AIzaSy...",
        "ZAP_API_URL": "http://localhost:8080",
        "ZAP_API_KEY": "your-zap-api-key-here"
      }
    }
  }
}
```

*Note: Environment parameters inside the `"env"` object allow Claude to securely pass API keys and scanner URLs to the backend script.*

3. Save the config file and **completely restart** Claude Desktop.

---

## 🔍 Verification

Once restarted, look for the **plug icon** 🔌 in the bottom-right corner of the Claude Desktop prompt box. Hovering over it should list `dast-security-testing-agent` as active.

You can verify the connection by prompting Claude:
> *"List the tools available on the dast-security-testing-agent server and run a quick framework check on https://example.com"*
