# 🛡️ Claude Desktop MCP Integration Guide

This guide outlines how to integrate the AI DAST MCP server with Claude Desktop. Once connected, Claude can directly execute vulnerability audits, detect web frameworks, run OWASP ZAP scanners, and compile PDF reports.

> **Prerequisite:** OWASP ZAP is required and must be installed first with `./setup_zap.sh` (installs a self-contained ZAP into `./zap/`). The `run_zap_scan` tool auto-starts that bundled daemon; there is no simulated fallback.

---

## 🛠️ Exposed MCP Tools

The server registers the following tools via FastMCP:

| Tool Name | Arguments | Description |
| :--- | :--- | :--- |
| `detect_framework` | `url` (string) | Inspects cookies, headers, and scripts to determine web frameworks (e.g. React, Laravel). |
| `crawl_site` | `url` (string) | Performs a fast crawl to index internal paths and state-changing forms. |
| `run_zap_scan` | `url` (string) | Runs a real OWASP ZAP scan (auto-starts the bundled ZAP daemon) to execute spidering and active vulnerability checks. |
| `get_scan_results` | `scan_id` (string) | Retrieves parsed vulnerability data including request/response HTTP buffers. |
| `validate_findings` | `findings_json` (string), `api_key` (string, opt) | Runs LLM checks on High/Critical alerts for false positive reduction. Uses **your own model (Claude) via MCP sampling — no key needed**; only falls back to Gemini if a key is provided. |
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
      ]
    }
  }
}
```

The `"env"` block is entirely optional and can be omitted:

- **No `GEMINI_API_KEY` needed.** When Claude drives this server, `validate_findings` runs on Claude's own model via MCP sampling. Add `GEMINI_API_KEY` only if you want to force Gemini to do the validation instead.
- **`ZAP_API_URL` / `ZAP_API_KEY`** are only needed to point at an *external* ZAP. By default the bundled `./zap` (installed via `./setup_zap.sh`) is auto-started on `localhost:8080`.

```json
      "env": {
        "GEMINI_API_KEY": "AIzaSy...",          // optional: use Gemini instead of Claude
        "ZAP_API_URL": "http://localhost:8080", // optional: external ZAP
        "ZAP_API_KEY": "your-zap-api-key-here"  // optional
      }
```

3. Save the config file and **completely restart** Claude Desktop.

---

## 🔍 Verification

Once restarted, look for the **plug icon** 🔌 in the bottom-right corner of the Claude Desktop prompt box. Hovering over it should list `dast-security-testing-agent` as active.

You can verify the connection by prompting Claude:
> *"List the tools available on the dast-security-testing-agent server and run a quick framework check on https://example.com"*

---

## 🌐 HTTP Transport (remote / networked clients)

Claude Desktop launches the server over **stdio** (the config above). For MCP clients that connect to a URL instead of spawning the process, run the server over **Streamable HTTP**:

```bash
python3 mcp_server.py --transport http --host 0.0.0.0 --port 8000 --path /mcp
```

Clients then point at `http://<host>:8000/mcp`. The transport can also be set via environment variables (`MCP_TRANSPORT=http`, `MCP_HOST`, `MCP_PORT`, `MCP_PATH`), which is handy inside the `"env"` block of a client config. Bind to `127.0.0.1` unless the endpoint is intentionally exposed, and place it behind TLS/auth for any non-local use.
