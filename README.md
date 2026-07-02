# AI DAST Security Testing Agent (Orchestrator & MCP Server)

An AI-powered, **1-click Dynamic Application Security Testing (DAST)** orchestration tool that integrates lightweight reconnaissance, OWASP ZAP scanning simulation, token-optimized AI validation, and professional PDF report generation.

## 🚀 Key Features

- **1-Click Scanning Pipeline**: Provide a URL; the Recon Agent, Scan Agent, Validation Agent, Report Agent, and PDF Generator run automatically in sequence.
- **Multi-Agent Architecture**:
  - **Recon Agent**: Crawls target links, discovers input forms, detects technology stack/frameworks (React, Next.js, Django, WordPress, etc.), and sets the scan profile.
  - **Scan Agent**: Runs automated DAST tests (security headers, cookie leakage, forms lacking anti-CSRF) and mimics custom OWASP ZAP configurations.
  - **Validation Agent (Token-Optimized)**: Extracts only High and Critical findings and routes them to the Gemini LLM to eliminate false positives and explain vulnerability mechanics.
  - **Report Agent**: Dynamically computes risk scores (0-100), evaluates business impacts, and writes intermediate JSON report schemas.
  - **PDF Generator**: Compiles beautiful, letter-sized PDF reports (`Executive_Report.pdf` and `Technical_VA_Report.pdf`) featuring custom styling, page numbers ("Page X of Y"), and severity charts.
- **MCP Server Capabilities**: Exposes the complete security toolkit as MCP tools for integration into Claude Desktop or other MCP-compatible clients.
- **Beautiful Dark-Theme Dashboard**: A premium, highly interactive web UI built with HTML/CSS (featuring smooth transitions, real-time logging terminal, animated charts, and download links).

---

## 🛠️ Project Structure

- `scan_engine.py`: Core DAST scanner and crawler analyzing links, inputs, and response headers.
- `agents.py`: Orchestration logic for Recon, Scan, Validation, Report, and PDF compilation agents.
- `pdf_generator.py`: Custom `ReportLab` implementation for generating professional security documents.
- `dast_orchestrator.py`: Command Line Interface (CLI) driver for running scans directly from the terminal.
- `app.py`: Web dashboard Flask server displaying progress and real-time logs.
- `mcp_server.py`: FastMCP server exposing tools for MCP clients.
- `test_dast_pipeline.py`: Automated unit tests verifying the end-to-end security pipeline.

---

## 💾 Installation & Setup

1. **Clone/Navigate to Workspace**:
   ```bash
   cd dast-mcp
   ```

2. **Activate the Virtual Environment**:
   ```bash
   source venv/bin/activate
   ```

3. **Configure API Key (Optional)**:
   To run actual LLM-based verification using Gemini, set your API key:
   ```bash
   export GEMINI_API_KEY="your-api-key-here"
   ```
   *Note: If no API key is supplied, the agent automatically falls back to an integrated Smart Fallback Heuristic Engine to simulate the AI validation analysis.*

---

## 💻 Usage

### Option A: Interactive Web UI (Recommended)
Launch the dark-themed web dashboard:
```bash
python3 app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser. Input your target URL, click **Start 1-Click Scan**, watch the real-time logs, and download the compiled PDFs!

### Option B: CLI Orchestrator
Run a scan directly from your terminal:
```bash
python3 dast_orchestrator.py https://example.com
```

### Option C: MCP Server Mode
To integrate these tools into an MCP client, register the server script with the following path:
```bash
/path/to/dast-mcp/venv/bin/python3 /path/to/dast-mcp/mcp_server.py
```

### Option D: Run Unit Tests
To execute the automated pipeline test suite:
```bash
python3 -m unittest test_dast_pipeline.py
```
