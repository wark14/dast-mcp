# AI DAST Security Testing Agent (Orchestrator & MCP Server)

An AI-powered, **1-click Dynamic Application Security Testing (DAST)** orchestration tool that integrates lightweight reconnaissance, real **OWASP ZAP** scanning, token-optimized AI validation, and professional PDF report generation.

> **OWASP ZAP is required.** Findings come exclusively from a real ZAP scan — there is no simulated/fallback scanner and no fabricated findings. A self-contained ZAP (bundled with its own Java runtime) is installed into `./zap/` via `./setup_zap.sh` and is auto-started on the first scan.

## 🚀 Key Features

- **1-Click Scanning Pipeline**: Provide a URL; the Recon Agent, Scan Agent, Validation Agent, Report Agent, and PDF Generator run automatically in sequence.
- **Multi-Agent Architecture**:
  - **Recon Agent**: Crawls target links, discovers input forms, detects technology stack/frameworks (React, Next.js, Django, WordPress, etc.), and sets the scan profile.
  - **Scan Agent**: Drives a real **OWASP ZAP** scan — auto-starting the bundled ZAP daemon, running the standard or AJAX spider (chosen from the recon profile), then (optionally) the active scanner, and extracting genuine alerts with their HTTP request/response evidence. No simulated findings.
  - **Active-scan toggle**: The active scanner sends intrusive attack payloads (SQLi, XSS, …). It can be disabled for a safe **passive-only** scan (spider + response analysis) — via the web UI checkbox, the CLI `--no-active-scan` flag, or the MCP `run_zap_scan(active_scan=false)` argument.
  - **Validation Agent (Token-Optimized)**: Extracts only High and Critical findings and routes them to an LLM to eliminate false positives and explain vulnerability mechanics. Over MCP it uses the **connected client's own model (e.g. Claude) via MCP sampling — no API key needed**; in the web app / CLI it optionally uses **Google Gemini** when `GEMINI_API_KEY` is set.
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

3. **Install OWASP ZAP (required, one-time)**:
   ZAP is the scanning engine and is mandatory. This installs a self-contained ZAP
   (with its own bundled Java runtime) into `./zap/` — no system Java or Docker needed:
   ```bash
   ./setup_zap.sh
   ```
   The app auto-starts this ZAP daemon on the first scan (~30–60s the first time) and
   reuses it afterwards. To point at an existing ZAP instead, set `ZAP_API_URL` (and
   `ZAP_API_KEY` if enabled).

4. **Configure API Key (Optional — web app / CLI only)**:
   The Validation Agent needs an LLM. **How it gets one depends on how you run the tool:**
   - **Over MCP (e.g. Claude Desktop / Claude Code):** validation runs on the client's own
     model via MCP sampling. **No API key required** — nothing to configure here.
   - **Web app / CLI:** set a Gemini key to enable validation:
     ```bash
     export GEMINI_API_KEY="your-api-key-here"
     ```
     If no key is supplied here, the Validation Agent is skipped — the scan still runs and both
     reports are generated from the raw ZAP findings, but High/Critical findings won't carry AI
     confidence scores, false-positive verdicts, or reasoning. This is intentional: it avoids
     presenting "AI-verified" badges when no AI was actually used.

---

## 💻 Usage

### Option A: Interactive Web UI (Recommended)
Launch the dark-themed web dashboard:
```bash
python3 app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser. Input your target URL, click **Start 1-Click Scan**, and watch the real-time logs. Results are organized into two tabs:
- **🔎 Recon** — detected technology stack, selected scan profile, crawled endpoints, and discovered forms (attack surface).
- **🛡️ Scan** — risk score, severity breakdown, per-finding ZAP evidence, and (when a Gemini key is set) AI validation of High/Critical findings.

Then download the compiled Executive and Technical PDFs.

### Option B: CLI Orchestrator
Run a scan directly from your terminal:
```bash
python3 dast_orchestrator.py https://example.com
```

### Option C: MCP Server Mode
The server supports two transports:

**stdio (default)** — for local clients like Claude Desktop, which launch the process:
```bash
/path/to/dast-mcp/venv/bin/python3 /path/to/dast-mcp/mcp_server.py
```

**HTTP (Streamable HTTP)** — for networked/remote MCP clients. Run it as a long-lived server:
```bash
python3 mcp_server.py --transport http --host 0.0.0.0 --port 8000 --path /mcp
```
Clients then connect to `http://<host>:8000/mcp`. All flags also read from env vars
(`MCP_TRANSPORT`, `MCP_HOST`, `MCP_PORT`, `MCP_PATH`), e.g. `MCP_TRANSPORT=http python3 mcp_server.py`.

### Option D: Run Unit Tests
To execute the automated pipeline test suite:
```bash
python3 -m unittest test_dast_pipeline.py
```
