import os
import json
import time
import requests
import logging
import re
from scan_engine import DASTScanEngine
from pdf_generator import generate_pdf_report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Agents")

class ReconAgent:
    def __init__(self, target_url):
        self.target_url = target_url

    def run(self):
        logger.info(f"[Recon Agent] Analyzing target: {self.target_url}")
        engine = DASTScanEngine(self.target_url)
        # Perform quick reconnaissance
        frameworks = engine.detect_framework()
        crawled_urls = engine.crawl_site(max_pages=5) # quick crawl for recon
        
        scan_profile = "Standard Profile"
        use_ajax = False
        if any("WordPress" in f for f in frameworks):
            scan_profile = "WordPress Focused Profile"
        elif any("React" in f or "Angular" in f or "Vue" in f or "Next.js" in f for f in frameworks):
            scan_profile = "SPA/Ajax Focused Profile"
            use_ajax = True
            
        scan_config = {
            "target_url": self.target_url,
            "frameworks": frameworks,
            "detected_forms_count": len(engine.forms_found),
            "scan_profile": scan_profile,
            "use_ajax_spider": use_ajax,
            "pages_to_scan": crawled_urls
        }
        logger.info(f"[Recon Agent] Recon completed. Frameworks: {frameworks}. Profile: {scan_profile}")
        return scan_config


class ScanAgent:
    def __init__(self, scan_config):
        self.scan_config = scan_config

    def run(self):
        active_scan = self.scan_config.get("active_scan", True)
        mode = "active + passive" if active_scan else "passive only"
        logger.info(f"[Scan Agent] Running DAST scan ({mode}) on: {self.scan_config['target_url']}")
        engine = DASTScanEngine(self.scan_config['target_url'])
        # Pass dynamic spider preference determined by Recon Agent and the active-scan toggle.
        scan_results = engine.run_dast_scan(
            use_ajax_spider=self.scan_config.get("use_ajax_spider", False),
            active_scan=active_scan,
        )
        logger.info(f"[Scan Agent] Scan completed. Found {len(scan_results['findings'])} total raw findings.")
        return scan_results


class ValidationAgent:
    # Shared LLM role prompt, reused by both the Gemini (webapp/CLI) path and the
    # MCP client-sampling (Claude) path so validation behaves identically either way.
    SYSTEM_PROMPT = (
        "You are a Senior Web Application Penetration Tester and AI Security Agent. "
        "You analyze High/Critical DAST findings, estimate the likelihood of false positives, "
        "assign confidence scores, deduplicate similar findings, and provide concrete remediation."
    )

    def __init__(self, raw_findings, api_key=None):
        self.raw_findings = raw_findings
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")

    def filter_high_critical(self):
        """Token optimization: only High/Critical findings are ever sent to an LLM."""
        return [
            f for f in self.raw_findings
            if str(f.get("risk", "")).lower() in ["critical", "high"]
        ]

    def build_prompt(self, findings):
        """Builds the validation instruction + findings payload (LLM-agnostic)."""
        return (
            "Analyze the following High/Critical DAST vulnerability findings and determine "
            "whether each is likely a false positive. Assess exploitability, assign a confidence "
            "score, deduplicate similar findings, and provide clear remediation.\n\n"
            "Here is the list of findings in JSON format:\n"
            f"{json.dumps(findings, indent=2)}\n\n"
            "Respond ONLY with a JSON array containing the validated results. Do not include "
            "markdown code block formatting (such as ```json). Each element MUST correspond to a "
            "finding ID from the input and use the following schema:\n"
            "[\n"
            "  {\n"
            "    \"id\": \"<finding_id>\",\n"
            "    \"is_false_positive\": true/false,\n"
            "    \"confidence\": <float 0.0 to 1.0>,\n"
            "    \"reasoning\": \"Detailed security justification based on the description and evidence.\",\n"
            "    \"solution\": \"Specific remediation steps.\",\n"
            "    \"is_duplicate\": true/false,\n"
            "    \"duplicate_of_id\": \"<parent_id_if_duplicate_else_null>\"\n"
            "  }\n"
            "]"
        )

    @staticmethod
    def parse_validation_response(text):
        """Parses an LLM response into a validated-findings list; tolerant of code fences."""
        if not text:
            return []
        text = re.sub(r"^```json\s*", "", text.strip())
        text = re.sub(r"\s*```$", "", text)
        try:
            data = json.loads(text)
            return data if isinstance(data, list) else []
        except Exception as e:
            logger.error(f"[Validation Agent] Failed to parse validation response: {e}")
            return []

    def run(self):
        """
        Webapp/CLI entrypoint. Uses Google Gemini when a key is available; otherwise skips AI
        validation entirely (no fabricated confidence/badges). When the pipeline is driven over
        MCP, the connected client's own model performs validation instead — see
        mcp_server.validate_findings — so no external key is required there.
        """
        logger.info("[Validation Agent] Reviewing High and Critical findings...")
        high_crit = self.filter_high_critical()
        logger.info(
            f"[Validation Agent] Filtered {len(high_crit)} High/Critical findings out of "
            f"{len(self.raw_findings)} total."
        )

        if not high_crit:
            logger.info("[Validation Agent] No High/Critical findings to validate.")
            return []

        if not self.api_key:
            logger.info("[Validation Agent] No Gemini API key detected. Skipping AI validation.")
            return []

        return self._validate_with_llm(high_crit)

    def _validate_with_llm(self, findings):
        """Gemini validation path (used by the webapp/CLI when GEMINI_API_KEY is set)."""
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        headers = {"Content-Type": "application/json", "x-goog-api-key": self.api_key}
        payload = {
            "contents": [{
                "parts": [{"text": self.SYSTEM_PROMPT + "\n\n" + self.build_prompt(findings)}]
            }],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
        }

        try:
            response = requests.post(f"{url}?key={self.api_key}", json=payload, headers=headers, timeout=30)
            if response.status_code == 200:
                res_data = response.json()
                candidates = res_data.get("candidates", [])
                if not candidates:
                    logger.error(f"[Validation Agent] Gemini API returned no candidates (possibly blocked): {res_data}")
                    return []
                text_content = candidates[0]["content"]["parts"][0]["text"]
                validated_list = self.parse_validation_response(text_content)
                logger.info("[Validation Agent] Successfully validated findings via Gemini API.")
                return validated_list
            else:
                logger.error(f"[Validation Agent] Gemini API returned error code {response.status_code}: {response.text}")
        except Exception as e:
            logger.error(f"[Validation Agent] Exception occurred during Gemini API validation: {e}")

        return []


class ReportAgent:
    def __init__(self, target_url, scan_config, raw_findings, validated_findings):
        self.target_url = target_url
        self.scan_config = scan_config
        self.raw_findings = raw_findings
        self.validated_findings = validated_findings

    def run(self):
        logger.info("[Report Agent] Generating reports...")
        
        # Create map of validated findings by ID (empty if AI wasn't used)
        val_map = {vf["id"]: vf for vf in self.validated_findings}
        ai_used = len(self.validated_findings) > 0
        
        enriched_findings = []
        stats = {
            "critical": 0,
            "critical_validated": 0,
            "high": 0,
            "high_validated": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }

        for rf in self.raw_findings:
            severity = str(rf.get("risk", "")).lower()
            finding_id = rf.get("id")
            
            # Enrich with AI data if validated
            if finding_id in val_map:
                v_data = val_map[finding_id]
                rf["is_false_positive"] = v_data["is_false_positive"]
                rf["ai_confidence"] = v_data["confidence"]
                rf["ai_reasoning"] = v_data["reasoning"]
                rf["solution"] = v_data["solution"]
                
                if severity == "critical":
                    stats["critical"] += 1
                    if not v_data["is_false_positive"]:
                        stats["critical_validated"] += 1
                elif severity == "high":
                    stats["high"] += 1
                    if not v_data["is_false_positive"]:
                        stats["high_validated"] += 1
            else:
                # No AI data
                if severity == "critical":
                    stats["critical"] += 1
                    stats["critical_validated"] += 1 # assume true positive if not AI checked
                elif severity == "high":
                    stats["high"] += 1
                    stats["high_validated"] += 1 # assume true positive if not AI checked
                elif severity == "medium":
                    stats["medium"] += 1
                elif severity == "low":
                    stats["low"] += 1
                else:
                    stats["informational"] += 1
            
            enriched_findings.append(rf)

        # Calculate Risk Score (0-100), anchored to the WORST active severity so that a large
        # volume of low-severity findings can never inflate the profile to "critical".
        active = [f for f in enriched_findings if not f.get("is_false_positive", False)]
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in active:
            sev = str(f.get("risk", "")).lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
        n_crit = sev_counts["critical"]
        n_high = sev_counts["high"]
        n_med = sev_counts["medium"]
        n_low = sev_counts["low"]

        # The band (and its base score) is set by the highest severity present; counts only
        # nudge the score WITHIN the band (capped) so they can't cross into a higher band.
        if n_crit:
            base, risk_desc = 80, "CRITICAL RISK PROFILE"
        elif n_high:
            base, risk_desc = 55, "HIGH RISK PROFILE"
        elif n_med:
            base, risk_desc = 25, "MEDIUM RISK PROFILE"
        elif n_low:
            base, risk_desc = 8, "LOW RISK PROFILE"
        else:
            base, risk_desc = 0, "LOW RISK PROFILE"

        bonus = min(n_crit * 6 + n_high * 4 + n_med * 1.5 + n_low * 0.5, 19)
        risk_score = int(min(base + bonus, 100))

        active_criticals = n_crit
        active_highs = n_high

        # Generate Executive Summary Text based on the risk band.
        if risk_desc == "CRITICAL RISK PROFILE":
            summary_text = (
                f"The security assessment of {self.target_url} revealed a CRITICAL risk profile with a risk score of {risk_score}/100. "
                f"{n_crit} Critical and {n_high} High severity vulnerabilities are active. "
                "Immediate remediation is required to prevent server compromise or data leakage."
            )
            business_impact = (
                "The current security posture represents an immediate threat to business operations, client confidentiality, "
                "and regulatory compliance. Exploitable critical vulnerabilities could allow attackers to steal sensitive "
                "records, resulting in financial penalties, reputational damage, and loss of client trust."
            )
            recs = [
                "Remediate all Critical findings immediately (e.g. parameterized queries for any injection points).",
                "Address High severity findings before the next release.",
                "Deploy anti-CSRF protection and restrict verbose server banners."
            ]
        elif risk_desc == "HIGH RISK PROFILE":
            summary_text = (
                f"The security assessment of {self.target_url} identified a HIGH risk profile with a risk score of {risk_score}/100. "
                f"{n_high} High severity vulnerabilities are active, alongside {n_med} Medium and {n_low} Low severity issues. "
                "No Critical vulnerabilities were confirmed, but High findings should be prioritized in the current cycle."
            )
            business_impact = (
                "High severity issues can meaningfully weaken the application's security posture and, if chained, may expose "
                "sensitive functionality. Prompt remediation is recommended to reduce the likelihood of a successful attack."
            )
            recs = [
                "Prioritize remediation of all High severity findings this cycle.",
                "Deploy anti-CSRF token middleware and enforce security headers (CSP, X-Frame-Options).",
                "Re-scan to confirm fixes and check for regressions."
            ]
        elif risk_desc == "MEDIUM RISK PROFILE":
            summary_text = (
                f"The security assessment of {self.target_url} identified a MEDIUM risk profile with a risk score of {risk_score}/100. "
                f"No Critical or High severity vulnerabilities are active. {n_med} Medium and {n_low} Low severity issues — "
                "largely configuration and hardening gaps — were identified. Plan remediation in an upcoming sprint."
            )
            business_impact = (
                "The core application appears reasonably secured, but supplementary controls (such as security headers or "
                "cross-site request validation) are missing. These gaps could aid an attacker but are not directly exploitable on their own."
            )
            recs = [
                "Ensure X-Frame-Options and Content Security Policy (CSP) headers are set on all responses.",
                "Add anti-CSRF tokens to state-changing forms.",
                "Address remaining Medium findings during routine maintenance."
            ]
        else:
            summary_text = (
                f"The security assessment of {self.target_url} indicates a LOW risk profile with a risk score of {risk_score}/100. "
                f"No Critical or High severity vulnerabilities are active. {n_med} Medium and {n_low} Low severity hardening "
                "recommendations were identified. Standard configuration improvements are advised."
            )
            business_impact = (
                "The business impact is low. Current security configurations meet basic safety baselines, but the posture "
                "can be further strengthened by completing the recommended security header and hardening updates."
            )
            recs = [
                "Add any missing HTTP security headers (X-Content-Type-Options, HSTS, CSP).",
                "Periodically re-scan to catch regressions as the application changes."
            ]

        report_data = {
            "target_url": self.target_url,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "frameworks": self.scan_config.get("frameworks", []),
            "scan_profile": self.scan_config.get("scan_profile", "Standard Profile"),
            "active_scan": self.scan_config.get("active_scan", True),
            "pages_crawled": self.scan_config.get("pages_to_scan", []),
            "pages_crawled_count": len(self.scan_config.get("pages_to_scan", [])),
            "forms_found_count": self.scan_config.get("detected_forms_count", 0),
            "risk_score": risk_score,
            "risk_desc": risk_desc,
            "executive_summary": summary_text,
            "business_impact": business_impact,
            "strategic_recommendations": recs,
            "stats": stats,
            "findings": enriched_findings,
            "ai_used": ai_used
        }

        with open("executive_report.json", "w") as f:
            json.dump(report_data, f, indent=4)
        
        with open("technical_va_report.json", "w") as f:
            json.dump(report_data, f, indent=4)

        logger.info("[Report Agent] Generated JSON report databases.")
        return report_data


class PDFReportGenerator:
    def __init__(self, report_data):
        self.report_data = report_data

    def run(self):
        logger.info("[PDF Generator] Compiling PDF reports...")
        exec_path = "Executive_Report.pdf"
        tech_path = "Technical_VA_Report.pdf"
        
        generate_pdf_report(self.report_data, exec_path, is_executive=True)
        generate_pdf_report(self.report_data, tech_path, is_executive=False)
        
        logger.info(f"[PDF Generator] PDFs compiled successfully:\n - {exec_path}\n - {tech_path}")
        return exec_path, tech_path
