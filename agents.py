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
        logger.info(f"[Scan Agent] Running DAST scan on: {self.scan_config['target_url']}")
        engine = DASTScanEngine(self.scan_config['target_url'])
        # Pass dynamic spider preference determined by Recon Agent
        scan_results = engine.run_dast_scan(use_ajax_spider=self.scan_config.get("use_ajax_spider", False))
        logger.info(f"[Scan Agent] Scan completed. Found {len(scan_results['findings'])} total raw findings.")
        return scan_results


class ValidationAgent:
    def __init__(self, raw_findings, api_key=None):
        self.raw_findings = raw_findings
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")

    def run(self):
        logger.info("[Validation Agent] Reviewing High and Critical findings...")
        
        # 1. Filter High and Critical findings
        high_crit_findings = [
            f for f in self.raw_findings 
            if str(f.get("risk", "")).lower() in ["critical", "high"]
        ]
        
        logger.info(f"[Validation Agent] Filtered {len(high_crit_findings)} High/Critical findings out of {len(self.raw_findings)} total.")
        
        if not high_crit_findings:
            logger.info("[Validation Agent] No High/Critical findings to validate.")
            return []

        # STRICT RULE: If no API key is provided, we do NOT perform AI validation.
        # This prevents showing "Analyzed by AI" or fake confidence ratings when AI was not actually used.
        if not self.api_key:
            logger.info("[Validation Agent] No API key detected. Skipping AI validation as requested.")
            return []

        # Run actual LLM Validation
        return self._validate_with_llm(high_crit_findings)

    def _validate_with_llm(self, findings):
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key
        }
        
        prompt = (
            "You are a Senior Web Application Penetration Tester and AI Security Agent. "
            "Your task is to analyze the following High/Critical DAST vulnerability findings and determine "
            "if they are likely false positives. Assess the likelihood of exploitation, assign a confidence score, "
            "deduplicate any duplicates, and provide clear remediation steps.\n\n"
            "Here is the list of findings in JSON format:\n"
            f"{json.dumps(findings, indent=2)}\n\n"
            "Respond ONLY with a JSON array containing the validated results. Do not include markdown code block formatting (such as ```json). "
            "Each element in the returned array MUST correspond to a finding ID from the input and have the following schema:\n"
            "[\n"
            "  {\n"
            "    \"id\": \"<finding_id>\",\n"
            "    \"is_false_positive\": true/false,\n"
            "    \"confidence\": <float 0.0 to 1.0>,\n"
            "    \"reasoning\": \"Detailed security justification explaining why this is/is not a false positive based on the description and evidence.\",\n"
            "    \"solution\": \"Specific remediation steps.\",\n"
            "    \"is_duplicate\": true/false,\n"
            "    \"duplicate_of_id\": \"<parent_id_if_duplicate_else_null>\"\n"
            "  }\n"
            "]"
        )

        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json"
            }
        }

        try:
            response = requests.post(f"{url}?key={self.api_key}", json=payload, headers=headers, timeout=30)
            if response.status_code == 200:
                res_data = response.json()
                text_content = res_data['contents'][0]['parts'][0]['text']
                text_content = re.sub(r"^```json\s*", "", text_content.strip())
                text_content = re.sub(r"\s*```$", "", text_content)
                validated_list = json.loads(text_content)
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

        # Calculate Risk Score: (0-100 scale)
        score = 0
        for f in enriched_findings:
            severity = str(f.get("risk", "")).lower()
            is_fp = f.get("is_false_positive", False)
            if is_fp:
                continue
            
            if severity == "critical":
                score += 25
            elif severity == "high":
                score += 15
            elif severity == "medium":
                score += 7
            elif severity == "low":
                score += 2
        
        risk_score = min(score, 100)

        # Generate Executive Summary Text based on results
        active_criticals = stats["critical_validated"]
        active_highs = stats["high_validated"]
        
        if risk_score >= 70:
            risk_desc = "CRITICAL RISK PROFILE"
            summary_text = (
                f"The security assessment of {self.target_url} has revealed a {risk_desc} with a risk score of {risk_score}/100. "
                f"A total of {active_criticals} Critical and {active_highs} High vulnerabilities have been validated as active. "
                "Immediate remediation is required to safeguard systems and prevent complete server compromise or data leakage."
            )
            business_impact = (
                "The current security posture represents an immediate threat to business operations, client confidentiality, "
                "and regulatory compliance. Exposure of SQL databases and form controllers could allow attackers to steal "
                "sensitive records, resulting in financial penalties, reputational damage, and loss of client trust."
            )
            recs = [
                "Implement parameterized SQL queries immediately on all database query points.",
                "Deploy CSRF protection frameworks across all POST forms to prevent session hijack triggers.",
                "Restrict details in server response banners to minimize technical leakage to recon tools."
            ]
        elif risk_score >= 30:
            risk_desc = "MEDIUM RISK PROFILE"
            summary_text = (
                f"The security assessment of {self.target_url} has identified a {risk_desc} with a risk score of {risk_score}/100. "
                f"Although critical vulnerabilities were resolved or flagged as false positives, {active_highs} High severity issues "
                "and several configuration deficiencies remain. Remediation should be planned in the current sprint cycle."
            )
            business_impact = (
                "A medium risk score indicates that while core code layers are partially secured, supplementary components "
                "(such as cross-site request validation or security headers) are unconfigured. Attacks could disrupt user actions."
            )
            recs = [
                "Deploy anti-CSRF token middleware on Web App controls.",
                "Ensure X-Frame-Options and Content Security Policy (CSP) headers are active on all public response pages."
            ]
        else:
            risk_desc = "LOW RISK PROFILE"
            summary_text = (
                f"The security assessment of {self.target_url} indicates a {risk_desc} with a risk score of {risk_score}/100. "
                "No critical or high-severity vulnerabilities are active on this application. Standard server configuration improvements "
                "are recommended to achieve industry-best-practice configurations."
            )
            business_impact = (
                "The business impact is low. Current security configurations meet basic safety baselines, but security posture "
                "can be further strengthened by completing recommended security header updates."
            )
            recs = [
                "Add missing HTTP security headers (X-Content-Type-Options, HSTS) to web server configurations."
            ]

        report_data = {
            "target_url": self.target_url,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "frameworks": self.scan_config.get("frameworks", []),
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
