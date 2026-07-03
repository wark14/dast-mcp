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
        scan_results = engine.run_dast_scan(
            use_ajax_spider=self.scan_config.get("use_ajax_spider", False),
            active_scan=active_scan,
        )
        
        # Log explicitly how many High and Critical findings were detected.
        crit_count = sum(1 for f in scan_results['findings'] if f.get('risk', '').lower() == 'critical')
        high_count = sum(1 for f in scan_results['findings'] if f.get('risk', '').lower() == 'high')
        logger.info(
            f"[Scan Agent] Scan completed. Found {len(scan_results['findings'])} total raw findings. "
            f"Severity counts: {crit_count} Critical, {high_count} High findings."
        )
        return scan_results


class ValidationAgent:
    SYSTEM_PROMPT = (
        "You are a Senior Web Application Penetration Tester and AI Security Agent. "
        "You analyze High/Critical DAST findings, estimate the likelihood of false positives, "
        "assign confidence scores, deduplicate similar findings, and provide concrete remediation. "
        "Even if you classify a finding as a False Positive, you must still return it, setting "
        "is_false_positive to true, and explain your reasoning in the reasoning field."
    )

    def __init__(self, raw_findings, api_key=None):
        self.raw_findings = raw_findings
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")

    def filter_high_critical(self):
        return [
            f for f in self.raw_findings
            if str(f.get("risk", "")).lower() in ["critical", "high"]
        ]

    def build_prompt(self, findings):
        return (
            "Analyze the following High/Critical DAST vulnerability findings and determine "
            "whether each is likely a false positive. Assess exploitability, assign a confidence "
            "score, deduplicate similar findings, and provide clear remediation. Even if a "
            "finding is marked as a False Positive, do not remove it. Set is_false_positive: true "
            "and detail your reasons in the reasoning field.\n\n"
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
            "    \"reasoning\": \"Detailed security justification based on the description and evidence explaining why this is or is not a false positive.\",\n"
            "    \"solution\": \"Specific remediation steps.\",\n"
            "    \"is_duplicate\": true/false,\n"
            "    \"duplicate_of_id\": \"<parent_id_if_duplicate_else_null>\"\n"
            "  }\n"
            "]"
        )

    @staticmethod
    def parse_validation_response(text):
        if not text:
            return []
        # Strip any markdown code fences the model may have wrapped the JSON in.
        text = re.sub(r"^```(?:json)?\s*", "", text.strip())
        text = re.sub(r"\s*```$", "", text).strip()

        try:
            data = json.loads(text)
            return data if isinstance(data, list) else []
        except Exception:
            pass

        # Fallback: isolate the JSON array (models sometimes wrap it in prose) and,
        # if it still won't parse, repair the single most common LLM mistake — stray
        # backslashes inside evidence/HTTP strings that aren't valid JSON escapes
        # (this is the "Invalid \escape" failure that otherwise drops ALL AI results).
        start, end = text.find("["), text.rfind("]")
        if start != -1 and end > start:
            candidate = text[start:end + 1]
            for attempt in (candidate, re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', candidate)):
                try:
                    data = json.loads(attempt)
                    return data if isinstance(data, list) else []
                except Exception:
                    continue

        logger.error("[Validation Agent] Failed to parse validation response (no recoverable JSON array).")
        return []

    def run(self):
        logger.info("[Validation Agent] Reviewing High and Critical findings...")
        high_crit = self.filter_high_critical()
        
        crit_count = sum(1 for f in high_crit if f.get('risk', '').lower() == 'critical')
        high_count = sum(1 for f in high_crit if f.get('risk', '').lower() == 'high')
        logger.info(
            f"[Validation Agent] Initiating review for {crit_count} Critical and {high_count} High findings "
            f"({len(high_crit)} High/Critical out of {len(self.raw_findings)} total findings)."
        )

        if not high_crit:
            logger.info("[Validation Agent] No High/Critical findings to validate.")
            return []

        if not self.api_key:
            logger.info("[Validation Agent] No Gemini API key detected. Skipping AI validation.")
            return []

        return self._validate_with_llm(high_crit)

    def _validate_with_llm(self, findings):
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
                    logger.error(f"[Validation Agent] Gemini API returned no candidates: {res_data}")
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
    def __init__(self, target_url, scan_config, raw_findings, validated_findings, scan_id=None):
        self.target_url = target_url
        self.scan_config = scan_config
        self.raw_findings = raw_findings
        self.validated_findings = validated_findings
        self.scan_id = scan_id or scan_config.get("scan_id") or "latest"

    def get_vuln_references(self, alert_title, cwe_id=None):
        """
        Maps a finding to its standardized CWE and OWASP Top 10 (2021) category.

        These are legitimately derivable from the vulnerability class. CVE is left
        as 'N/A' for category-level DAST findings: a CVE identifies a specific
        product vulnerability, which a generic class of finding does not have, so
        emitting one would be fabricated. A real CVE is only surfaced when the
        underlying ZAP alert explicitly references one (see _cve_from_alert).
        """
        alert_lower = str(alert_title).lower()
        cwe_num = str(cwe_id) if cwe_id else ""

        cwe_val = f"CWE-{cwe_num}" if cwe_num else "CWE-200"
        owasp_val = "A05:2021-Security Misconfiguration"
        cve_val = "N/A"

        if "sql" in alert_lower or cwe_num == "89":
            cwe_val = "CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)"
            owasp_val = "A03:2021-Injection"
        elif "xss" in alert_lower or "cross-site scripting" in alert_lower or cwe_num == "79":
            cwe_val = "CWE-79 (Improper Neutralization of Input During Web Page Generation)"
            owasp_val = "A03:2021-Injection"
        elif "csrf" in alert_lower or "cross-site request forgery" in alert_lower or cwe_num == "352":
            cwe_val = "CWE-352 (Cross-Site Request Forgery)"
            owasp_val = "A01:2021-Broken Access Control"
        elif "csp" in alert_lower or "content security policy" in alert_lower:
            cwe_val = "CWE-693 (Protection Mechanism Failure)"
            owasp_val = "A05:2021-Security Misconfiguration"
        elif "frame-options" in alert_lower or "clickjacking" in alert_lower:
            cwe_val = "CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)"
            owasp_val = "A05:2021-Security Misconfiguration"
        elif "hsts" in alert_lower or "strict-transport-security" in alert_lower:
            cwe_val = "CWE-523 (Unprotected Transport of Credentials)"
            owasp_val = "A05:2021-Security Misconfiguration"
        elif "content-type" in alert_lower or "mime-sniffing" in alert_lower:
            cwe_val = "CWE-116 (Improper Encoding or Escaping of Output)"
            owasp_val = "A05:2021-Security Misconfiguration"
        elif "server" in alert_lower or "information disclosure" in alert_lower or cwe_num == "200":
            cwe_val = "CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"
            owasp_val = "A01:2021-Broken Access Control"
        elif "directory" in alert_lower or "directory browsing" in alert_lower or cwe_num == "548":
            cwe_val = "CWE-548 (Exposure of Information Through Directory Listing)"
            owasp_val = "A01:2021-Broken Access Control"
        elif "rce" in alert_lower or "code execution" in alert_lower or cwe_num == "94":
            cwe_val = "CWE-94 (Improper Control of Generation of Code)"
            owasp_val = "A03:2021-Injection"

        return cwe_val, owasp_val, cve_val

    @staticmethod
    def _cve_from_alert(rf):
        """
        Extract a genuine CVE id from a ZAP alert's reference/other fields if it
        cites one (some active-scan rules do). Returns 'N/A' when none is present —
        never a fabricated identifier.
        """
        haystack = " ".join(str(rf.get(k, "")) for k in ("reference", "other", "alert", "description"))
        m = re.search(r"CVE-\d{4}-\d{4,7}", haystack, re.I)
        return m.group(0).upper() if m else "N/A"

    def run(self):
        logger.info("[Report Agent] Generating reports...")
        
        # Create map of validated findings by ID
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

        seen_alerts = {}
        for rf in self.raw_findings:
            severity = str(rf.get("risk", "")).lower()
            finding_id = rf.get("id")
            alert_title = rf.get("alert", "Vulnerability")
            
            # 1. Map CWE and OWASP Top 10 categories; surface a real CVE only if the
            #    ZAP alert actually references one (never a fabricated placeholder).
            cwe_full, owasp_full, cve_full = self.get_vuln_references(alert_title, rf.get("cweid"))
            real_cve = self._cve_from_alert(rf)
            rf["cwe_full"] = cwe_full
            rf["owasp_full"] = owasp_full
            rf["cve_full"] = real_cve if real_cve != "N/A" else cve_full
            
            # Deduplication: group URLs of duplicate findings under the parent
            if alert_title not in seen_alerts:
                seen_alerts[alert_title] = finding_id
                rf["is_duplicate"] = False
                rf["duplicate_of_id"] = None
                rf["affected_urls"] = [rf.get("url")]
                
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
                    # No AI data or AI not run
                    rf["is_false_positive"] = False
                    if severity == "critical":
                        stats["critical"] += 1
                        stats["critical_validated"] += 1
                    elif severity == "high":
                        stats["high"] += 1
                        stats["high_validated"] += 1
                    elif severity == "medium":
                        stats["medium"] += 1
                    elif severity == "low":
                        stats["low"] += 1
                    else:
                        stats["informational"] += 1
            else:
                rf["is_duplicate"] = True
                rf["duplicate_of_id"] = seen_alerts[alert_title]
                
                # Append this finding's URL to the parent's affected_urls list
                parent_id = seen_alerts[alert_title]
                for p in enriched_findings:
                    if p["id"] == parent_id:
                        if rf.get("url") not in p["affected_urls"]:
                            p["affected_urls"].append(rf.get("url"))
                        break
                
                # Populate local copy AI details to stay consistent
                if finding_id in val_map:
                    v_data = val_map[finding_id]
                    rf["is_false_positive"] = v_data["is_false_positive"]
                    rf["ai_confidence"] = v_data["confidence"]
                    rf["ai_reasoning"] = v_data["reasoning"]
                    rf["solution"] = v_data["solution"]
                else:
                    rf["is_false_positive"] = False

            enriched_findings.append(rf)

        # Risk Score (0-100), ANCHORED to the worst active severity present, plus a
        # small bounded bonus for volume. False positives and duplicates are excluded.
        # Anchoring (instead of a naive additive sum) is what prevents a handful of
        # Medium/High alerts from trivially saturating the score to 100/CRITICAL —
        # a real DAST run of only High findings should read HIGH, not CRITICAL/100.
        active_findings = [
            f for f in enriched_findings
            if not f.get("is_false_positive", False) and not f.get("is_duplicate", False)
        ]
        n_crit = sum(1 for f in active_findings if str(f.get("risk", "")).lower() == "critical")
        n_high = sum(1 for f in active_findings if str(f.get("risk", "")).lower() == "high")
        n_med  = sum(1 for f in active_findings if str(f.get("risk", "")).lower() == "medium")
        n_low  = sum(1 for f in active_findings if str(f.get("risk", "")).lower() == "low")

        if n_crit:
            base, risk_desc = 85, "CRITICAL RISK PROFILE"
        elif n_high:
            base, risk_desc = 62, "HIGH RISK PROFILE"
        elif n_med:
            base, risk_desc = 35, "MEDIUM RISK PROFILE"
        elif n_low:
            base, risk_desc = 12, "LOW RISK PROFILE"
        else:
            base, risk_desc = 0, "MINIMAL RISK PROFILE"

        # Volume bonus is capped at 14 so counts nudge the score within a band but
        # never jump it into a higher-severity band on their own.
        bonus = min(n_crit * 5 + n_high * 3 + n_med * 1 + n_low * 0.5, 14)
        risk_score = int(min(base + bonus, 100))

        # Generate Summary text dynamically from counts
        findings_summary = []
        if stats["critical_validated"] > 0:
            findings_summary.append(f"{stats['critical_validated']} Critical")
        if stats["high_validated"] > 0:
            findings_summary.append(f"{stats['high_validated']} High")
        if stats["medium"] > 0:
            findings_summary.append(f"{stats['medium']} Medium")
        if stats["low"] > 0:
            findings_summary.append(f"{stats['low']} Low")
        
        if findings_summary:
            findings_str = ", ".join(findings_summary[:-1]) + (" and " + findings_summary[-1] if len(findings_summary) > 1 else findings_summary[0])
            summary_text = (
                f"The security assessment of {self.target_url} has revealed a {risk_desc} with a risk score of {risk_score}/100. "
                f"A total of {findings_str} vulnerabilities have been identified as active."
            )
        else:
            summary_text = (
                f"The security assessment of {self.target_url} has revealed a {risk_desc} with a risk score of {risk_score}/100. "
                "No active vulnerabilities were identified."
            )

        # Generate Business Impact dynamically from vulnerability types
        impact_reasons = []
        for f in enriched_findings:
            if f.get("is_false_positive") or f.get("is_duplicate"):
                continue
            alert = str(f.get("alert", "")).lower()
            if "sql" in alert:
                impact_reasons.append("unauthorized database access or data exfiltration via SQL injection")
            elif "xss" in alert or "cross-site scripting" in alert:
                impact_reasons.append("session hijacking or credential theft of application users via cross-site scripting")
            elif "csrf" in alert or "cross-site request forgery" in alert:
                impact_reasons.append("unauthorized actions performed on behalf of authenticated users")
            elif "header" in alert or "csp" in alert or "policy" in alert:
                impact_reasons.append("vulnerability to client-side injection attacks due to missing security headers")
            elif "version" in alert or "leak" in alert or "disclosure" in alert:
                impact_reasons.append("facilitation of targeted attacks through server information leakage")

        if impact_reasons:
            unique_reasons = list(set(impact_reasons))
            impact_str = ", ".join(unique_reasons[:-1]) + (" and " + unique_reasons[-1] if len(unique_reasons) > 1 else unique_reasons[0])
            business_impact = (
                f"The identified vulnerabilities present risk to business operations, including potential {impact_str}. "
                "Failure to address these issues could lead to compromised user sessions or technical compliance failures."
            )
        else:
            business_impact = (
                "The business impact is low. No active, high-priority vulnerabilities were found, meaning "
                "the application conforms to standard safety baselines."
            )

        # Generate Strategic Recommendations dynamically from vulnerability types
        recs = []
        alert_titles = [str(f.get("alert", "")).lower() for f in enriched_findings if not f.get("is_false_positive") and not f.get("is_duplicate")]
        
        has_sqli = any("sql" in title for title in alert_titles)
        has_xss = any("xss" in title or "cross-site scripting" in title for title in alert_titles)
        has_csrf = any("csrf" in title or "cross-site request forgery" in title for title in alert_titles)
        has_headers = any("header" in title or "csp" in title or "clickjacking" in title or "policy" in title for title in alert_titles)
        has_disclosure = any("version" in title or "leak" in title or "disclosure" in title for title in alert_titles)
        has_directory = any("directory" in title or "browsing" in title for title in alert_titles)
        
        if has_sqli:
            recs.append("Implement parameterized SQL queries immediately on all database query points.")
        if has_xss:
            recs.append("Deploy robust HTML entity encoding and context-aware escaping on all user-supplied input render points.")
        if has_csrf:
            recs.append("Implement anti-CSRF token validation frameworks for all state-changing actions.")
        if has_headers:
            recs.append("Configure missing HTTP response security headers (CSP, X-Frame-Options, X-Content-Type-Options) to secure client-side interactions.")
        if has_disclosure:
            recs.append("Configure the web server to suppress product/version details in HTTP response headers (e.g. Server, X-Powered-By).")
        if has_directory:
            recs.append("Disable directory listing and file indexing on the web server directory structure.")
            
        if not recs:
            recs = [
                "Maintain periodic vulnerability scans and keep package dependencies up to date.",
                "Ensure SSL/TLS configuration follows modern cipher suites and security standards."
            ]

        report_data = {
            "target_url": self.target_url,
            "scan_id": self.scan_id,
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

        # Log final summary stats explicitly
        logger.info(
            f"[Report Agent] Finalizing report databases. Summary counts: "
            f"Critical: {stats['critical']} (validated: {stats['critical_validated']}), "
            f"High: {stats['high']} (validated: {stats['high_validated']}), "
            f"Medium: {stats['medium']}, Low: {stats['low']}, Info: {stats['informational']}."
        )

        with open(f"executive_report_{self.scan_id}.json", "w") as f:
            json.dump(report_data, f, indent=4)
        
        with open(f"technical_va_report_{self.scan_id}.json", "w") as f:
            json.dump(report_data, f, indent=4)

        logger.info(f"[Report Agent] Generated JSON report databases: executive_report_{self.scan_id}.json and technical_va_report_{self.scan_id}.json")
        return report_data


class PDFReportGenerator:
    def __init__(self, report_data):
        self.report_data = report_data

    def run(self):
        scan_id = self.report_data.get("scan_id", "latest")
        logger.info(f"[PDF Generator] Compiling PDF reports for scan {scan_id}...")
        exec_path = f"Executive_Report_{scan_id}.pdf"
        tech_path = f"Technical_VA_Report_{scan_id}.pdf"
        
        generate_pdf_report(self.report_data, exec_path, is_executive=True)
        generate_pdf_report(self.report_data, tech_path, is_executive=False)
        
        logger.info(f"[PDF Generator] PDFs compiled successfully:\n - {exec_path}\n - {tech_path}")
        return exec_path, tech_path
