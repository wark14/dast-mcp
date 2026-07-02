import urllib.parse
import requests
from bs4 import BeautifulSoup
import re
import uuid
import time
import json
import logging
import os
import subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ScanEngine")

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

class DASTScanEngine:
    # Shared handle to an auto-started ZAP daemon so it is launched once per process
    # and reused across scans.
    _zap_process = None

    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urllib.parse.urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AI-DAST-Agent/1.0"
        })
        self.crawled_urls = set()
        self.forms_found = []
        self.frameworks_detected = []
        self.headers_analyzed = {}
        self.scan_id = str(uuid.uuid4())
        
        # Configure ZAP API connection parameters
        self.zap_url = os.environ.get("ZAP_API_URL", "http://localhost:8080").rstrip('/')
        self.zap_api_key = os.environ.get("ZAP_API_KEY", "")
        self.parsed_zap = urllib.parse.urlparse(self.zap_url)

    def crawl_site(self, max_pages=15):
        """
        Crawls the target site starting from the target_url, up to max_pages.
        Identifies forms, links, and parameters.
        """
        to_crawl = [self.target_url]
        self.crawled_urls.add(self.target_url)

        logger.info(f"Starting crawl of {self.target_url}")
        
        while to_crawl and len(self.crawled_urls) < max_pages:
            current_url = to_crawl.pop(0)
            try:
                response = self.session.get(current_url, timeout=5, allow_redirects=True)
                if response.status_code != 200:
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                for form in soup.find_all('form'):
                    form_info = self._parse_form(current_url, form)
                    if form_info not in self.forms_found:
                        self.forms_found.append(form_info)
                
                # Extract links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urllib.parse.urljoin(current_url, href)
                    full_url = urllib.parse.urldefrag(full_url)[0]
                    
                    parsed_full = urllib.parse.urlparse(full_url)
                    if parsed_full.netloc == self.parsed_url.netloc:
                        if full_url not in self.crawled_urls and len(self.crawled_urls) < max_pages:
                            self.crawled_urls.add(full_url)
                            to_crawl.append(full_url)
                            
            except Exception as e:
                logger.error(f"Error crawling {current_url}: {e}")
        
        return list(self.crawled_urls)

    def _parse_form(self, page_url, form_elem):
        """Helper to extract details from an HTML form element."""
        action = form_elem.get('action', '')
        method = form_elem.get('method', 'get').lower()
        inputs = []
        for inp in form_elem.find_all(['input', 'textarea', 'select']):
            inp_name = inp.get('name')
            if inp_name:
                inputs.append({
                    'name': inp_name,
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', '')
                })
        
        action_url = urllib.parse.urljoin(page_url, action)
        return {
            'page_url': page_url,
            'action_url': action_url,
            'method': method,
            'inputs': inputs
        }

    def detect_framework(self):
        """
        Analyzes the homepage and headers to identify the framework, CMS,
        web server, cookies, and other characteristics.
        """
        try:
            response = self.session.get(self.target_url, timeout=5)
            self.headers_analyzed = dict(response.headers)
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
        except Exception as e:
            logger.error(f"Failed to fetch homepage for framework detection: {e}")
            return ["Unknown"]

        detected = []
        
        server_header = self.headers_analyzed.get('Server', '')
        if server_header:
            detected.append(f"Web Server: {server_header}")
        
        powered_by = self.headers_analyzed.get('X-Powered-By', '')
        if powered_by:
            detected.append(f"Backend: {powered_by}")

        cookies = response.cookies
        for cookie in cookies:
            if cookie.name.lower() in ['phpsessid', 'laravel_session']:
                detected.append("PHP Framework (Laravel or native)")
            elif cookie.name.lower() == 'jsessionid':
                detected.append("Java Servlet / Spring")
            elif cookie.name.lower() in ['csrftoken', 'django']:
                detected.append("Python Framework (Django)")

        if re.search(r'react|_reactRoot|data-reactroot', html, re.I) or soup.find(id='react-root'):
            detected.append("Frontend: React")
        
        if soup.find('script', id='__NEXT_DATA__') or re.search(r'_next/static', html):
            detected.append("Frontend: Next.js")

        if re.search(r'ng-version|ng-app|ng-controller', html, re.I):
            detected.append("Frontend: Angular")

        if re.search(r'vue|data-v-', html, re.I):
            detected.append("Frontend: Vue.js")

        if re.search(r'wp-content|wp-includes', html):
            detected.append("CMS: WordPress")
            
        if re.search(r'bootstrap(\.min)?\.css', html) or re.search(r'bootstrap(\.min)?\.js', html):
            detected.append("CSS Framework: Bootstrap")

        if re.search(r'jquery(\.min)?\.js', html):
            detected.append("JS Library: jQuery")

        if not detected:
            detected.append("Generic Web Application")

        self.frameworks_detected = list(set(detected))
        return self.frameworks_detected

    def _zap_version(self):
        """Returns the ZAP version string if the API is reachable, else None."""
        try:
            r = requests.get(
                f"{self.zap_url}/JSON/core/view/version/",
                params={"apikey": self.zap_api_key}, timeout=3
            )
            if r.status_code == 200:
                return r.json().get("version")
        except Exception:
            return None
        return None

    def ensure_zap_running(self, startup_timeout=120):
        """
        Guarantees a reachable OWASP ZAP daemon before scanning. If one is already
        up at ZAP_API_URL it is reused. Otherwise, when the target is a local ZAP
        and the bundled install (./zap) exists, it is auto-started as a daemon.

        Raises RuntimeError (no fallback / no fake findings) if ZAP cannot be made
        available — scanning without a real scanner is never simulated.
        """
        version = self._zap_version()
        if version:
            logger.info(f"OWASP ZAP is reachable (version {version}).")
            return

        host = self.parsed_zap.hostname or "localhost"
        if host not in ("localhost", "127.0.0.1"):
            raise RuntimeError(
                f"OWASP ZAP is required but not reachable at {self.zap_url}. "
                f"That address is not a local instance this tool can start automatically — "
                f"start ZAP there and retry."
            )

        zap_sh = os.path.join(PROJECT_DIR, "zap", "zap.sh")
        jre_bin = os.path.join(PROJECT_DIR, "zap", "jre", "bin")
        if not os.path.exists(zap_sh):
            raise RuntimeError(
                "OWASP ZAP is required but is not installed. Run './setup_zap.sh' to install a "
                "self-contained ZAP (with a bundled Java runtime) into ./zap/, then retry the scan."
            )

        port = self.parsed_zap.port or 8080
        logger.info("Starting bundled OWASP ZAP daemon (first startup can take ~30-60s)...")

        # Use the bundled JRE so no system Java is required.
        env = os.environ.copy()
        jre_home = os.path.join(PROJECT_DIR, "zap", "jre")
        if os.path.isdir(jre_home):
            env["JAVA_HOME"] = jre_home
            env["PATH"] = jre_bin + os.pathsep + env.get("PATH", "")

        log_path = os.path.join(PROJECT_DIR, "zap_daemon.log")
        with open(log_path, "ab") as logf:
            DASTScanEngine._zap_process = subprocess.Popen(
                [
                    zap_sh, "-daemon",
                    "-host", "127.0.0.1", "-port", str(port),
                    "-config", "api.disablekey=true",
                    "-config", "api.addrs.addr.name=.*",
                    "-config", "api.addrs.addr.regex=true",
                ],
                stdout=logf, stderr=logf, cwd=os.path.join(PROJECT_DIR, "zap"), env=env
            )

        deadline = time.time() + startup_timeout
        while time.time() < deadline:
            version = self._zap_version()
            if version:
                logger.info(f"OWASP ZAP daemon is up (version {version}).")
                return
            if DASTScanEngine._zap_process.poll() is not None:
                raise RuntimeError(
                    f"The ZAP daemon exited during startup. See {log_path} for details."
                )
            time.sleep(3)

        raise RuntimeError(
            f"OWASP ZAP daemon did not become ready within {startup_timeout}s. See {log_path}."
        )

    def run_dast_scan(self, use_ajax_spider=False, active_scan=True):
        """
        Runs a real OWASP ZAP scan. Reconnaissance (framework detection + crawl) primes
        the engine, then a reachable ZAP daemon is ensured (auto-started from ./zap if
        needed) and the ZAP spider (+ optional active scanner) are executed. There is no
        simulated fallback: if ZAP is unavailable this raises rather than fabricating findings.

        Args:
            use_ajax_spider: Force the AJAX spider (auto-selected for SPAs otherwise).
            active_scan: When True, run ZAP's active scanner, which sends intrusive attack
                payloads (SQLi, XSS, etc.). When False, only the spider + passive analysis
                run — safe, non-intrusive, but limited to what passive rules can detect.
        """
        logger.info("Initializing DAST scan engine...")
        self.detect_framework()
        self.crawl_site()
        self.ensure_zap_running()
        return self._run_real_zap_scan(use_ajax_spider, active_scan=active_scan)

    def _run_real_zap_scan(self, use_ajax_spider, active_scan=True):
        """Orchestrates actual OWASP ZAP spidering and vulnerability alert fetching."""
        apikey_param = {"apikey": self.zap_api_key}
        
        # 1. Select Spider based on framework
        is_spa = any(x in self.frameworks_detected for x in ["Frontend: React", "Frontend: Next.js", "Frontend: Angular", "Frontend: Vue.js"])
        
        if is_spa or use_ajax_spider:
            logger.info("[ZAP Scan] SPA detected. Launching ZAP AJAX Spider...")
            start_url = f"{self.zap_url}/JSON/ajaxSpider/action/scan/"
            params = {"url": self.target_url, "inScope": "true", **apikey_param}
            requests.get(start_url, params=params)
            
            # Poll AJAX Spider
            status_url = f"{self.zap_url}/JSON/ajaxSpider/view/status/"
            while True:
                status_res = requests.get(status_url, params=apikey_param).json()
                status = status_res.get("status")
                logger.info(f"[ZAP Scan] AJAX Spider Status: {status}")
                if status == "stopped":
                    break
                time.sleep(3)
        else:
            logger.info("[ZAP Scan] Standard application detected. Launching ZAP Standard Spider...")
            start_url = f"{self.zap_url}/JSON/spider/action/scan/"
            params = {"url": self.target_url, "maxChildren": 10, **apikey_param}
            scan_res = requests.get(start_url, params=params).json()
            scan_id = scan_res.get("scan")
            
            # Poll Standard Spider
            status_url = f"{self.zap_url}/JSON/spider/view/status/"
            while True:
                status_res = requests.get(status_url, params={"scanId": scan_id, **apikey_param}).json()
                status = status_res.get("status")
                logger.info(f"[ZAP Scan] ZAP Standard Spider Progress: {status}%")
                if int(status) >= 100:
                    break
                time.sleep(2)

        # 2. Start ZAP Active Scan (optional — intrusive attack payloads)
        if active_scan:
            logger.info("[ZAP Scan] Triggering ZAP Active Scanner...")
            ascan_url = f"{self.zap_url}/JSON/ascan/action/scan/"
            params = {"url": self.target_url, "recurse": "true", **apikey_param}
            ascan_res = requests.get(ascan_url, params=params).json()
            ascan_id = ascan_res.get("scan")

            # Poll Active Scanner
            ascan_status_url = f"{self.zap_url}/JSON/ascan/view/status/"
            while True:
                status_res = requests.get(ascan_status_url, params={"scanId": ascan_id, **apikey_param}).json()
                status = status_res.get("status")
                logger.info(f"[ZAP Scan] Active Scanner Progress: {status}%")
                if int(status) >= 100:
                    break
                time.sleep(3)
        else:
            logger.info("[ZAP Scan] Active scanning DISABLED — running passive analysis only (no attack payloads).")

        # 2b. Let the passive scanner drain so passive alerts are complete before we pull them.
        try:
            pscan_url = f"{self.zap_url}/JSON/pscan/view/recordsToScan/"
            deadline = time.time() + 60
            while time.time() < deadline:
                records = requests.get(pscan_url, params=apikey_param).json().get("recordsToScan")
                if records is None or int(records) == 0:
                    break
                logger.info(f"[ZAP Scan] Passive scanner draining: {records} records remaining...")
                time.sleep(2)
        except Exception:
            pass

        # 3. Pull ZAP Alerts
        logger.info("[ZAP Scan] Extracting alerts from ZAP Core...")
        alerts_url = f"{self.zap_url}/JSON/core/view/alerts/"
        params = {"baseurl": self.target_url, **apikey_param}
        alerts = requests.get(alerts_url, params=params).json().get("alerts", [])
        
        findings = []
        for alert in alerts:
            # Query message details (req/res headers and body)
            msg_id = alert.get("messageId")
            req_header, req_body, res_header, res_body = "", "", "", ""
            if msg_id:
                try:
                    msg_url = f"{self.zap_url}/JSON/core/view/message/"
                    msg_res = requests.get(msg_url, params={"id": msg_id, **apikey_param}).json().get("message", {})
                    req_header = msg_res.get("requestHeader", "")
                    req_body = msg_res.get("requestBody", "")
                    res_header = msg_res.get("responseHeader", "")
                    res_body = msg_res.get("responseBody", "")[:4000] # Cap size
                except Exception:
                    pass

            findings.append({
                "id": str(uuid.uuid4()),
                "alert": alert.get("alert", "Vulnerability"),
                "risk": alert.get("risk", "Low"),
                "confidence": alert.get("confidence", "Medium"),
                "url": alert.get("url", ""),
                "parameter": alert.get("param", ""),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "evidence": alert.get("evidence", ""),
                "wascid": alert.get("wascId", ""),
                "cweid": alert.get("cweId", ""),
                "request_header": req_header,
                "request_body": req_body,
                "response_header": res_header,
                "response_body": res_body,
                "other": alert.get("other", "")
            })

        scan_results = {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "frameworks": self.frameworks_detected,
            "pages_crawled_count": len(self.crawled_urls),
            "pages_crawled": list(self.crawled_urls),
            "forms_found_count": len(self.forms_found),
            "active_scan": active_scan,
            "findings": findings
        }

        with open(f"scan_results_{self.scan_id}.json", "w") as f:
            json.dump(scan_results, f, indent=4)
            
        return scan_results

