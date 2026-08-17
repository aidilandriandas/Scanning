"""
Dynamic Web Scanner Module
Menggunakan Headless Browser (Playwright) untuk analisis JavaScript-heavy apps,
deteksi XSS dinamis, DOM-based vulnerabilities, dan client-side logic.
"""

import asyncio
from playwright.async_api import async_playwright
from typing import List, Dict, Any
from urllib.parse import urlparse
import re

class DynamicWebScanner:
    def __init__(self, headless: bool = True):
        self.headless = headless
        self.browser = None
        self.context = None
        self.page = None
        
    async def start(self):
        """Initialize browser context"""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=self.headless)
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            ignore_https_errors=True
        )
        self.page = await self.context.new_page()
        
    async def close(self):
        """Close browser resources"""
        if self.browser:
            await self.browser.close()
            
    async def crawl_js_routes(self, url: str) -> List[str]:
        """Discover client-side routes by monitoring navigation events"""
        discovered_routes = set()
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            page = await browser.new_page()
            
            # Monitor navigation events
            page.on("framenavigated", lambda frame: discovered_routes.add(frame.url))
            
            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
                
                # Click all links to trigger SPA routing
                links = await page.query_selector_all("a")
                for link in links[:50]:  # Limit to prevent hang
                    try:
                        await link.click(timeout=2000)
                        await page.wait_for_load_state("networkidle", timeout=5000)
                        discovered_routes.add(page.url)
                        await page.go_back()
                    except:
                        continue
                        
            except Exception as e:
                print(f"Crawl error: {e}")
            finally:
                await browser.close()
                
        return list(discovered_routes)

    async def detect_dom_xss(self, url: str, payload: str = "<img src=x onerror=alert(1)>") -> List[Dict]:
        """Detect DOM-based XSS by injecting payloads and monitoring execution"""
        findings = []
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            page = await browser.new_page()
            
            # Enable console monitoring
            console_messages = []
            page.on("console", lambda msg: console_messages.append(msg.text))
            page.on("pageerror", lambda err: console_messages.append(str(err)))
            
            try:
                # Inject payload into URL parameters and hash
                parsed = urlparse(url)
                test_urls = [
                    f"{url}#{payload}",
                    f"{url}?q={payload}",
                    f"{url}?search={payload}"
                ]
                
                for test_url in test_urls:
                    console_messages.clear()
                    try:
                        await page.goto(test_url, wait_until="domcontentloaded", timeout=10000)
                        await page.wait_for_timeout(2000) # Wait for JS execution
                        
                        if any("alert(1)" in msg or "Refused to execute" in msg for msg in console_messages):
                            findings.append({
                                "type": "DOM_XSS",
                                "url": test_url,
                                "severity": "HIGH",
                                "evidence": console_messages,
                                "remediation": "Sanitize user input before inserting into DOM. Use textContent instead of innerHTML."
                            })
                    except:
                        continue
                        
            except Exception as e:
                print(f"XSS Scan error: {e}")
            finally:
                await browser.close()
                
        return findings

    async def analyze_sensitive_data_exposure(self, url: str) -> List[Dict]:
        """Scan network traffic and local storage for sensitive data"""
        findings = []
        sensitive_patterns = {
            "API_KEY": r"api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]",
            "JWT": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            "PRIVATE_IP": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            "AWS_SECRET": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]"
        }
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            page = await browser.new_page()
            
            requests_log = []
            page.on("request", lambda req: requests_log.append({
                "url": req.url,
                "method": req.method,
                "headers": dict(req.headers),
                "post_data": req.post_data
            }))
            
            try:
                await page.goto(url, wait_until="networkidle", timeout=30000)
                
                # Check LocalStorage & SessionStorage
                local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
                session_storage = await page.evaluate("() => JSON.stringify(sessionStorage)")
                
                storage_data = {"localStorage": local_storage, "sessionStorage": session_storage}
                
                for source, data in storage_data.items():
                    for label, pattern in sensitive_patterns.items():
                        if re.search(pattern, data, re.IGNORECASE):
                            findings.append({
                                "type": "SENSITIVE_DATA_STORAGE",
                                "location": source,
                                "data_type": label,
                                "severity": "CRITICAL",
                                "remediation": f"Do not store {label} in browser storage. Use httpOnly cookies or secure backend sessions."
                            })
                
                # Check Network Requests
                for req in requests_log:
                    combined_text = f"{req['url']} {req.get('post_data', '')} {req['headers']}"
                    for label, pattern in sensitive_patterns.items():
                        if re.search(pattern, combined_text, re.IGNORECASE):
                            findings.append({
                                "type": "SENSITIVE_DATA_NETWORK",
                                "url": req['url'],
                                "data_type": label,
                                "severity": "HIGH",
                                "remediation": "Remove sensitive credentials from client-side code and network requests."
                            })
                            
            except Exception as e:
                print(f"Data Exposure Scan error: {e}")
            finally:
                await browser.close()
                
        return findings

    async def full_dynamic_scan(self, url: str) -> Dict[str, Any]:
        """Run complete dynamic analysis"""
        await self.start()
        results = {
            "target": url,
            "routes_discovered": [],
            "dom_xss": [],
            "data_exposure": [],
            "summary": {}
        }
        
        try:
            # 1. Crawl Routes
            results["routes_discovered"] = await self.crawl_js_routes(url)
            
            # 2. DOM XSS Scan
            results["dom_xss"] = await self.detect_dom_xss(url)
            
            # 3. Sensitive Data Scan
            results["data_exposure"] = await self.analyze_sensitive_data_exposure(url)
            
            total_vulns = len(results["dom_xss"]) + len(results["data_exposure"])
            results["summary"] = {
                "total_vulnerabilities": total_vulns,
                "critical": len([x for x in results["data_exposure"] if x.get("severity") == "CRITICAL"]),
                "high": len([x for x in results["dom_xss"] if x.get("severity") == "HIGH"]) + len([x for x in results["data_exposure"] if x.get("severity") == "HIGH"]),
                "status": "FAILED" if total_vulns > 0 else "PASSED"
            }
        finally:
            await self.close()
            
        return results

# Wrapper Function
async def scan_dynamic_web(url: str) -> Dict:
    scanner = DynamicWebScanner()
    return await scanner.full_dynamic_scan(url)

if __name__ == "__main__":
    # Example usage
    import asyncio
    target = "https://example.com"
    print(f"Starting Dynamic Scan on {target}...")
    # result = asyncio.run(scan_dynamic_web(target))
    # print(result)
