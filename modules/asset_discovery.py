"""
Asset Discovery & Reconnaissance Module
Fitur untuk menemukan aset digital: subdomain, teknologi, port terbuka, dan cloud assets.
"""

import socket
import dns.resolver
import requests
from typing import List, Dict, Set
from urllib.parse import urlparse
import re
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

class AssetDiscovery:
    def __init__(self):
        self.common_subdomains = [
            "www", "mail", "ftp", "admin", "test", "dev", "staging", "api", 
            "blog", "shop", "portal", "app", "cdn", "static", "m", "mobile",
            "support", "help", "docs", "status", "monitoring", "vpn", "remote"
        ]
        
    def resolve_domain(self, domain: str) -> Dict:
        """Resolve domain to IP addresses"""
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            return {"domain": domain, "ips": ips, "status": "active"}
        except socket.gaierror:
            return {"domain": domain, "ips": [], "status": "inactive"}
            
    def enumerate_subdomains(self, base_domain: str) -> List[Dict]:
        """Find active subdomains using brute-force"""
        results = []
        for sub in self.common_subdomains:
            candidate = f"{sub}.{base_domain}"
            result = self.resolve_domain(candidate)
            if result["status"] == "active":
                results.append(result)
        return results
        
    def fingerprint_technology(self, url: str) -> Dict:
        """Detect technologies used (CMS, Frameworks, Servers)"""
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; TechScanner/1.0)"
        }
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            tech_stack = []
            
            # Check Headers
            server = resp.headers.get("Server", "")
            if "nginx" in server.lower(): tech_stack.append("Web Server: Nginx")
            if "apache" in server.lower(): tech_stack.append("Web Server: Apache")
            if "cloudflare" in server.lower(): tech_stack.append("CDN: Cloudflare")
            
            powered_by = resp.headers.get("X-Powered-By", "")
            if "php" in powered_by.lower(): tech_stack.append("Language: PHP")
            if "express" in powered_by.lower(): tech_stack.append("Framework: Express.js")
            
            # Check HTML Content
            content = resp.text.lower()
            if "wordpress" in content: tech_stack.append("CMS: WordPress")
            if "react" in content: tech_stack.append("Framework: React")
            if "vue" in content: tech_stack.append("Framework: Vue.js")
            if "angular" in content: tech_stack.append("Framework: Angular")
            if "jquery" in content: tech_stack.append("Library: jQuery")
            
            # Check Cookies
            cookies = "; ".join(resp.cookies.keys())
            if "PHPSESSID" in cookies: tech_stack.append("Session: PHP")
            if "csrftoken" in cookies: tech_stack.append("Framework: Django")
            
            return {"url": url, "technologies": tech_stack, "headers": dict(resp.headers)}
            
        except Exception as e:
            return {"url": url, "error": str(e), "technologies": []}

    def scan_port(self, host: str, port: int) -> Dict:
        """Check if a specific port is open"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                service = self._guess_service(port)
                return {"port": port, "status": "open", "service": service}
            return {"port": port, "status": "closed"}
        except:
            return {"port": port, "status": "filtered"}
            
    def _guess_service(self, port: int) -> str:
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
            53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
            5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
            8080: "HTTP-Proxy", 9200: "Elasticsearch"
        }
        return services.get(port, "Unknown")

    def quick_port_scan(self, host: str, ports: List[int] = None) -> List[Dict]:
        """Scan common ports on a host"""
        if not ports:
            ports = [21, 22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017]
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.scan_port, host, p): p for p in ports}
            for future in futures:
                result = future.result()
                if result["status"] == "open":
                    open_ports.append(result)
        return open_ports

    async def check_cloud_buckets(self, domain: str) -> List[Dict]:
        """Check for exposed cloud storage buckets based on domain name"""
        findings = []
        bucket_names = [
            domain.replace(".", "-"),
            domain.replace(".", ""),
            f"{domain}-assets",
            f"{domain}-public"
        ]
        
        cloud_providers = {
            "AWS S3": "https://{}.s3.amazonaws.com",
            "DigitalOcean": "https://{}.nyc3.digitaloceanspaces.com",
            "Google Cloud": "https://storage.googleapis.com/{}"
        }
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for name in bucket_names:
                for provider, template in cloud_providers.items():
                    url = template.format(name)
                    tasks.append(self._check_bucket_url(session, url, provider, name))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r and isinstance(r, dict):
                    findings.append(r)
                    
        return findings
        
    async def _check_bucket_url(self, session: aiohttp.ClientSession, url: str, provider: str, name: str) -> Dict:
        try:
            async with session.get(url, timeout=5) as resp:
                if resp.status == 200:
                    content_type = resp.headers.get("Content-Type", "")
                    if "xml" in content_type or "listbucketresult" in (await resp.text()).lower():
                        return {
                            "type": "OPEN_CLOUD_BUCKET",
                            "provider": provider,
                            "url": url,
                            "name": name,
                            "severity": "CRITICAL",
                            "remediation": "Set bucket to private or configure proper CORS/Auth."
                        }
        except:
            pass
        return None

    def full_recon(self, domain: str) -> Dict:
        """Run complete reconnaissance"""
        print(f"[*] Starting Reconnaissance on {domain}...")
        
        # 1. Subdomain Enumeration
        print("[*] Enumerating subdomains...")
        subdomains = self.enumerate_subdomains(domain)
        
        # 2. Technology Fingerprinting
        tech_results = []
        urls_to_scan = [f"https://{domain}", f"http://{domain}"]
        for sub in subdomains[:5]: # Limit to top 5
            urls_to_scan.append(f"https://{sub['domain']}")
            
        print("[*] Fingerprinting technologies...")
        for url in urls_to_scan:
            tech = self.fingerprint_technology(url)
            if "technologies" in tech and tech["technologies"]:
                tech_results.append(tech)
                
        # 3. Port Scanning (Main Domain Only)
        print("[*] Scanning ports...")
        main_ip = self.resolve_domain(domain)
        open_ports = []
        if main_ip["ips"]:
            open_ports = self.quick_port_scan(main_ip["ips"][0])
            
        return {
            "domain": domain,
            "subdomains": subdomains,
            "technologies": tech_results,
            "open_ports": open_ports,
            "summary": {
                "total_subdomains": len(subdomains),
                "total_open_ports": len(open_ports),
                "technologies_found": sum(len(t.get("technologies", [])) for t in tech_results)
            }
        }

# Wrapper Function
def discover_assets(domain: str) -> Dict:
    scanner = AssetDiscovery()
    return scanner.full_recon(domain)

if __name__ == "__main__":
    # Example usage
    target = "example.com"
    # result = discover_assets(target)
    # print(result)
