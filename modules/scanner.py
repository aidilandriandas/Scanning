"""
Advanced Vulnerability Scanner Module
Includes: SCA, AI Analysis, Subdomain Enumeration, Compliance Checks, Attack Path Visualization
"""

import requests
import re
import json
import socket
import dns.resolver
import certifi
import whois
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional
from datetime import datetime
import networkx as nx
from config import (
    SAFE_MODE_DEFAULT, RATE_LIMIT_DELAY, USER_AGENT, 
    AI_ENABLED, AI_API_KEY, AI_MODEL_NAME, AI_API_BASE_URL,
    COMPLIANCE_STANDARDS, SCAN_PROFILES
)

class VulnerabilityScanner:
    def __init__(self, target_url: str, mode: str = 'safe', enable_ai: bool = False, 
                 compliance_standard: str = 'OWASP_TOP_10', discover_subdomains: bool = False):
        self.target_url = target_url.rstrip('/')
        self.mode = mode
        self.enable_ai = enable_ai
        self.compliance_standard = compliance_standard
        self.discover_subdomains = discover_subdomains
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.vulnerabilities = []
        self.subdomains = []
        self.assets = {}
        self.attack_graph = nx.DiGraph()
        
        # Load scan profile
        profile = SCAN_PROFILES.get(mode, SCAN_PROFILES['safe'])
        self.active_tests = profile.get('active_tests', False)
        self.rate_limit = profile.get('rate_limit', 1.0)
        self.max_depth = profile.get('max_depth', 3)
        self.enable_browser = profile.get('enable_browser', False)
        
        # CVE Database (simplified for demo - in production use NVD API)
        self.cve_database = self._load_cve_database()
        
    def _load_cve_database(self) -> Dict:
        """Load simplified CVE database for SCA"""
        return {
            'requests': {'vulnerable_versions': ['<2.25.0'], 'cve': 'CVE-2023-32681', 'severity': 'MEDIUM'},
            'flask': {'vulnerable_versions': ['<2.0.0'], 'cve': 'CVE-2023-30861', 'severity': 'HIGH'},
            'django': {'vulnerable_versions': ['<3.2.20'], 'cve': 'CVE-2023-23969', 'severity': 'CRITICAL'},
            'lodash': {'vulnerable_versions': ['<4.17.21'], 'cve': 'CVE-2021-23337', 'severity': 'HIGH'},
            'express': {'vulnerable_versions': ['<4.17.3'], 'cve': 'CVE-2022-24999', 'severity': 'MEDIUM'}
        }
    
    def _calculate_cvss(self, vuln_type: str) -> float:
        """Calculate CVSS score based on vulnerability type"""
        cvss_scores = {
            'SQL Injection': 9.8,
            'XSS': 7.5,
            'Directory Traversal': 7.5,
            'Sensitive Data Exposure': 8.0,
            'Missing Security Headers': 5.0,
            'Outdated Dependency': 6.5,
            'Open Redirect': 5.5,
            'Data Leakage': 7.0,
            'Subdomain Takeover': 8.5
        }
        return cvss_scores.get(vuln_type, 5.0)
    
    def _get_severity(self, cvss: float) -> str:
        """Get severity level from CVSS score"""
        if cvss >= 9.0:
            return 'CRITICAL'
        elif cvss >= 7.0:
            return 'HIGH'
        elif cvss >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def enumerate_subdomains(self) -> List[str]:
        """Enumerate subdomains using multiple techniques"""
        domain = urlparse(self.target_url).netloc.split(':')[0]
        found_subdomains = set()
        
        # Technique 1: Certificate Transparency Logs (simplified)
        try:
            # In production, use crt.sh API
            found_subdomains.add(f"www.{domain}")
            found_subdomains.add(f"mail.{domain}")
            found_subdomains.add(f"api.{domain}")
        except Exception:
            pass
        
        # Technique 2: DNS Brute-force (common subdomains)
        common_subs = ['www', 'api', 'dev', 'staging', 'test', 'admin', 'blog', 'shop']
        for sub in common_subs:
            try:
                full_domain = f"{sub}.{domain}"
                socket.gethostbyname(full_domain)
                found_subdomains.add(full_domain)
            except socket.gaierror:
                continue
        
        # Technique 3: DNS Records lookup
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                found_subdomains.add(str(rdata))
        except Exception:
            pass
        
        self.subdomains = list(found_subdomains)
        return self.subdomains
    
    def analyze_dependencies_sca(self, content: str, url: str) -> List[Dict]:
        """Software Composition Analysis - Detect outdated dependencies"""
        vulnerabilities = []
        
        # Check for package.json
        if 'package.json' in url or 'node_modules' in url:
            try:
                data = json.loads(content)
                deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                for pkg, version in deps.items():
                    clean_version = version.replace('^', '').replace('~', '')
                    if pkg.lower() in self.cve_database:
                        cve_info = self.cve_database[pkg.lower()]
                        vulnerabilities.append({
                            'type': 'Outdated Dependency',
                            'url': url,
                            'parameter': pkg,
                            'details': f"Version {clean_version} may be vulnerable",
                            'cvss': self._calculate_cvss('Outdated Dependency'),
                            'severity': self._get_severity(8.0),
                            'cve': cve_info.get('cve'),
                            'compliance': ['PCI_DSS', 'OWASP_TOP_10']
                        })
            except Exception:
                pass
        
        # Check for requirements.txt
        if 'requirements.txt' in url:
            lines = content.split('\n')
            for line in lines:
                if '==' in line:
                    parts = line.strip().split('==')
                    if len(parts) == 2:
                        pkg, version = parts
                        if pkg.lower() in self.cve_database:
                            cve_info = self.cve_database[pkg.lower()]
                            vulnerabilities.append({
                                'type': 'Outdated Dependency',
                                'url': url,
                                'parameter': pkg,
                                'details': f"Version {version} may be vulnerable",
                                'cvss': self._calculate_cvss('Outdated Dependency'),
                                'severity': self._get_severity(7.5),
                                'cve': cve_info.get('cve'),
                                'compliance': ['PCI_DSS', 'OWASP_TOP_10']
                            })
        
        # Check HTML for framework versions
        if '.html' in url or url == self.target_url:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check for Laravel
            laravel_match = re.search(r'Laravel\s+v?(\d+\.\d+)', content)
            if laravel_match:
                version = laravel_match.group(1)
                if float(version) < 9.0:
                    vulnerabilities.append({
                        'type': 'Outdated Dependency',
                        'url': url,
                        'parameter': 'Laravel',
                        'details': f"Laravel {version} is outdated",
                        'cvss': self._calculate_cvss('Outdated Dependency'),
                        'severity': self._get_severity(7.0),
                        'compliance': ['OWASP_TOP_10']
                    })
        
        return vulnerabilities
    
    def detect_data_leakage(self, content: str, url: str) -> List[Dict]:
        """Detect sensitive data leakage"""
        vulnerabilities = []
        
        patterns = {
            'Email Addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'Phone Numbers': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'IP Addresses': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'API Keys (Generic)': r'(?i)(api[_-]?key|apikey)[\s]*[=:]\s*[\"\'\w-]{16,}',
            'Private Keys': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            'Password Fields': r'(?i)(password|passwd|pwd)[\s]*[=:]\s*[\"\'\w-]{4,}',
            'Credit Card Numbers': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
            'Indonesian NIK': r'\b\d{16}\b',
            'AWS Access Key': r'(?i)AKIA[0-9A-Z]{16}'
        }
        
        for data_type, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                # Limit to first 5 matches to avoid noise
                sample_matches = list(set(matches))[:5]
                vulnerabilities.append({
                    'type': 'Data Leakage',
                    'url': url,
                    'parameter': data_type,
                    'details': f"Found {len(matches)} potential {data_type}",
                    'evidence': sample_matches,
                    'cvss': self._calculate_cvss('Data Leakage'),
                    'severity': self._get_severity(8.0),
                    'compliance': ['GDPR', 'PCI_DSS', 'OWASP_TOP_10']
                })
        
        return vulnerabilities
    
    def check_security_headers(self, response: requests.Response) -> List[Dict]:
        """Check for missing security headers"""
        vulnerabilities = []
        headers = response.headers
        
        required_headers = {
            'Strict-Transport-Security': {
                'cvss': 5.0,
                'description': 'HSTS header missing, site vulnerable to protocol downgrade attacks',
                'compliance': ['PCI_DSS', 'OWASP_TOP_10']
            },
            'Content-Security-Policy': {
                'cvss': 6.0,
                'description': 'CSP header missing, site vulnerable to XSS and injection attacks',
                'compliance': ['OWASP_TOP_10']
            },
            'X-Frame-Options': {
                'cvss': 4.5,
                'description': 'X-Frame-Options missing, site vulnerable to clickjacking',
                'compliance': ['OWASP_TOP_10']
            },
            'X-Content-Type-Options': {
                'cvss': 4.0,
                'description': 'X-Content-Type-Options missing, MIME sniffing possible',
                'compliance': ['OWASP_TOP_10']
            },
            'Referrer-Policy': {
                'cvss': 3.5,
                'description': 'Referrer-Policy missing, may leak sensitive URL information',
                'compliance': ['GDPR']
            },
            'Permissions-Policy': {
                'cvss': 4.0,
                'description': 'Permissions-Policy missing, browser features not restricted',
                'compliance': ['OWASP_TOP_10']
            }
        }
        
        for header, info in required_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'url': response.url,
                    'parameter': header,
                    'details': info['description'],
                    'cvss': info['cvss'],
                    'severity': self._get_severity(info['cvss']),
                    'compliance': info['compliance']
                })
        
        return vulnerabilities
    
    def test_sql_injection(self, url: str, params: Dict) -> List[Dict]:
        """Test for SQL Injection vulnerabilities"""
        vulnerabilities = []
        
        if not self.active_tests:
            return vulnerabilities
        
        sql_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL, NULL, NULL--",
            "1' AND '1'='1",
            "admin'--"
        ]
        
        for param, value in params.items():
            for payload in sql_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    response = self.session.get(url, params=test_params, timeout=5)
                    
                    # Simple detection based on error messages
                    error_indicators = [
                        'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 
                        'SQLite', 'syntax error', 'unclosed quotation'
                    ]
                    
                    if any(indicator.lower() in response.text.lower() for indicator in error_indicators):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'details': f"Potential SQL Injection via parameter '{param}'",
                            'payload': payload,
                            'cvss': self._calculate_cvss('SQL Injection'),
                            'severity': self._get_severity(9.8),
                            'compliance': ['OWASP_TOP_10', 'PCI_DSS']
                        })
                        break  # One vulnerability per parameter is enough
                except Exception:
                    continue
        
        return vulnerabilities
    
    def test_xss(self, url: str, params: Dict) -> List[Dict]:
        """Test for Cross-Site Scripting vulnerabilities"""
        vulnerabilities = []
        
        if not self.active_tests:
            return vulnerabilities
        
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            '<svg onload=alert(1)>'
        ]
        
        for param, value in params.items():
            for payload in xss_payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    response = self.session.get(url, params=test_params, timeout=5)
                    
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'XSS',
                            'url': url,
                            'parameter': param,
                            'details': f"Reflected XSS via parameter '{param}'",
                            'payload': payload,
                            'cvss': self._calculate_cvss('XSS'),
                            'severity': self._get_severity(7.5),
                            'compliance': ['OWASP_TOP_10']
                        })
                        break
                except Exception:
                    continue
        
        return vulnerabilities
    
    async def analyze_with_ai(self, vulnerability: Dict) -> Dict:
        """Analyze vulnerability using AI (simulated if no API key)"""
        if not AI_ENABLED or not AI_API_KEY:
            # Simulated AI analysis
            vulnerability['ai_analysis'] = {
                'confidence': 0.85,
                'false_positive_likelihood': 'Low',
                'context': 'Automated analysis suggests this is a genuine finding',
                'priority': 'High' if vulnerability['cvss'] > 7.0 else 'Medium',
                'ai_model': 'Simulated AI'
            }
            return vulnerability
        
        # Real AI analysis (OpenAI compatible)
        try:
            prompt = f"""
            Analyze this security vulnerability finding:
            Type: {vulnerability['type']}
            URL: {vulnerability['url']}
            Parameter: {vulnerability.get('parameter', 'N/A')}
            Details: {vulnerability['details']}
            CVSS: {vulnerability['cvss']}
            
            Provide:
            1. Confidence score (0-1)
            2. False positive likelihood (Low/Medium/High)
            3. Context analysis
            4. Remediation priority
            """
            
            response = requests.post(
                f"{AI_API_BASE_URL}/chat/completions",
                headers={"Authorization": f"Bearer {AI_API_KEY}"},
                json={
                    "model": AI_MODEL_NAME,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500
                },
                timeout=30
            )
            
            if response.status_code == 200:
                ai_response = response.json()['choices'][0]['message']['content']
                vulnerability['ai_analysis'] = {
                    'confidence': 0.9,
                    'analysis_text': ai_response,
                    'ai_model': AI_MODEL_NAME
                }
        except Exception as e:
            vulnerability['ai_analysis'] = {
                'error': str(e),
                'confidence': 0.5
            }
        
        return vulnerability
    
    def build_attack_graph(self, vulnerabilities: List[Dict]) -> nx.DiGraph:
        """Build attack path graph from vulnerabilities"""
        graph = nx.DiGraph()
        
        # Add nodes for each vulnerability
        for i, vuln in enumerate(vulnerabilities):
            node_id = f"vuln_{i}"
            graph.add_node(
                node_id,
                type=vuln['type'],
                severity=vuln['severity'],
                cvss=vuln['cvss'],
                url=vuln['url']
            )
        
        # Add edges based on logical attack paths
        # Example: Info Disclosure -> Auth Bypass -> RCE
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        
        vuln_nodes = list(graph.nodes())
        for i in range(len(vuln_nodes) - 1):
            node1 = vuln_nodes[i]
            node2 = vuln_nodes[i + 1]
            
            sev1 = severity_order.get(graph.nodes[node1]['severity'], 1)
            sev2 = severity_order.get(graph.nodes[node2]['severity'], 1)
            
            # Connect vulnerabilities that could form an attack chain
            if sev2 >= sev1:
                graph.add_edge(node1, node2, relationship='escalation')
        
        return graph
    
    def check_compliance(self, vulnerabilities: List[Dict]) -> Dict:
        """Check compliance against selected standard"""
        compliance_results = {
            'standard': COMPLIANCE_STANDARDS.get(self.compliance_standard, 'Custom'),
            'passed': [],
            'failed': [],
            'warnings': [],
            'score': 0
        }
        
        # Map vulnerabilities to compliance controls
        compliance_map = {
            'OWASP_TOP_10': {
                'A01': ['SQL Injection', 'XSS', 'Command Injection'],
                'A02': ['Missing Security Header', 'Weak Cryptography'],
                'A03': ['Data Leakage', 'Sensitive Data Exposure'],
                'A05': ['Outdated Dependency', 'Missing Security Header'],
                'A07': ['Authentication Bypass', 'Session Fixation']
            },
            'PCI_DSS': {
                'Req 1': ['Missing Security Header'],
                'Req 2': ['Default Credentials', 'Data Leakage'],
                'Req 6': ['SQL Injection', 'XSS', 'Outdated Dependency'],
                'Req 8': ['Authentication Bypass'],
                'Req 3': ['Data Leakage', 'Credit Card Numbers']
            },
            'GDPR': {
                'Art 5': ['Data Leakage', 'Email Addresses'],
                'Art 32': ['Missing Security Header', 'Weak Cryptography'],
                'Art 33': ['Data Breach Risk']
            }
        }
        
        standard_controls = compliance_map.get(self.compliance_standard, {})
        
        for control, vuln_types in standard_controls.items():
            failed_vulns = [v for v in vulnerabilities if v['type'] in vuln_types]
            
            if failed_vulns:
                compliance_results['failed'].append({
                    'control': control,
                    'vulnerabilities': failed_vulns,
                    'count': len(failed_vulns)
                })
            else:
                compliance_results['passed'].append(control)
        
        # Calculate compliance score
        total_controls = len(standard_controls)
        passed_controls = len(compliance_results['passed'])
        compliance_results['score'] = round((passed_controls / total_controls) * 100, 2) if total_controls > 0 else 0
        
        return compliance_results
    
    def generate_poc(self, vulnerability: Dict) -> str:
        """Generate Proof of Concept script for vulnerability"""
        vuln_type = vulnerability['type']
        url = vulnerability['url']
        param = vulnerability.get('parameter', '')
        payload = vulnerability.get('payload', '')
        
        if vuln_type == 'SQL Injection':
            return f"""# SQL Injection PoC
import requests

url = "{url}"
params = {{{repr(param)}: {repr(payload)}}}

response = requests.get(url, params=params)
print("Status:", response.status_code)
print("Response length:", len(response.text))

# Verify injection
if 'SQL syntax' in response.text or 'error' in response.text.lower():
    print("[+] SQL Injection confirmed!")
else:
    print("[-] SQL Injection not confirmed")
"""
        
        elif vuln_type == 'XSS':
            return f"""# XSS PoC
import requests
from bs4 import BeautifulSoup

url = "{url}"
params = {{{repr(param)}: {repr(payload)}}}

response = requests.get(url, params=params)
soup = BeautifulSoup(response.text, 'html.parser')

if {repr(payload)} in response.text:
    print("[+] XSS vulnerability confirmed!")
    print("Payload reflected in response")
else:
    print("[-] XSS not confirmed")
"""
        
        elif vuln_type == 'Data Leakage':
            return f"""# Data Leakage Verification
import requests
import re

url = "{url}"
pattern = r'{vulnerability.get("evidence", [""])[0] if vulnerability.get("evidence") else ".*"}'

response = requests.get(url)
matches = re.findall(pattern, response.text)

if matches:
    print(f"[+] Found {{len(matches)}} instances of potential data leakage")
    print("Sample:", matches[:3])
else:
    print("[-] No data leakage detected in current scan")
"""
        
        else:
            return f"""# General Verification Script
import requests

url = "{url}"

response = requests.get(url)
print(f"URL: {{url}}")
print(f"Status: {{response.status_code}}")
print(f"Headers: {{dict(response.headers)}}")

# Manual verification required for {{vuln_type}}
print("\\nPlease manually verify this finding.")
"""
    
    def scan(self) -> Dict[str, Any]:
        """Main scanning function"""
        start_time = datetime.now()
        
        try:
            # Step 1: Subdomain Enumeration (if enabled)
            if self.discover_subdomains:
                self.enumerate_subdomains()
            
            # Step 2: Initial request
            response = self.session.get(self.target_url, timeout=10)
            
            # Step 3: Check security headers
            header_vulns = self.check_security_headers(response)
            self.vulnerabilities.extend(header_vulns)
            
            # Step 4: Analyze content for data leakage
            leakage_vulns = self.detect_data_leakage(response.text, self.target_url)
            self.vulnerabilities.extend(leakage_vulns)
            
            # Step 5: SCA - Check dependencies
            sca_vulns = self.analyze_dependencies_sca(response.text, self.target_url)
            self.vulnerabilities.extend(sca_vulns)
            
            # Step 6: Extract forms and parameters
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            params = {}
            
            for form in forms:
                inputs = form.find_all('input')
                for inp in inputs:
                    if inp.get('name'):
                        params[inp.get('name')] = inp.get('value', 'test')
            
            # Step 7: Test for SQL Injection and XSS (if active tests enabled)
            if self.active_tests and params:
                sql_vulns = self.test_sql_injection(self.target_url, params)
                self.vulnerabilities.extend(sql_vulns)
                
                xss_vulns = self.test_xss(self.target_url, params)
                self.vulnerabilities.extend(xss_vulns)
            
            # Step 8: AI Analysis (if enabled)
            if self.enable_ai:
                for i, vuln in enumerate(self.vulnerabilities):
                    self.vulnerabilities[i] = self.analyze_with_ai(vuln)
            
            # Step 9: Build attack graph
            self.attack_graph = self.build_attack_graph(self.vulnerabilities)
            
            # Step 10: Compliance check
            compliance_results = self.check_compliance(self.vulnerabilities)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            return {
                'target': self.target_url,
                'scan_mode': self.mode,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'subdomains_found': len(self.subdomains),
                'subdomains': self.subdomains,
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities,
                'compliance': compliance_results,
                'attack_graph': {
                    'nodes': list(self.attack_graph.nodes(data=True)),
                    'edges': list(self.attack_graph.edges(data=True)),
                    'has_paths': nx.number_strongly_connected_components(self.attack_graph) > 1
                },
                'summary': {
                    'critical': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                    'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                    'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                    'low': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
                }
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'target': self.target_url,
                'scan_mode': self.mode
            }
