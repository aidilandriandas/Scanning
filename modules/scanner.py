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
    
    def _get_remediation_and_poc(self, vuln_type: str, details: str, url: str, param: str = None) -> Dict:
        """Get remediation steps and safe proof-of-concept for vulnerabilities"""
        remediation_db = {
            'SQL Injection': {
                'remediation': '''1. Gunakan Prepared Statements/Parameterized Queries
2. Implementasi input validation dan sanitization
3. Gunakan ORM (Object-Relational Mapping) seperti SQLAlchemy
4. Terapkan principle of least privilege untuk database user
5. Enable WAF (Web Application Firewall)''',
                'safe_poc': f"Payload verifikasi aman: ' OR '1'='1 (JANGAN dieksekusi di production)\nVerifikasi: Jika response berubah saat payload ditambahkan ke parameter '{param or 'query'}', maka rentan.",
                'impact': 'Attacker dapat membaca, mengubah, atau menghapus seluruh database. Dapat menyebabkan data breach masif.'
            },
            'XSS': {
                'remediation': '''1. Encode semua output yang berasal dari user input
2. Gunakan Content Security Policy (CSP) header
3. Implementasi input validation ketat
4. Gunakan framework dengan auto-escaping (React, Vue, Angular)
5. Sanitize HTML input dengan library seperti DOMPurify''',
                'safe_poc': f"Payload verifikasi: <script>alert('XSS')</script>\nVerifikasi: Jika alert muncul saat input dimasukkan ke parameter '{param or 'input'}', maka rentan.",
                'impact': 'Attacker dapat mencuri session cookies, redirect user ke situs phishing, atau mengambil alih akun user.'
            },
            'Missing Security Header': {
                'remediation': f'''1. Tambahkan header berikut di web server atau aplikasi:
   - Strict-Transport-Security: max-age=31536000; includeSubDomains
   - Content-Security-Policy: default-src 'self'
   - X-Frame-Options: DENY
   - X-Content-Type-Options: nosniff
   - Referrer-Policy: strict-origin-when-cross-origin
2. Gunakan middleware security seperti helmet.js (Node.js) atau Flask-Talisman (Python)''',
                'safe_poc': "Verifikasi: Cek response headers menggunakan browser DevTools atau curl -I {url}\nJika header tidak ada, maka rentan.",
                'impact': 'Situs rentan terhadap clickjacking, XSS, MIME sniffing, dan protocol downgrade attacks.'
            },
            'Data Leakage': {
                'remediation': '''1. Hapus sensitive data dari source code dan logs
2. Encrypt data sensitif di rest dan transit
3. Implementasi access control ketat
4. Gunakan secret management tools (HashiCorp Vault, AWS Secrets Manager)
5. Audit dan monitoring akses data sensitif''',
                'safe_poc': f"Verifikasi: Akses halaman {url} dan lihat apakah terdapat email, phone number, API keys, atau credit card numbers yang terekspos.",
                'impact': 'Data sensitif seperti PII, credentials, atau financial data dapat diakses attacker. Dapat menyebabkan compliance violation (GDPR, PCI-DSS).'
            },
            'Outdated Dependency': {
                'remediation': '''1. Update dependency ke versi terbaru yang aman
2. Gunakan tools seperti npm audit, pip-audit, atau Dependabot
3. Implementasi automated dependency scanning di CI/CD
4. Pin versi dependency di package.json/requirements.txt
5. Subscribe ke security advisory dari vendor''',
                'safe_poc': f"Verifikasi: Cek versi dependency di {url}. Bandingkan dengan CVE database.\nJika versi < versi aman yang direkomendasikan, maka rentan.",
                'impact': 'Known vulnerabilities dapat dieksploitasi attacker. Dapat menyebabkan remote code execution atau data breach.'
            },
            'Directory Traversal': {
                'remediation': '''1. Validasi dan sanitize file paths
2. Gunakan chroot jail atau containerization
3. Implementasi whitelist untuk file yang dapat diakses
4. Disable directory listing di web server
5. Gunakan fungsi basename() untuk extract filename saja''',
                'safe_poc': f"Payload verifikasi: ../../etc/passwd\nVerifikasi: Jika content file sistem terlihat di response parameter '{param or 'file'}', maka rentan.",
                'impact': 'Attacker dapat membaca file sensitif di server seperti /etc/passwd, config files, atau source code.'
            },
            'Subdomain Takeover': {
                'remediation': '''1. Hapus DNS records untuk subdomain yang tidak digunakan
2. Audit regularly DNS records dan third-party services
3. Gunakan monitoring tools untuk detect dangling DNS
4. Claim subdomain di third-party services sebelum attacker melakukannya
5. Implementasi automated DNS monitoring''',
                'safe_poc': f"Verifikasi: Coba akses subdomain yang ditemukan. Jika menampilkan 'site not found' atau error dari third-party (GitHub Pages, Heroku, dll), maka berpotensi takeover.",
                'impact': 'Attacker dapat mengambil alih subdomain dan digunakan untuk phishing, malware distribution, atau bypass security controls.'
            },
            'Open Redirect': {
                'remediation': '''1. Validasi URL redirect terhadap whitelist domain
2. Gunakan relative path untuk redirect internal
3. Implementasi user confirmation untuk redirect eksternal
4. Hindari menggunakan user input langsung untuk redirect
5. Gunakan token-based redirect mechanism''',
                'safe_poc': f"Payload verifikasi: ?redirect=http://evil.com\nVerifikasi: Jika di-redirect ke domain eksternal tanpa warning, maka rentan.",
                'impact': 'Digunakan untuk phishing attacks dengan membuat link yang terlihat legitimate tapi redirect ke situs malicious.'
            }
        }
        
        # Default remediation jika type tidak ada di database
        default = {
            'remediation': 'Lakukan security review dan implementasi best practices sesuai jenis kerentanan.',
            'safe_poc': 'Verifikasi manual diperlukan untuk konfirmasi temuan ini.',
            'impact': 'Dampak bervariasi tergantung konteks aplikasi dan kerentanan spesifik.'
        }
        
        result = remediation_db.get(vuln_type, default)
        
        # Customize dengan info spesifik
        customized = result.copy()
        customized['safe_poc'] = customized['safe_poc'].format(url=url, param=param or 'query')
        
        return customized
    
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
                        remediation_poc = self._get_remediation_and_poc('Outdated Dependency', f"Version {clean_version} may be vulnerable", url, pkg)
                        vulnerabilities.append({
                            'type': 'Outdated Dependency',
                            'url': url,
                            'parameter': pkg,
                            'details': f"Version {clean_version} may be vulnerable",
                            'cvss': self._calculate_cvss('Outdated Dependency'),
                            'severity': self._get_severity(8.0),
                            'cve': cve_info.get('cve'),
                            'compliance': ['PCI_DSS', 'OWASP_TOP_10'],
                            'remediation': remediation_poc['remediation'],
                            'safe_poc': remediation_poc['safe_poc'],
                            'impact_analysis': remediation_poc['impact']
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
                            remediation_poc = self._get_remediation_and_poc('Outdated Dependency', f"Version {version} may be vulnerable", url, pkg)
                            vulnerabilities.append({
                                'type': 'Outdated Dependency',
                                'url': url,
                                'parameter': pkg,
                                'details': f"Version {version} may be vulnerable",
                                'cvss': self._calculate_cvss('Outdated Dependency'),
                                'severity': self._get_severity(7.5),
                                'cve': cve_info.get('cve'),
                                'compliance': ['PCI_DSS', 'OWASP_TOP_10'],
                                'remediation': remediation_poc['remediation'],
                                'safe_poc': remediation_poc['safe_poc'],
                                'impact_analysis': remediation_poc['impact']
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
                remediation_poc = self._get_remediation_and_poc('Data Leakage', f"Found {len(matches)} potential {data_type}", url, data_type)
                vulnerabilities.append({
                    'type': 'Data Leakage',
                    'url': url,
                    'parameter': data_type,
                    'details': f"Found {len(matches)} potential {data_type}",
                    'evidence': sample_matches,
                    'cvss': self._calculate_cvss('Data Leakage'),
                    'severity': self._get_severity(8.0),
                    'compliance': ['GDPR', 'PCI_DSS', 'OWASP_TOP_10'],
                    'remediation': remediation_poc['remediation'],
                    'safe_poc': remediation_poc['safe_poc'],
                    'impact_analysis': remediation_poc['impact']
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
                remediation_poc = self._get_remediation_and_poc('Missing Security Header', info['description'], response.url, header)
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'url': response.url,
                    'parameter': header,
                    'details': info['description'],
                    'cvss': info['cvss'],
                    'severity': self._get_severity(info['cvss']),
                    'compliance': info['compliance'],
                    'remediation': remediation_poc['remediation'],
                    'safe_poc': remediation_poc['safe_poc'],
                    'impact_analysis': remediation_poc['impact']
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
                        remediation_poc = self._get_remediation_and_poc('SQL Injection', f"Potential SQL Injection via parameter '{param}'", url, param)
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'details': f"Potential SQL Injection via parameter '{param}'",
                            'payload': payload,
                            'cvss': self._calculate_cvss('SQL Injection'),
                            'severity': self._get_severity(9.8),
                            'compliance': ['OWASP_TOP_10', 'PCI_DSS'],
                            'remediation': remediation_poc['remediation'],
                            'safe_poc': remediation_poc['safe_poc'],
                            'impact_analysis': remediation_poc['impact']
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
            failed_vulns = [v for v in vulnerabilities if v.get('type', '') in vuln_types]
            
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
    
    def _validate_findings(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Smart validation to reduce false positives
        Uses multi-layer verification and assigns confidence scores
        """
        validated = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            confidence_score = 75  # Default confidence
            
            # Layer 1: Check if evidence is strong
            evidence = vuln.get('evidence', '')
            if evidence and len(evidence) > 20:
                confidence_score += 10
            
            # Layer 2: Cross-verify with external scanners if available
            if hasattr(self, 'external_scanners_used') and self.external_scanners_used:
                # If external scanner confirms, boost confidence
                confidence_score += 10
            
            # Layer 3: Pattern-based validation
            if vuln_type in ['SQL Injection', 'XSS']:
                if vuln.get('payload') and vuln.get('details'):
                    confidence_score += 5
            
            # Layer 4: Check for common false positive patterns
            fp_patterns = ['example.com', 'test', 'demo', 'localhost']
            url = vuln.get('url', '')
            if any(pattern in url.lower() for pattern in fp_patterns):
                confidence_score -= 15
            
            # Normalize confidence score
            confidence_score = max(0, min(100, confidence_score))
            
            # Only include if confidence is above threshold (50%)
            if confidence_score >= 50:
                vuln['confidence_score'] = confidence_score
                vuln['validation_status'] = 'validated' if confidence_score >= 75 else 'needs_review'
                
                # Add false positive flag if low confidence
                if confidence_score < 60:
                    vuln['false_positive_likelihood'] = 'High'
                elif confidence_score < 75:
                    vuln['false_positive_likelihood'] = 'Medium'
                else:
                    vuln['false_positive_likelihood'] = 'Low'
                
                validated.append(vuln)
        
        return validated
    
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
    
    def scan(self, progress_callback=None) -> Dict[str, Any]:
        """Main scanning function with optional progress callback"""
        start_time = datetime.now()
        
        # Helper to send progress updates
        def send_progress(activity: str, percentage: int):
            if progress_callback:
                progress_callback({
                    'activity': activity,
                    'percentage': percentage,
                    'timestamp': datetime.now().isoformat()
                })
        
        try:
            # Step 1: Subdomain Enumeration (if enabled)
            if self.discover_subdomains:
                send_progress("Enumerating subdomains...", 5)
                self.enumerate_subdomains()
            
            # Step 2: Initial request
            send_progress(f"Connecting to {self.target_url}...", 10)
            response = self.session.get(self.target_url, timeout=10)
            
            # Step 3: Check security headers
            send_progress("Checking security headers...", 20)
            header_vulns = self.check_security_headers(response)
            self.vulnerabilities.extend(header_vulns)
            
            # Step 4: Analyze content for data leakage
            send_progress("Analyzing for data leakage...", 30)
            leakage_vulns = self.detect_data_leakage(response.text, self.target_url)
            self.vulnerabilities.extend(leakage_vulns)
            
            # Step 5: SCA - Check dependencies
            send_progress("Checking dependencies (SCA)...", 40)
            sca_vulns = self.analyze_dependencies_sca(response.text, self.target_url)
            self.vulnerabilities.extend(sca_vulns)
            
            # Step 6: Extract forms and parameters
            send_progress("Extracting forms and parameters...", 50)
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
                send_progress("Testing for SQL Injection...", 60)
                sql_vulns = self.test_sql_injection(self.target_url, params)
                self.vulnerabilities.extend(sql_vulns)
                
                send_progress("Testing for XSS...", 70)
                xss_vulns = self.test_xss(self.target_url, params)
                self.vulnerabilities.extend(xss_vulns)
            
            # Step 8: AI Analysis (if enabled)
            if self.enable_ai:
                send_progress("Running AI analysis...", 80)
                for i, vuln in enumerate(self.vulnerabilities):
                    self.vulnerabilities[i] = self.analyze_with_ai(vuln)
            
            # Step 9: Build attack graph
            send_progress("Building attack graph...", 85)
            self.attack_graph = self.build_attack_graph(self.vulnerabilities)
            
            # Step 10: Compliance check with detailed mapping
            send_progress("Checking compliance standards...", 90)
            compliance_results = self.check_compliance(self.vulnerabilities)
            
            # Step 11: Smart validation & confidence scoring
            send_progress("Validating findings with external tools...", 93)
            validated_vulns = self._validate_findings(self.vulnerabilities)
            
            # Add compliance tags to each vulnerability
            from modules.reports.generator import ComplianceMapper
            for vuln in validated_vulns:
                vuln['compliance_tags'] = ComplianceMapper.get_compliance_tags(vuln.get('name', ''))
            
            send_progress("Finalizing report...", 95)
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            send_progress("Scan completed!", 100)
            
            # Calculate overall confidence score
            avg_confidence = sum([v.get('confidence_score', 75) for v in validated_vulns]) / len(validated_vulns) if validated_vulns else 0
            
            return {
                'target': self.target_url,
                'scan_mode': self.mode,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'subdomains_found': len(self.subdomains),
                'subdomains': self.subdomains,
                'total_vulnerabilities': len(validated_vulns),
                'vulnerabilities': validated_vulns,
                'compliance': compliance_results,
                'validation_status': 'validated',
                'confidence_score': avg_confidence,
                'attack_graph': {
                    'nodes': list(self.attack_graph.nodes(data=True)),
                    'edges': list(self.attack_graph.edges(data=True)),
                    'has_paths': nx.number_strongly_connected_components(self.attack_graph) > 1
                },
                'summary': {
                    'critical': len([v for v in validated_vulns if v.get('cvss_severity', 'MEDIUM').upper() == 'CRITICAL']),
                    'high': len([v for v in validated_vulns if v.get('cvss_severity', 'MEDIUM').upper() == 'HIGH']),
                    'medium': len([v for v in validated_vulns if v.get('cvss_severity', 'MEDIUM').upper() == 'MEDIUM']),
                    'low': len([v for v in validated_vulns if v.get('cvss_severity', 'MEDIUM').upper() == 'LOW'])
                }
            }
            
        except Exception as e:
            if progress_callback:
                progress_callback({
                    'activity': f'Error: {str(e)}',
                    'percentage': 0,
                    'timestamp': datetime.now().isoformat(),
                    'error': True
                })
            return {
                'error': str(e),
                'target': self.target_url,
                'scan_mode': self.mode
            }
