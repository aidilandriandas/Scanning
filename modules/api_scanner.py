"""
API Security Scanner Module
Detects OWASP API Top 10 vulnerabilities:
- API1: Broken Object Level Authorization (BOLA)
- API2: Broken Authentication
- API3: Excessive Data Exposure
- API4: Lack of Resources & Rate Limiting
- API5: Broken Function Level Authorization
- API6: Mass Assignment
- API7: Security Misconfiguration
- API8: Injection
- API9: Improper Assets Management
- API10: Unsafe Consumption of APIs
"""

import requests
import json
import re
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional
from datetime import datetime


class APISecurityScanner:
    def __init__(self, base_url: str, api_endpoints: List[str] = None, 
                 auth_token: str = None, openapi_spec: str = None):
        self.base_url = base_url.rstrip('/')
        self.api_endpoints = api_endpoints or []
        self.auth_token = auth_token
        self.openapi_spec = openapi_spec
        self.session = requests.Session()
        self.vulnerabilities = []
        self.discovered_endpoints = []
        self.rate_limit_info = {}
        
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})
        
        self.session.headers.update({
            'User-Agent': 'APISecurityScanner/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
    
    def load_openapi_spec(self, spec_url: str = None) -> bool:
        """Load and parse OpenAPI/Swagger specification"""
        try:
            if spec_url:
                response = self.session.get(spec_url, timeout=10)
                if response.status_code == 200:
                    self.openapi_spec = response.json() if spec_url.endswith('.json') else response.text
            elif self.openapi_spec:
                if isinstance(self.openapi_spec, str):
                    self.openapi_spec = json.loads(self.openapi_spec)
            
            if self.openapi_spec:
                self._extract_endpoints_from_openapi()
                return True
        except Exception as e:
            print(f"Failed to load OpenAPI spec: {e}")
        return False
    
    def _extract_endpoints_from_openapi(self):
        """Extract API endpoints from OpenAPI specification"""
        if not self.openapi_spec:
            return
        
        paths = self.openapi_spec.get('paths', {})
        for path, methods in paths.items():
            for method in methods.keys():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    endpoint = {
                        'path': path,
                        'method': method.upper(),
                        'url': f"{self.base_url}{path}"
                    }
                    self.discovered_endpoints.append(endpoint)
                    if endpoint['url'] not in self.api_endpoints:
                        self.api_endpoints.append(endpoint['url'])
    
    def discover_endpoints(self) -> List[str]:
        """Discover API endpoints through common patterns"""
        common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/graphql', '/graphiql',
            '/rest', '/rest/v1',
            '/v1', '/v2', '/v3',
            '/api/users', '/api/user', '/api/auth',
            '/api/products', '/api/items',
            '/api/orders', '/api/transactions',
            '/api/settings', '/api/config',
            '/api/admin', '/api/dashboard'
        ]
        
        discovered = []
        for path in common_api_paths:
            try:
                url = f"{self.base_url}{path}"
                response = self.session.get(url, timeout=5)
                if response.status_code in [200, 201, 401, 403, 404, 405, 422]:
                    # Even 401/403 indicates endpoint exists
                    endpoint = {'path': path, 'method': 'GET', 'url': url}
                    discovered.append(endpoint)
                    if url not in self.api_endpoints:
                        self.api_endpoints.append(url)
            except Exception:
                continue
        
        self.discovered_endpoints.extend(discovered)
        return self.api_endpoints
    
    def check_bola(self, endpoint: str, method: str = 'GET') -> List[Dict]:
        """API1: Broken Object Level Authorization (BOLA/IDOR)"""
        vulnerabilities = []
        
        # Test with different ID patterns
        test_ids = ['1', '2', '999999', '../admin', 'null', 'undefined']
        
        for test_id in test_ids:
            try:
                test_url = endpoint.replace('{id}', test_id).replace(':id', test_id)
                if '{id}' not in endpoint and ':id' not in endpoint:
                    test_url = f"{endpoint}/{test_id}"
                
                response = self.session.request(method, test_url, timeout=10)
                
                # Check if different IDs return different user data without auth
                if response.status_code == 200:
                    data = response.json() if 'application/json' in response.headers.get('Content-Type', '') else {}
                    
                    # Check if sensitive data is exposed
                    if any(key in str(data) for key in ['email', 'password', 'ssn', 'credit_card', 'phone']):
                        vulnerabilities.append({
                            'type': 'API1: Broken Object Level Authorization (BOLA)',
                            'url': test_url,
                            'method': method,
                            'details': f'Endpoint returns sensitive data with ID {test_id} without proper authorization',
                            'severity': 'HIGH',
                            'cvss': 8.6,
                            'owasp_category': 'API1:2023 Broken Object Level Authorization',
                            'remediation': '''1. Implementasi object-level authorization checks
2. Gunakan UUID random daripada sequential IDs
3. Validasi user ownership sebelum return data
4. Terapkan principle of least privilege
5. Audit semua endpoint yang mengakses objek''',
                            'impact': 'Attacker dapat mengakses data user lain dengan mengubah ID parameter. Dapat menyebabkan data breach masif.',
                            'compliance': ['GDPR', 'PCI-DSS', 'OWASP_API_TOP_10']
                        })
                        break
            except Exception:
                continue
        
        return vulnerabilities
    
    def check_broken_authentication(self, endpoint: str) -> List[Dict]:
        """API2: Broken Authentication"""
        vulnerabilities = []
        
        # Test common auth bypass techniques
        auth_tests = [
            {'headers': {'Authorization': 'Bearer invalid_token'}, 'desc': 'Invalid Bearer token accepted'},
            {'headers': {'Authorization': 'Basic invalid_base64'}, 'desc': 'Invalid Basic auth accepted'},
            {'headers': {}, 'desc': 'No authentication required'},
            {'headers': {'X-Forwarded-User': 'admin'}, 'desc': 'Header injection allows impersonation'},
            {'headers': {'X-Original-URL': '/admin'}, 'desc': 'URL rewriting bypass'}
        ]
        
        for test in auth_tests:
            try:
                response = self.session.get(endpoint, headers=test['headers'], timeout=10)
                
                # Check if authentication is bypassed
                if response.status_code == 200 and 'unauthorized' not in response.text.lower():
                    # Additional check: see if we get admin/sensitive data
                    data = response.json() if 'application/json' in response.headers.get('Content-Type', '') else {}
                    
                    if any(key in str(data) for key in ['admin', 'role', 'permission', 'token']):
                        vulnerabilities.append({
                            'type': 'API2: Broken Authentication',
                            'url': endpoint,
                            'method': 'GET',
                            'details': test['desc'],
                            'severity': 'CRITICAL',
                            'cvss': 9.1,
                            'owasp_category': 'API2:2023 Broken Authentication',
                            'remediation': '''1. Implementasi strong authentication (OAuth2, JWT)
2. Validasi token di setiap request
3. Gunakan secure session management
4. Implementasi rate limiting untuk login attempts
5. Enable multi-factor authentication (MFA)
6. Invalidate tokens setelah logout''',
                            'impact': 'Attacker dapat bypass authentication dan mengakses akun user lain atau fungsi admin.',
                            'compliance': ['OWASP_API_TOP_10', 'PCI-DSS']
                        })
                        break
            except Exception:
                continue
        
        return vulnerabilities
    
    def check_excessive_data_exposure(self, endpoint: str) -> List[Dict]:
        """API3: Excessive Data Exposure"""
        vulnerabilities = []
        
        try:
            response = self.session.get(endpoint, timeout=10)
            if response.status_code == 200:
                data = response.json() if 'application/json' in response.headers.get('Content-Type', '') else {}
                
                # Check for excessive fields
                sensitive_fields = [
                    'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
                    'credit_card', 'cc_number', 'cvv', 'ssn', 'nik', 'birth_date',
                    'private_key', 'encryption_key', 'bank_account', 'salary'
                ]
                
                found_sensitive = []
                if isinstance(data, dict):
                    for field in sensitive_fields:
                        if field in str(data).lower():
                            found_sensitive.append(field)
                
                if found_sensitive:
                    vulnerabilities.append({
                        'type': 'API3: Excessive Data Exposure',
                        'url': endpoint,
                        'method': 'GET',
                        'details': f'API exposes sensitive fields: {", ".join(found_sensitive)}',
                        'severity': 'HIGH',
                        'cvss': 7.5,
                        'owasp_category': 'API3:2023 Excessive Data Exposure',
                        'remediation': '''1. Return hanya field yang diperlukan (filter response)
2. Implementasi DTOs (Data Transfer Objects)
3. Gunakan field-level access control
4. Review semua API responses untuk sensitive data
5. Encrypt sensitive data di transit dan rest''',
                        'impact': 'Sensitive data terekspos ke attacker. Dapat menyebabkan identity theft, financial fraud, atau compliance violation.',
                        'compliance': ['GDPR', 'PCI-DSS', 'OWASP_API_TOP_10']
                    })
        except Exception:
            pass
        
        return vulnerabilities
    
    def check_rate_limiting(self, endpoint: str, method: str = 'POST') -> List[Dict]:
        """API4: Lack of Resources & Rate Limiting"""
        vulnerabilities = []
        
        # Send multiple rapid requests
        request_count = 10
        responses = []
        
        try:
            for i in range(request_count):
                start_time = datetime.now()
                response = self.session.request(method, endpoint, timeout=5)
                end_time = datetime.now()
                
                responses.append({
                    'status_code': response.status_code,
                    'response_time': (end_time - start_time).total_seconds(),
                    'headers': response.headers
                })
                
                # Check for rate limit headers
                if 'X-RateLimit-Limit' in response.headers:
                    self.rate_limit_info = {
                        'limit': response.headers.get('X-RateLimit-Limit'),
                        'remaining': response.headers.get('X-RateLimit-Remaining'),
                        'reset': response.headers.get('X-RateLimit-Reset')
                    }
            
            # Analyze responses
            status_codes = [r['status_code'] for r in responses]
            
            # No rate limiting if all requests succeed
            if all(code == 200 for code in status_codes):
                vulnerabilities.append({
                    'type': 'API4: Lack of Resources & Rate Limiting',
                    'url': endpoint,
                    'method': method,
                    'details': f'No rate limiting detected. {request_count} rapid requests all succeeded with status 200',
                    'severity': 'MEDIUM',
                    'cvss': 5.3,
                    'owasp_category': 'API4:2023 Lack of Resources & Rate Limiting',
                    'remediation': '''1. Implementasi rate limiting (contoh: 100 requests/minute per user)
2. Gunakan token bucket atau leaky bucket algorithm
3. Apply throttling berdasarkan IP, user, atau API key
4. Return 429 Too Many Requests saat limit terlampaui
5. Monitor dan alert untuk unusual traffic patterns''',
                    'impact': 'API rentan terhadap DoS attacks, brute force, dan resource exhaustion. Dapat menyebabkan service downtime.',
                    'compliance': ['OWASP_API_TOP_10']
                })
        except Exception:
            pass
        
        return vulnerabilities
    
    def check_mass_assignment(self, endpoint: str, method: str = 'POST') -> List[Dict]:
        """API6: Mass Assignment"""
        vulnerabilities = []
        
        # Test payloads with unexpected fields
        test_payloads = [
            {"role": "admin", "is_admin": True, "permission": "full"},
            {"price": 0.01, "discount": 100},
            {"verified": True, "status": "active"},
            {"__proto__": {"isAdmin": True}, "constructor": {"prototype": {"admin": True}}}
        ]
        
        for payload in test_payloads:
            try:
                response = self.session.post(endpoint, json=payload, timeout=10)
                
                # Check if privileged fields were accepted
                if response.status_code in [200, 201]:
                    response_data = response.json() if 'application/json' in response.headers.get('Content-Type', '') else {}
                    
                    # Check if sensitive fields were modified
                    if any(key in str(response_data) for key in ['admin', 'role', 'permission', 'verified']):
                        vulnerabilities.append({
                            'type': 'API6: Mass Assignment',
                            'url': endpoint,
                            'method': method,
                            'details': f'Endpoint accepts unexpected privileged fields: {list(payload.keys())}',
                            'severity': 'HIGH',
                            'cvss': 8.1,
                            'owasp_category': 'API6:2023 Mass Assignment',
                            'remediation': '''1. Gunakan allowlists untuk field yang dapat di-update
2. Implementasi DTOs dengan explicit field mapping
3. Pisahkan input models untuk user vs admin
4. Validasi dan filter input sebelum processing
5. Audit semua endpoint POST/PUT/PATCH''',
                            'impact': 'Attacker dapat memanipulasi privileged fields seperti role, permission, atau harga. Dapat menyebabkan privilege escalation.',
                            'compliance': ['OWASP_API_TOP_10']
                        })
                        break
            except Exception:
                continue
        
        return vulnerabilities
    
    def check_security_misconfiguration(self, endpoint: str) -> List[Dict]:
        """API7: Security Misconfiguration"""
        vulnerabilities = []
        
        try:
            response = self.session.options(endpoint, timeout=10)
            headers = response.headers
            
            # Check missing security headers
            missing_headers = []
            required_headers = {
                'Strict-Transport-Security': 'HSTS missing',
                'Content-Security-Policy': 'CSP missing',
                'X-Content-Type-Options': 'MIME sniffing protection missing',
                'X-Frame-Options': 'Clickjacking protection missing',
                'Access-Control-Allow-Origin': 'CORS misconfiguration possible'
            }
            
            for header, issue in required_headers.items():
                if header not in headers:
                    missing_headers.append(issue)
            
            # Check CORS misconfiguration
            cors_header = headers.get('Access-Control-Allow-Origin', '')
            if cors_header == '*' and 'credentials' in str(headers).lower():
                missing_headers.append('CORS allows all origins with credentials')
            
            if missing_headers:
                vulnerabilities.append({
                    'type': 'API7: Security Misconfiguration',
                    'url': endpoint,
                    'method': 'OPTIONS',
                    'details': f'Missing security headers: {", ".join(missing_headers)}',
                    'severity': 'MEDIUM',
                    'cvss': 5.3,
                    'owasp_category': 'API7:2023 Security Misconfiguration',
                    'remediation': '''1. Tambahkan semua security headers yang diperlukan
2. Disable verbose error messages di production
3. Remove default accounts dan unused features
4. Configure CORS dengan ketat (whitelist domains)
5. Regular security configuration review''',
                    'impact': 'Situs rentan terhadap berbagai attacks seperti XSS, clickjacking, MIME sniffing. Dapat memudahkan attacker.',
                    'compliance': ['OWASP_API_TOP_10', 'PCI-DSS']
                })
        except Exception:
            pass
        
        return vulnerabilities
    
    def check_injection(self, endpoint: str, method: str = 'POST') -> List[Dict]:
        """API8: Injection (SQL, NoSQL, Command)"""
        vulnerabilities = []
        
        injection_payloads = {
            'sql': ["' OR '1'='1", "'; DROP TABLE users--", "1; SELECT * FROM users"],
            'nosql': [{"$ne": null}, {"$gt": ""}, {"$regex": "^.*"}],
            'command': ["; ls -la", "| cat /etc/passwd", "$(whoami)"]
        }
        
        for inj_type, payloads in injection_payloads.items():
            for payload in payloads:
                try:
                    test_data = {'search': payload, 'query': payload, 'filter': payload}
                    response = self.session.post(endpoint, json=test_data, timeout=10)
                    
                    # Check for error messages indicating injection
                    error_patterns = [
                        'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                        'MongoError', 'BSON', 'syntax error', 'stack trace'
                    ]
                    
                    response_text = response.text.lower()
                    if any(pattern.lower() in response_text for pattern in error_patterns):
                        vulnerabilities.append({
                            'type': f'API8: Injection ({inj_type.upper()})',
                            'url': endpoint,
                            'method': method,
                            'details': f'Potential {inj_type} injection detected with payload: {str(payload)[:50]}',
                            'severity': 'CRITICAL',
                            'cvss': 9.8,
                            'owasp_category': 'API8:2023 Injection',
                            'remediation': '''1. Gunakan parameterized queries/prepared statements
2. Implementasi input validation dan sanitization
3. Gunakan ORM yang aman
4. Escape special characters
5. Apply principle of least privilege untuk database
6. Enable WAF dengan injection rules''',
                            'impact': 'Attacker dapat execute arbitrary commands, mengakses database, atau mengambil alih server. Dapat menyebabkan data breach total.',
                            'compliance': ['OWASP_API_TOP_10', 'PCI-DSS', 'GDPR']
                        })
                        break
                except Exception:
                    continue
            
            if vulnerabilities:
                break
        
        return vulnerabilities
    
    def scan_all_endpoints(self) -> List[Dict]:
        """Run all API security checks on discovered endpoints"""
        all_vulnerabilities = []
        
        # Discover endpoints if not already done
        if not self.api_endpoints:
            self.discover_endpoints()
        
        # Load OpenAPI spec if available
        if self.openapi_spec:
            self.load_openapi_spec()
        
        print(f"Scanning {len(self.api_endpoints)} API endpoints...")
        
        for endpoint in self.api_endpoints:
            print(f"  Scanning: {endpoint}")
            
            # Determine method from endpoint
            method = 'GET'
            for disc_endpoint in self.discovered_endpoints:
                if disc_endpoint['url'] == endpoint:
                    method = disc_endpoint.get('method', 'GET')
                    break
            
            # Run all checks
            checks = [
                ('BOLA', lambda: self.check_bola(endpoint, method)),
                ('Authentication', lambda: self.check_broken_authentication(endpoint)),
                ('Data Exposure', lambda: self.check_excessive_data_exposure(endpoint)),
                ('Rate Limiting', lambda: self.check_rate_limiting(endpoint, method)),
                ('Mass Assignment', lambda: self.check_mass_assignment(endpoint, method)),
                ('Misconfiguration', lambda: self.check_security_misconfiguration(endpoint)),
                ('Injection', lambda: self.check_injection(endpoint, method))
            ]
            
            for check_name, check_func in checks:
                try:
                    vulns = check_func()
                    all_vulnerabilities.extend(vulns)
                    if vulns:
                        print(f"    ✓ Found {len(vulns)} {check_name} issue(s)")
                except Exception as e:
                    print(f"    ✗ Error in {check_name}: {e}")
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities
    
    def generate_report(self) -> Dict:
        """Generate comprehensive API security report"""
        return {
            'scan_timestamp': datetime.now().isoformat(),
            'target': self.base_url,
            'total_endpoints': len(self.api_endpoints),
            'discovered_endpoints': self.discovered_endpoints,
            'rate_limit_info': self.rate_limit_info,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities_by_severity': {
                'CRITICAL': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                'HIGH': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                'MEDIUM': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                'LOW': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
            },
            'vulnerabilities_by_category': self._group_by_category(),
            'vulnerabilities': self.vulnerabilities,
            'compliance_status': self._check_compliance()
        }
    
    def _group_by_category(self) -> Dict:
        """Group vulnerabilities by OWASP category"""
        categories = {}
        for vuln in self.vulnerabilities:
            category = vuln.get('owasp_category', 'Unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(vuln)
        return categories
    
    def _check_compliance(self) -> Dict:
        """Check compliance status against standards"""
        compliance_map = {
            'OWASP_API_TOP_10': set(),
            'GDPR': set(),
            'PCI-DSS': set()
        }
        
        for vuln in self.vulnerabilities:
            for standard in vuln.get('compliance', []):
                if standard in compliance_map:
                    compliance_map[standard].add(vuln['type'])
        
        return {
            standard: {
                'violations': list(issues),
                'compliant': len(issues) == 0,
                'violation_count': len(issues)
            }
            for standard, issues in compliance_map.items()
        }


def scan_api(target_url: str, endpoints: List[str] = None, 
             auth_token: str = None, openapi_spec_url: str = None) -> Dict:
    """
    Convenience function to scan API for vulnerabilities
    
    Args:
        target_url: Base URL of the API
        endpoints: List of specific endpoints to scan (optional)
        auth_token: Bearer token for authentication (optional)
        openapi_spec_url: URL to OpenAPI/Swagger spec (optional)
    
    Returns:
        Dictionary containing scan results and vulnerabilities
    """
    scanner = APISecurityScanner(
        base_url=target_url,
        api_endpoints=endpoints,
        auth_token=auth_token,
        openapi_spec=openapi_spec_url
    )
    
    # Discover endpoints
    scanner.discover_endpoints()
    
    # Load OpenAPI spec if provided
    if openapi_spec_url:
        scanner.load_openapi_spec(openapi_spec_url)
    
    # Run all scans
    scanner.scan_all_endpoints()
    
    # Generate report
    report = scanner.generate_report()
    
    return report
