"""
Business Logic & PII Leakage Scanner Module
Mendeteksi kerentanan logika bisnis (IDOR, Race Condition) dan kebocoran data pribadi (PII).
"""

import re
import uuid
import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs

class BusinessLogicScanner:
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; LogicScanner/1.0)"
        })
        
    def test_idor(self, base_url: str, param_name: str, sample_id: str, auth_headers: Dict) -> List[Dict]:
        """
        Test Insecure Direct Object Reference (IDOR)
        Mencoba mengakses resource dengan ID milik user lain (random UUID/int)
        """
        findings = []
        parsed = urlparse(base_url)
        
        # Generate random IDs untuk testing
        test_ids = [
            str(uuid.uuid4()),          # Random UUID
            "999999999",                # High integer
            "1",                        # Low integer (admin?)
            "../etc/passwd"             # Path traversal attempt
        ]
        
        for test_id in test_ids:
            # Construct test URL
            if "?" in base_url:
                test_url = re.sub(f"{param_name}=[^&]+", f"{param_name}={test_id}", base_url)
            else:
                test_url = f"{base_url}?{param_name}={test_id}"
                
            try:
                resp = self.session.get(test_url, headers=auth_headers, timeout=10, verify=False)
                
                # Indikator IDOR: Response 200 OK dengan data sensitif meskipun ID tidak valid
                if resp.status_code == 200 and len(resp.text) > 500:
                    # Cek apakah response berisi data yang terlihat seperti user data
                    sensitive_patterns = ["email", "password", "address", "phone", "credit_card", "ssn"]
                    content_lower = resp.text.lower()
                    
                    if any(p in content_lower for p in sensitive_patterns):
                        findings.append({
                            "type": "IDOR",
                            "url": test_url,
                            "param": param_name,
                            "test_id": test_id,
                            "severity": "HIGH",
                            "evidence": f"Access granted with invalid ID: {test_id}",
                            "remediation": "Implement proper authorization checks. Verify user ownership of the requested resource ID."
                        })
            except Exception as e:
                continue
                
        return findings

    def test_race_condition(self, url: str, payload: Dict, auth_headers: Dict, iterations: int = 10) -> Dict:
        """
        Test Race Condition dengan mengirim request simultan berulang kali
        Berguna untuk testing limit bypass, double spending, coupon reuse
        """
        import threading
        import time
        
        results = {"success_count": 0, "fail_count": 0, "errors": 0}
        lock = threading.Lock()
        
        def make_request():
            try:
                resp = self.session.post(url, json=payload, headers=auth_headers, timeout=10, verify=False)
                with lock:
                    if resp.status_code == 200:
                        results["success_count"] += 1
                    else:
                        results["fail_count"] += 1
            except:
                with lock:
                    results["errors"] += 1
        
        threads = []
        start_time = time.time()
        
        # Fire all requests nearly simultaneously
        for _ in range(iterations):
            t = threading.Thread(target=make_request)
            threads.append(t)
            
        for t in threads:
            t.start()
            
        for t in threads:
            t.join()
            
        elapsed = time.time() - start_time
        
        # Jika banyak request sukses dalam waktu singkat tanpa error rate limiting
        if results["success_count"] > iterations * 0.8 and elapsed < 2.0:
            return {
                "type": "RACE_CONDITION_RISK",
                "url": url,
                "severity": "MEDIUM",
                "details": f"{results['success_count']}/{iterations} requests succeeded in {elapsed:.2f}s",
                "remediation": "Implement locking mechanisms, idempotency keys, or rate limiting per user/session."
            }
            
        return {"type": "RACE_CONDITION_TEST", "status": "NO_ISSUE_DETECTED", "results": results}

class PIIScanner:
    def __init__(self):
        # Regex patterns untuk berbagai jenis PII
        self.patterns = {
            "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "PHONE_US": r"\b(?:\+?1[-.\s]?)?\(?(?:[2-9][0-9]{2})\)?[-.\s]?(?:[2-9][0-9]{2})[-.\s]?(?:[0-9]{4})\b",
            "SSN_US": r"\b\d{3}-\d{2}-\d{4}\b",
            "CREDIT_CARD": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
            "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "DATE_OF_BIRTH": r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b",
            "AWS_KEY": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"
        }
        
    def scan_response(self, url: str, response_text: str, headers: Dict = None) -> List[Dict]:
        """Scan response content untuk PII leakage"""
        findings = []
        
        for pii_type, pattern in self.patterns.items():
            matches = re.findall(pattern, response_text)
            if matches:
                # Filter false positives (contoh: IP address di URL tracking)
                unique_matches = list(set(matches))[:5] # Batasi jumlah sample
                
                severity = "CRITICAL" if pii_type in ["SSN_US", "CREDIT_CARD", "PRIVATE_KEY", "AWS_KEY"] else "HIGH"
                
                findings.append({
                    "type": "PII_LEAKAGE",
                    "url": url,
                    "data_type": pii_type,
                    "count": len(matches),
                    "samples": unique_matches, # Sample saja, jangan semua
                    "severity": severity,
                    "remediation": f"Remove or mask {pii_type} from API responses. Implement data minimization principles."
                })
                
        return findings
        
    def scan_endpoint(self, url: str, auth_headers: Dict = None) -> List[Dict]:
        """Fetch endpoint dan scan untuk PII"""
        findings = []
        headers = auth_headers or {}
        
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
                findings.extend(self.scan_response(url, resp.text, dict(resp.headers)))
        except Exception as e:
            pass
            
        return findings

def scan_business_logic(url: str, param: str, sample_id: str, token: str) -> List[Dict]:
    """Wrapper function untuk Business Logic Scan"""
    scanner = BusinessLogicScanner()
    headers = {"Authorization": f"Bearer {token}"}
    
    findings = []
    findings.extend(scanner.test_idor(url, param, sample_id, headers))
    # Race condition test butuh endpoint POST yang spesifik, skip di wrapper umum
    return findings

def scan_pii(url: str, token: str = None) -> List[Dict]:
    """Wrapper function untuk PII Scan"""
    scanner = PIIScanner()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return scanner.scan_endpoint(url, headers)

if __name__ == "__main__":
    # Example usage
    target_url = "https://api.example.com/users/123"
    # results = scan_business_logic(target_url, "id", "123", "your_token_here")
    # print(results)
