"""
Risk Analyzer Module
Menganalisis hasil scanning dan memberikan penjelasan detail tentang:
- Apa kerentanannya?
- Bagaimana cara kerjanya?
- Apa risiko/dampaknya bagi bisnis dan teknis?
- Contoh skenario serangan nyata
- Prioritas perbaikan
"""

import json
from typing import Dict, List, Any
from dataclasses import dataclass, asdict

@dataclass
class RiskDetail:
    vulnerability_name: str
    category: str
    description: str
    technical_explanation: str
    business_impact: str
    attack_scenario: str
    affected_assets: List[str]
    cvss_score: float
    severity: str
    remediation_summary: str
    references: List[str]

class RiskAnalyzer:
    """
    Modul untuk enriching hasil scan dengan penjelasan risiko mendalam.
    Mengubah data teknis menjadi insight yang bisa dipahami manajemen & tim teknis.
    """
    
    # Database pengetahuan kerentanan (bisa diperluas atau diambil dari API eksternal)
    VULN_KNOWLEDGE_BASE = {
        "SQL Injection": {
            "category": "Injection",
            "technical_explanation": "Penyerang menyisipkan query SQL berbahaya melalui input user yang tidak divalidasi, memungkinkan manipulasi database backend.",
            "business_impact": "Pencurian data sensitif (user, password, kartu kredit), penghapusan data seluruhnya, atau pengambilan alih server database.",
            "attack_scenario": "Penyerang memasukkan `' OR '1'='1` pada form login, berhasil masuk tanpa password sebagai admin.",
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "CWE-89"]
        },
        "Cross-Site Scripting (XSS)": {
            "category": "Injection",
            "technical_explanation": "Skrip malicious disuntikkan ke halaman web yang dipercaya dan dieksekusi di browser korban.",
            "business_impact": "Pencurian session cookie, redirect ke situs phishing, defacement website, penyebaran malware ke pengunjung.",
            "attack_scenario": "Penyerang memposting komentar berisi `<script>stealCookie()</script>`. Saat admin membaca komentar, session admin dicuri.",
            "references": ["https://owasp.org/www-community/attacks/xss/", "CWE-79"]
        },
        "Broken Object Level Authorization (BOLA)": {
            "category": "API Security",
            "technical_explanation": "API tidak memvalidasi apakah user yang meminta akses ke objek (misal: ID user lain) memiliki izin yang sah.",
            "business_impact": "Akses data pribadi user lain secara massal, pelanggaran privasi berat (GDPR violation).",
            "attack_scenario": "User A mengubah ID pada URL/API dari `/api/user/100` menjadi `/api/user/101` dan berhasil melihat data User B.",
            "references": ["https://owasp.org/www-project-api-security/", "OWASP API1:2023"]
        },
        "Sensitive Data Exposure": {
            "category": "Data Protection",
            "technical_explanation": "Data sensitif (password, kunci API, PII) disimpan atau ditransmisikan tanpa enkripsi yang kuat.",
            "business_impact": "Kebocoran data massal, denda regulasi (GDPR/UU PDP), hilangnya kepercayaan pelanggan.",
            "attack_scenario": "Penyerang melakukan sniffing jaringan dan membaca password yang dikirim dalam plain text HTTP.",
            "references": ["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure", "CWE-311"]
        },
        "PII Leakage": {
            "category": "Privacy Compliance",
            "technical_explanation": "Informasi Identifikasi Pribadi (Email, No KTP, No HP) terpapar di source code, response API, atau file log.",
            "business_impact": "Pelanggaran undang-undang privasi, potensi penipuan identitas terhadap korban, denda hukum.",
            "attack_scenario": "Scanner menemukan file JSON publik yang berisi 10.000 record NIK dan nama penduduk.",
            "references": ["GDPR Article 33", "UU PDP Indonesia"]
        },
        "IDOR (Insecure Direct Object Reference)": {
            "category": "Access Control",
            "technical_explanation": "Mirip BOLA, aplikasi memberikan akses langsung ke objek internal menggunakan input dari user tanpa validasi otorisasi.",
            "business_impact": "Akses unauthorized ke dokumen, transaksi, atau akun user lain.",
            "attack_scenario": "Mengubah parameter `invoice_id=500` menjadi `invoice_id=501` untuk melihat tagihan orang lain.",
            "references": ["CWE-639", "OWASP Top 10 2021 - A01"]
        },
        "Security Misconfiguration": {
            "category": "Configuration",
            "technical_explanation": "Pengaturan keamanan default tidak diubah, fitur tidak perlu diaktifkan, atau pesan error terlalu verbose.",
            "business_impact": "Memberikan peta jalan bagi penyerang untuk eksploitasi lebih lanjut, kebocoran info sistem.",
            "attack_scenario": "Halaman error menampilkan stack trace lengkap yang mengungkap struktur database dan versi framework.",
            "references": ["OWASP Top 10 2021 - A05", "CWE-16"]
        },
        "Race Condition": {
            "category": "Logic Flaw",
            "technical_explanation": "Sistem tidak menangani eksekusi simultan dengan benar, memungkinkan manipulasi state aplikasi.",
            "business_impact": "Penyalahgunaan fitur finansial (double spending), bypass limitasi kuota, manipulasi stok.",
            "attack_scenario": "Mengirim 50 request transfer dana secara bersamaan dalam milidetik yang sama untuk menarik saldo lebih dari yang dimiliki.",
            "references": ["CWE-362", "OWASP Testing Guide"]
        }
    }

    def get_severity_label(self, score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        elif score >= 7.0: return "HIGH"
        elif score >= 4.0: return "MEDIUM"
        elif score > 0.0: return "LOW"
        else: return "INFO"

    def analyze(self, scan_results: List[Dict[str, Any]]) -> List[RiskDetail]:
        """
        Mengambil hasil mentah dari scanner dan melengkapinya dengan analisis risiko mendalam.
        """
        detailed_report = []

        for vuln in scan_results:
            vuln_name = vuln.get('vulnerability', vuln.get('type', 'Unknown'))
            
            # Cari knowledge base, jika tidak ada buat default
            kb_entry = self.VULN_KNOWLEDGE_BASE.get(vuln_name, {})
            
            # Jika tidak ada di KB, generate penjelasan generik berdasarkan kategori
            if not kb_entry:
                kb_entry = {
                    "category": vuln.get('category', 'General'),
                    "technical_explanation": f"Kerentanan tipe {vuln_name} terdeteksi. Perlu investigasi manual.",
                    "business_impact": "Potensi kompromi keamanan sistem tergantung konteks implementasi.",
                    "attack_scenario": "Penyerang mungkin memanfaatkan celah ini untuk akses tidak sah.",
                    "references": ["https://cwe.mitre.org/"]
                }

            detail = RiskDetail(
                vulnerability_name=vuln_name,
                category=kb_entry.get('category', 'Unknown'),
                description=vuln.get('description', 'Tidak ada deskripsi'),
                technical_explanation=kb_entry.get('technical_explanation', 'Perlu analisis manual'),
                business_impact=kb_entry.get('business_impact', 'Dampak bisnis belum terdefinisi'),
                attack_scenario=kb_entry.get('attack_scenario', 'Skenario belum tersedia'),
                affected_assets=[vuln.get('url', vuln.get('endpoint', 'System'))],
                cvss_score=vuln.get('cvss_score', 5.0),
                severity=self.get_severity_label(vuln.get('cvss_score', 5.0)),
                remediation_summary=vuln.get('remediation', 'Lakukan validasi input dan patch sistem'),
                references=kb_entry.get('references', [])
            )
            detailed_report.append(detail)

        # Urutkan berdasarkan severity (Critical dulu)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        detailed_report.sort(key=lambda x: severity_order.get(x.severity, 5))

        return detailed_report

    def generate_executive_summary(self, risks: List[RiskDetail]) -> str:
        """
        Membuat ringkasan eksekutif untuk manajemen non-teknis.
        """
        total = len(risks)
        critical = sum(1 for r in risks if r.severity == "CRITICAL")
        high = sum(1 for r in risks if r.severity == "HIGH")
        
        summary = f"""
=== LAPORAN RISIKO KEAMANAN (EXECUTIVE SUMMARY) ===

Total Kerentanan Ditemukan: {total}
- Critical: {critical}
- High: {high}

TINGKAT RISIKO Keseluruhan: {'KRITIS - SEGERA AKSI' if critical > 0 else 'TINGGI - PERLU PERBAIKAN' if high > 0 else 'SEDANG'}

FOKUS UTAMA:
"""
        if critical > 0 or high > 0:
            top_risks = [r for r in risks if r.severity in ["CRITICAL", "HIGH"]][:3]
            for i, risk in enumerate(top_risks, 1):
                summary += f"\n{i}. {risk.vulnerability_name} ({risk.severity})\n"
                summary += f"   Dampak Bisnis: {risk.business_impact}\n"
                summary += f"   Skenario Serangan: {risk.attack_scenario}\n"
        else:
            summary += "\nTidak ada risiko kritis mendesak. Lanjutkan pemantauan rutin."

        summary += "\n\nREKOMENDASI TINDAKAN:\n"
        summary += "1. Segera perbaiki semua temuan Critical dalam 24 jam.\n"
        summary += "2. Jadwalkan perbaikan temuan High dalam 1 minggu.\n"
        summary += "3. Lakukan review kode untuk mencegah kerentanan serupa di masa depan."
        
        return summary

    def export_detailed_json(self, risks: List[RiskDetail]) -> str:
        """Export hasil analisis ke format JSON lengkap."""
        return json.dumps([asdict(r) for r in risks], indent=2)

# Helper function untuk penggunaan cepat
def analyze_risks(scan_results: List[Dict]) -> Dict[str, Any]:
    analyzer = RiskAnalyzer()
    detailed_risks = analyzer.analyze(scan_results)
    summary = analyzer.generate_executive_summary(detailed_risks)
    
    return {
        "detailed_findings": [asdict(r) for r in detailed_risks],
        "executive_summary": summary,
        "total_vulnerabilities": len(detailed_risks),
        "critical_count": sum(1 for r in detailed_risks if r.severity == "CRITICAL"),
        "high_count": sum(1 for r in detailed_risks if r.severity == "HIGH")
    }

if __name__ == "__main__":
    # Simulasi hasil scan dari modul lain
    mock_scan_data = [
        {
            "vulnerability": "SQL Injection",
            "description": "Parameter 'id' rentan terhadap SQL Injection.",
            "url": "https://example.com/product?id=1",
            "cvss_score": 9.8
        },
        {
            "vulnerability": "PII Leakage",
            "description": "Email user ditemukan di response JSON.",
            "url": "https://api.example.com/users/list",
            "cvss_score": 7.5
        },
        {
            "vulnerability": "Race Condition",
            "description": "Endpoint transfer memungkinkan request simultan.",
            "url": "https://bank.example.com/transfer",
            "cvss_score": 8.2
        }
    ]

    print("🔍 Menganalisis Risiko...")
    result = analyze_risks(mock_scan_data)
    
    print("\n" + "="*50)
    print(result['executive_summary'])
    print("\n" + "="*50)
    print(f"\n✅ Analisis Selesai. Total {result['total_vulnerabilities']} temuan dianalisis.")
    print("💡 Detail lengkap tersedia dalam objek 'detailed_findings'.")
