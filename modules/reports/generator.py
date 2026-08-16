"""
Report Generator Module
Generates professional PDF and HTML reports with executive and technical summaries
Includes compliance mapping for OWASP, CWE, PCI-DSS, and ISO 27001
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import json
import os
from jinja2 import Template


class ComplianceMapper:
    """Maps vulnerabilities to compliance standards"""
    
    # OWASP Top 10 2021 Mapping
    OWASP_MAPPING = {
        'SQL Injection': 'A03:2021-Injection',
        'XSS': 'A03:2021-Injection',
        'Command Injection': 'A03:2021-Injection',
        'Broken Authentication': 'A01:2021-Broken Access Control',
        'Sensitive Data Exposure': 'A02:2021-Cryptographic Failures',
        'XXE': 'A05:2021-Security Misconfiguration',
        'Broken Access Control': 'A01:2021-Broken Access Control',
        'Security Misconfiguration': 'A05:2021-Security Misconfiguration',
        'Outdated Components': 'A06:2021-Vulnerable and Outdated Components',
        'Insufficient Logging': 'A09:2021-Security Logging and Monitoring Failures',
        'SSRF': 'A10:2021-Server-Side Request Forgery',
        'Directory Traversal': 'A01:2021-Broken Access Control',
        'Missing Security Headers': 'A05:2021-Security Misconfiguration'
    }
    
    # CWE Mapping
    CWE_MAPPING = {
        'SQL Injection': 'CWE-89',
        'XSS': 'CWE-79',
        'Command Injection': 'CWE-78',
        'Broken Authentication': 'CWE-287',
        'Sensitive Data Exposure': 'CWE-311',
        'XXE': 'CWE-611',
        'Broken Access Control': 'CWE-284',
        'Security Misconfiguration': 'CWE-16',
        'Outdated Components': 'CWE-1104',
        'Insufficient Logging': 'CWE-778',
        'SSRF': 'CWE-918',
        'Directory Traversal': 'CWE-22',
        'Missing Security Headers': 'CWE-693'
    }
    
    # PCI-DSS Mapping
    PCI_DSS_MAPPING = {
        'SQL Injection': '6.5.1',
        'XSS': '6.5.7',
        'Command Injection': '6.5.1',
        'Broken Authentication': '8.2',
        'Sensitive Data Exposure': '3.4, 4.1',
        'XXE': '6.5.1',
        'Broken Access Control': '7.1',
        'Security Misconfiguration': '6.5.10',
        'Outdated Components': '6.2',
        'Insufficient Logging': '10.1',
        'SSRF': '6.5.1',
        'Directory Traversal': '7.1',
        'Missing Security Headers': '6.5.10'
    }
    
    # ISO 27001 Mapping
    ISO_MAPPING = {
        'SQL Injection': 'A.14.2.5',
        'XSS': 'A.14.2.5',
        'Command Injection': 'A.14.2.5',
        'Broken Authentication': 'A.9.2.1',
        'Sensitive Data Exposure': 'A.10.1.1',
        'XXE': 'A.14.2.5',
        'Broken Access Control': 'A.9.1.2',
        'Security Misconfiguration': 'A.12.6.1',
        'Outdated Components': 'A.12.6.1',
        'Insufficient Logging': 'A.12.4.1',
        'SSRF': 'A.14.2.5',
        'Directory Traversal': 'A.9.1.2',
        'Missing Security Headers': 'A.12.6.1'
    }
    
    @classmethod
    def get_compliance_tags(cls, vulnerability_name):
        """Get all compliance tags for a vulnerability"""
        tags = []
        
        vuln_lower = vulnerability_name.lower()
        
        for key, owasp_tag in cls.OWASP_MAPPING.items():
            if key.lower() in vuln_lower:
                tags.append({
                    'standard': 'OWASP Top 10 2021',
                    'tag': owasp_tag,
                    'name': key
                })
                break
        
        for key, cwe_tag in cls.CWE_MAPPING.items():
            if key.lower() in vuln_lower:
                tags.append({
                    'standard': 'CWE',
                    'tag': cwe_tag,
                    'name': key
                })
                break
        
        for key, pci_tag in cls.PCI_DSS_MAPPING.items():
            if key.lower() in vuln_lower:
                tags.append({
                    'standard': 'PCI-DSS',
                    'tag': pci_tag,
                    'name': key
                })
                break
        
        for key, iso_tag in cls.ISO_MAPPING.items():
            if key.lower() in vuln_lower:
                tags.append({
                    'standard': 'ISO 27001',
                    'tag': iso_tag,
                    'name': key
                })
                break
        
        return tags
    
    @classmethod
    def get_summary_by_standard(cls, vulnerabilities):
        """Get compliance summary grouped by standard"""
        summary = {
            'OWASP Top 10 2021': {},
            'CWE': {},
            'PCI-DSS': {},
            'ISO 27001': {}
        }
        
        for vuln in vulnerabilities:
            name = vuln.get('name', '')
            severity = vuln.get('cvss_severity', 'MEDIUM')
            
            tags = cls.get_compliance_tags(name)
            
            for tag in tags:
                standard = tag['standard']
                tag_name = tag['tag']
                
                if tag_name not in summary[standard]:
                    summary[standard][tag_name] = {
                        'count': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0,
                        'vulnerabilities': []
                    }
                
                summary[standard][tag_name]['count'] += 1
                summary[standard][tag_name]['vulnerabilities'].append(name)
                
                if severity.upper() == 'HIGH' or severity.upper() == 'CRITICAL':
                    summary[standard][tag_name]['high'] += 1
                elif severity.upper() == 'MEDIUM':
                    summary[standard][tag_name]['medium'] += 1
                else:
                    summary[standard][tag_name]['low'] += 1
        
        return summary


class ReportGenerator:
    """Generate professional PDF and HTML reports"""
    
    def __init__(self, scan_job):
        self.scan_job = scan_job
        self.styles = getSampleStyleSheet()
        self.setup_styles()
    
    def setup_styles(self):
        """Setup custom styles for reports"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#16213e'),
            spaceAfter=12,
            spaceBefore=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='NormalLeft',
            parent=self.styles['Normal'],
            alignment=TA_LEFT
        ))
    
    def generate_pdf_report(self, output_path, report_type='full'):
        """Generate PDF report"""
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        elements = []
        
        # Title
        elements.append(Paragraph("Vulnerability Assessment Report", self.styles['CustomTitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Meta information
        meta_data = [
            ['Target URL:', self.scan_job.target_url],
            ['Scan Date:', self.scan_job.started_at.strftime('%Y-%m-%d %H:%M:%S') if self.scan_job.started_at else 'N/A'],
            ['Status:', self.scan_job.status],
            ['Total Vulnerabilities:', str(self.scan_job.vulnerability_count)],
            ['Risk Score:', f"{self.scan_job.risk_score:.2f}"],
            ['Confidence Score:', f"{self.scan_job.confidence_score:.2f}"] if hasattr(self.scan_job, 'confidence_score') else ['Confidence Score:', 'N/A']
        ]
        
        meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#1a1a2e')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6'))
        ]))
        
        elements.append(meta_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        if report_type in ['full', 'executive']:
            elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
            elements.append(self._create_executive_summary())
            elements.append(Spacer(1, 0.2*inch))
        
        # Compliance Overview
        if report_type in ['full', 'compliance']:
            elements.append(Paragraph("Compliance Overview", self.styles['SectionHeader']))
            elements.append(self._create_compliance_summary())
            elements.append(Spacer(1, 0.2*inch))
            elements.append(PageBreak())
        
        # Technical Details
        if report_type in ['full', 'technical']:
            elements.append(Paragraph("Technical Findings", self.styles['SectionHeader']))
            elements.append(self._create_technical_findings())
            elements.append(Spacer(1, 0.2*inch))
        
        # Remediation Recommendations
        if report_type in ['full', 'technical']:
            elements.append(Paragraph("Remediation Recommendations", self.styles['SectionHeader']))
            elements.append(self._create_remediation_section())
        
        doc.build(elements)
        return output_path
    
    def _create_executive_summary(self):
        """Create executive summary section"""
        elements = []
        
        results = self.scan_job.results or {}
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            sev = vuln.get('cvss_severity', 'MEDIUM').upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        summary_text = f"""
        This report presents the findings of an automated security assessment conducted on 
        <b>{self.scan_job.target_url}</b>. The scan identified <b>{len(vulnerabilities)}</b> potential 
        vulnerabilities with a calculated risk score of <b>{self.scan_job.risk_score:.2f}/10</b>.
        </br></br>
        <b>Key Findings:</b>
        </br>• Critical Severity: {severity_counts['CRITICAL']}
        </br>• High Severity: {severity_counts['HIGH']}
        </br>• Medium Severity: {severity_counts['MEDIUM']}
        </br>• Low Severity: {severity_counts['LOW']}
        </br></br>
        Immediate attention is recommended for critical and high severity findings to mitigate 
        potential security risks.
        """
        
        elements.append(Paragraph(summary_text, self.styles['NormalLeft']))
        return elements[0] if elements else Paragraph("No summary available", self.styles['NormalLeft'])
    
    def _create_compliance_summary(self):
        """Create compliance mapping summary"""
        elements = []
        results = self.scan_job.results or {}
        vulnerabilities = results.get('vulnerabilities', [])
        
        compliance_summary = ComplianceMapper.get_summary_by_standard(vulnerabilities)
        
        # OWASP Summary Table
        elements.append(Paragraph("OWASP Top 10 2021 Compliance", self.styles['SectionHeader']))
        owasp_data = [['Category', 'Count', 'High', 'Medium', 'Low']]
        
        for cat, data in compliance_summary['OWASP Top 10 2021'].items():
            owasp_data.append([cat, str(data['count']), str(data['high']), str(data['medium']), str(data['low'])])
        
        if len(owasp_data) > 1:
            owasp_table = Table(owasp_data, colWidths=[2.5*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch])
            owasp_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa'))
            ]))
            elements.append(owasp_table)
        
        return elements
    
    def _create_technical_findings(self):
        """Create technical findings section"""
        elements = []
        results = self.scan_job.results or {}
        vulnerabilities = results.get('vulnerabilities', [])
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            vuln_title = f"{idx}. {vuln.get('name', 'Unknown')} [{vuln.get('cvss_severity', 'MEDIUM')}]"
            elements.append(Paragraph(vuln_title, self.styles['SectionHeader']))
            
            details = f"""
            <b>URL:</b> {vuln.get('url', 'N/A')}
            </br><b>Parameter:</b> {vuln.get('parameter', 'N/A')}
            </br><b>CVSS Score:</b> {vuln.get('cvss_score', 'N/A')}
            </br><b>Description:</b> {vuln.get('description', 'No description available')}
            </br><b>Evidence:</b> <i>{vuln.get('evidence', 'No evidence captured')}</i>
            </br><b>Confidence:</b> {vuln.get('confidence', 'Medium')}
            """
            
            # Add compliance tags
            compliance_tags = ComplianceMapper.get_compliance_tags(vuln.get('name', ''))
            if compliance_tags:
                tags_str = ', '.join([f"{t['standard']}: {t['tag']}" for t in compliance_tags[:3]])
                details += f"</br><b>Compliance:</b> {tags_str}"
            
            elements.append(Paragraph(details, self.styles['NormalLeft']))
            elements.append(Spacer(1, 0.15*inch))
        
        return elements
    
    def _create_remediation_section(self):
        """Create remediation recommendations section"""
        elements = []
        results = self.scan_job.results or {}
        vulnerabilities = results.get('vulnerabilities', [])
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            remediation = vuln.get('remediation', {})
            
            if remediation:
                rem_title = f"Remediation for #{idx}: {vuln.get('name', 'Unknown')}"
                elements.append(Paragraph(rem_title, self.styles['SectionHeader']))
                
                steps = remediation.get('steps', [])
                for step in steps:
                    step_text = f"• {step}"
                    elements.append(Paragraph(step_text, self.styles['NormalLeft']))
                
                code_fix = remediation.get('code_example', {})
                if code_fix:
                    elements.append(Spacer(1, 0.1*inch))
                    elements.append(Paragraph("<b>Code Example:</b>", self.styles['NormalLeft']))
                    for lang, code in code_fix.items():
                        elements.append(Paragraph(f"<i>{lang.title()}:</i>", self.styles['NormalLeft']))
                        # Note: Code blocks need special handling in reportlab
                        elements.append(Paragraph(code[:200] + "..." if len(code) > 200 else code, self.styles['NormalLeft']))
                
                elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def generate_html_report(self, output_path, report_type='full'):
        """Generate HTML report using Jinja2"""
        results = self.scan_job.results or {}
        vulnerabilities = results.get('vulnerabilities', [])
        
        compliance_summary = ComplianceMapper.get_summary_by_standard(vulnerabilities)
        
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f6fa; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #1a1a2e; text-align: center; }
        h2 { color: #16213e; border-bottom: 2px solid #0f3460; padding-bottom: 10px; }
        .meta-info { background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }
        .meta-info table { width: 100%; }
        .meta-info td { padding: 8px; }
        .severity-badge { display: inline-block; padding: 4px 12px; border-radius: 15px; color: white; font-weight: bold; }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #000; }
        .low { background: #28a745; }
        .vuln-card { border: 1px solid #dee2e6; border-radius: 5px; padding: 20px; margin-bottom: 20px; }
        .compliance-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .compliance-table th, .compliance-table td { border: 1px solid #dee2e6; padding: 10px; text-align: left; }
        .compliance-table th { background: #16213e; color: white; }
        .remediation-step { background: #e8f5e9; padding: 10px; margin: 5px 0; border-left: 4px solid #28a745; }
        .code-block { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Vulnerability Assessment Report</h1>
        
        <div class="meta-info">
            <table>
                <tr><td><strong>Target URL:</strong></td><td>{{ scan.target_url }}</td></tr>
                <tr><td><strong>Scan Date:</strong></td><td>{{ scan.started_at }}</td></tr>
                <tr><td><strong>Status:</strong></td><td>{{ scan.status }}</td></tr>
                <tr><td><strong>Total Vulnerabilities:</strong></td><td>{{ scan.vulnerability_count }}</td></tr>
                <tr><td><strong>Risk Score:</strong></td><td>{{ "%.2f"|format(scan.risk_score) }}/10</td></tr>
                {% if scan.confidence_score %}
                <tr><td><strong>Confidence Score:</strong></td><td>{{ "%.2f"|format(scan.confidence_score) }}%</td></tr>
                {% endif %}
            </table>
        </div>
        
        {% if report_type in ['full', 'executive'] %}
        <h2>📊 Executive Summary</h2>
        <p>This report presents the findings of an automated security assessment conducted on <strong>{{ scan.target_url }}</strong>. The scan identified <strong>{{ vulnerabilities|length }}</strong> potential vulnerabilities.</p>
        
        <h3>Severity Distribution:</h3>
        <ul>
            <li><span class="severity-badge critical">CRITICAL</span>: {{ severity_counts.CRITICAL }}</li>
            <li><span class="severity-badge high">HIGH</span>: {{ severity_counts.HIGH }}</li>
            <li><span class="severity-badge medium">MEDIUM</span>: {{ severity_counts.MEDIUM }}</li>
            <li><span class="severity-badge low">LOW</span>: {{ severity_counts.LOW }}</li>
        </ul>
        {% endif %}
        
        {% if report_type in ['full', 'compliance'] %}
        <h2>🛡️ Compliance Overview</h2>
        <h3>OWASP Top 10 2021</h3>
        <table class="compliance-table">
            <thead>
                <tr><th>Category</th><th>Count</th><th>High</th><th>Medium</th><th>Low</th></tr>
            </thead>
            <tbody>
                {% for cat, data in compliance_summary['OWASP Top 10 2021'].items() %}
                <tr>
                    <td>{{ cat }}</td>
                    <td>{{ data.count }}</td>
                    <td>{{ data.high }}</td>
                    <td>{{ data.medium }}</td>
                    <td>{{ data.low }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
        
        {% if report_type in ['full', 'technical'] %}
        <h2>🔬 Technical Findings</h2>
        {% for vuln in vulnerabilities %}
        <div class="vuln-card">
            <h3>{{ loop.index }}. {{ vuln.name }} <span class="severity-badge {{ vuln.cvss_severity|lower }}">{{ vuln.cvss_severity }}</span></h3>
            <p><strong>URL:</strong> {{ vuln.url }}</p>
            <p><strong>Parameter:</strong> {{ vuln.parameter }}</p>
            <p><strong>CVSS Score:</strong> {{ vuln.cvss_score }}</p>
            <p><strong>Description:</strong> {{ vuln.description }}</p>
            <p><strong>Evidence:</strong> <em>{{ vuln.evidence }}</em></p>
            <p><strong>Confidence:</strong> {{ vuln.confidence }}</p>
            
            {% if vuln.compliance_tags %}
            <p><strong>Compliance Tags:</strong> 
                {% for tag in vuln.compliance_tags[:3] %}
                <span style="background: #e9ecef; padding: 2px 8px; border-radius: 3px; margin-right: 5px;">{{ tag.standard }}: {{ tag.tag }}</span>
                {% endfor %}
            </p>
            {% endif %}
            
            {% if vuln.remediation %}
            <h4>💡 How to Fix:</h4>
            {% for step in vuln.remediation.steps %}
            <div class="remediation-step">{{ step }}</div>
            {% endfor %}
            
            {% if vuln.remediation.code_example %}
            <p><strong>Code Example:</strong></p>
            {% for lang, code in vuln.remediation.code_example.items() %}
            <p><em>{{ lang|title }}:</em></p>
            <div class="code-block">{{ code }}</div>
            {% endfor %}
            {% endif %}
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}
    </div>
</body>
</html>
        """
        
        # Prepare context
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            sev = vuln.get('cvss_severity', 'MEDIUM').upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        context = {
            'scan': {
                'target_url': self.scan_job.target_url,
                'started_at': self.scan_job.started_at.strftime('%Y-%m-%d %H:%M:%S') if self.scan_job.started_at else 'N/A',
                'status': self.scan_job.status,
                'vulnerability_count': self.scan_job.vulnerability_count,
                'risk_score': self.scan_job.risk_score,
                'confidence_score': getattr(self.scan_job, 'confidence_score', None)
            },
            'vulnerabilities': vulnerabilities,
            'severity_counts': severity_counts,
            'compliance_summary': compliance_summary,
            'report_type': report_type
        }
        
        template = Template(template_str)
        html_content = template.render(context)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
