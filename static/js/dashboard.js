// Dashboard JavaScript for Vulnerability Scanner

let socket = null;
let currentJobId = null;

// Initialize WebSocket connection
function initWebSocket() {
    socket = io();
    
    socket.on('connect', () => {
        console.log('Connected to WebSocket');
    });
    
    socket.on('disconnect', () => {
        console.log('Disconnected from WebSocket');
    });
    
    socket.on('scan_progress', (data) => {
        updateProgress(data);
    });
}

// Handle scan form submission
document.getElementById('scanForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const targetUrl = document.getElementById('targetUrl').value;
    const scanMode = document.getElementById('scanMode').value;
    
    try {
        const response = await fetch('/api/scan/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: targetUrl,
                mode: scanMode
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentJobId = data.job_id;
            showProgress();
            monitorScan(data.job_id);
        } else {
            alert('Error starting scan: ' + data.error);
        }
    } catch (error) {
        alert('Failed to start scan: ' + error.message);
    }
});

// Show progress bar
function showProgress() {
    const progressDiv = document.getElementById('scanProgress');
    progressDiv.classList.remove('hidden');
    document.getElementById('progressFill').style.width = '0%';
    document.getElementById('progressText').textContent = 'Initializing scan...';
}

// Update progress
function updateProgress(data) {
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    
    if (progressFill && data.percentage !== undefined) {
        progressFill.style.width = data.percentage + '%';
    }
    
    if (progressText && data.activity) {
        progressText.textContent = data.activity;
    }
}

// Monitor scan status
async function monitorScan(jobId) {
    currentJobId = jobId;
    
    const pollStatus = async () => {
        try {
            const response = await fetch(`/api/scan/status/${jobId}`);
            const data = await response.json();
            
            if (response.ok) {
                // Update progress
                updateProgress({
                    percentage: data.progress,
                    activity: data.current_activity || 'Scanning...'
                });
                
                // Check if completed
                if (data.status === 'COMPLETED') {
                    setTimeout(() => location.reload(), 1000);
                } else if (data.status === 'FAILED') {
                    alert('Scan failed: ' + data.error_message);
                    document.getElementById('scanProgress').classList.add('hidden');
                } else {
                    // Continue polling
                    setTimeout(pollStatus, 2000);
                }
            }
        } catch (error) {
            console.error('Error polling status:', error);
            setTimeout(pollStatus, 3000);
        }
    };
    
    pollStatus();
}

// View scan results
async function viewResults(jobId) {
    try {
        const response = await fetch(`/api/scan/results/${jobId}`);
        const data = await response.json();
        
        if (response.ok) {
            displayResults(data);
            document.getElementById('resultsModal').classList.remove('hidden');
        } else {
            alert('Error loading results: ' + data.error);
        }
    } catch (error) {
        alert('Failed to load results: ' + error.message);
    }
}

// Display results in modal
function displayResults(results) {
    const modalBody = document.getElementById('modalBody');
    
    let html = `
        <div class="results-summary">
            <h4>Scan Summary</h4>
            <div class="summary-grid">
                <div class="summary-item">
                    <strong>Total Vulnerabilities:</strong>
                    <span>${results.vulnerabilities?.length || 0}</span>
                </div>
                <div class="summary-item">
                    <strong>Risk Score:</strong>
                    <span class="risk-score risk-${getRiskClass(results.overall_risk_score)}">
                        ${results.overall_risk_score || 0}/10
                    </span>
                </div>
            </div>
        </div>
        
        <h4>Vulnerabilities Found</h4>
        <div class="vulnerabilities-list">
    `;
    
    if (results.vulnerabilities && results.vulnerabilities.length > 0) {
        results.vulnerabilities.forEach((vuln, index) => {
            html += `
                <div class="vulnerability-card">
                    <div class="vuln-header">
                        <h5>${index + 1}. ${vuln.name}</h5>
                        <span class="badge badge-${getSeverityBadge(vuln.cvss_severity)}">
                            ${vuln.cvss_severity || 'MEDIUM'}
                        </span>
                    </div>
                    <div class="vuln-details">
                        <p><strong>URL:</strong> <code>${vuln.url || 'N/A'}</code></p>
                        <p><strong>Parameter:</strong> ${vuln.parameter || 'N/A'}</p>
                        <p><strong>CVSS Score:</strong> ${vuln.cvss_score || 'N/A'}</p>
                        <p><strong>Description:</strong> ${vuln.description || 'No description'}</p>
                        <p><strong>Impact:</strong> ${vuln.impact || 'No impact information'}</p>
                        
                        ${vuln.exploitation ? `
                        <details>
                            <summary><strong>⚠️ How to Exploit (Educational Purpose Only)</strong></summary>
                            <pre><code>${escapeHtml(vuln.exploitation)}</code></pre>
                        </details>
                        ` : ''}
                        
                        ${vuln.remediation ? `
                        <details open>
                            <summary><strong>✅ How to Fix</strong></summary>
                            <div class="remediation">${formatRemediation(vuln.remediation)}</div>
                        </details>
                        ` : ''}
                        
                        ${vuln.references && vuln.references.length > 0 ? `
                        <div class="references">
                            <strong>References:</strong>
                            <ul>
                                ${vuln.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('')}
                            </ul>
                        </div>
                        ` : ''}
                    </div>
                </div>
            `;
        });
    } else {
        html += '<p class="text-center">No vulnerabilities found! 🎉</p>';
    }
    
    html += '</div>';
    modalBody.innerHTML = html;
}

// Get risk class for CSS
function getRiskClass(score) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
}

// Get severity badge class
function getSeverityBadge(severity) {
    switch (severity) {
        case 'CRITICAL': return 'error';
        case 'HIGH': return 'warning';
        case 'MEDIUM': return 'warning';
        default: return 'success';
    }
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Format remediation text
function formatRemediation(remediation) {
    if (typeof remediation === 'object') {
        let html = '';
        if (remediation.description) {
            html += `<p>${remediation.description}</p>`;
        }
        if (remediation.code_examples) {
            html += '<h6>Code Examples:</h6>';
            Object.entries(remediation.code_examples).forEach(([lang, code]) => {
                html += `<pre><code class="language-${lang}">${escapeHtml(code)}</code></pre>`;
            });
        }
        return html;
    }
    return `<p>${remediation}</p>`;
}

// Close modal
function closeModal() {
    document.getElementById('resultsModal').classList.add('hidden');
}

// Close modal when clicking outside
document.addEventListener('click', (e) => {
    const modal = document.getElementById('resultsModal');
    if (e.target === modal) {
        closeModal();
    }
});

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    
    // Check if there are no scans
    const tableBody = document.getElementById('scansTableBody');
    if (tableBody && tableBody.children.length === 0) {
        document.getElementById('noScans').classList.remove('hidden');
    }
});

// Auto-refresh running scans every 30 seconds
setInterval(async () => {
    const monitorButtons = document.querySelectorAll('.btn-monitor');
    monitorButtons.forEach(btn => {
        // Could implement auto-refresh for running scans here
    });
}, 30000);
