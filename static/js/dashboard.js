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
    const externalScanners = document.getElementById('externalScanners').value;
    
    // Map external scanner selection to boolean or specific scanners
    const useExternalScanners = externalScanners !== 'none';
    
    try {
        const response = await fetch('/api/scan/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: targetUrl,
                mode: scanMode,
                use_external_scanners: useExternalScanners,
                external_scanner_type: externalScanners
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentJobId = data.job_id;
            showProgress();
            
            // Subscribe to WebSocket updates for this scan
            if (socket) {
                socket.emit('subscribe_scan', { job_id: data.job_id });
            }
            
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
    
    // Update realtime log if available
    if (data.log_entry) {
        addLogEntry(data.log_entry);
    }
}

// Add log entry to realtime log
function addLogEntry(logEntry) {
    const logDiv = document.getElementById('realtimeLog');
    const logContent = document.getElementById('logContent');
    
    if (!logDiv || !logContent) return;
    
    // Show the log section
    logDiv.classList.remove('hidden');
    
    // Create log entry element
    const entryDiv = document.createElement('div');
    entryDiv.className = 'log-entry';
    
    const timestamp = logEntry.timestamp ? new Date(logEntry.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
    const level = logEntry.level || 'info';
    const message = logEntry.message || logEntry.activity || 'Processing...';
    
    entryDiv.innerHTML = `
        <span class="log-timestamp">[${timestamp}]</span>
        <span class="log-${level}">${message}</span>
    `;
    
    logContent.appendChild(entryDiv);
    
    // Auto-scroll to bottom
    logContent.scrollTop = logContent.scrollHeight;
    
    // Keep only last 50 entries to avoid performance issues
    while (logContent.children.length > 50) {
        logContent.removeChild(logContent.firstChild);
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
                
                // Process realtime log entries if available
                if (data.realtime_log && Array.isArray(data.realtime_log)) {
                    // Only show the latest entries that haven't been shown yet
                    data.realtime_log.slice(-5).forEach(logEntry => {
                        addLogEntry(logEntry);
                    });
                }
                
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
    
    // Add compliance and validation summary
    const complianceTags = results.compliance_tags || [];
    const validationStatus = results.validation_status || 'pending';
    const confidenceScore = results.confidence_score || 0;
    
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
                <div class="summary-item">
                    <strong>Validation Status:</strong>
                    <span class="badge badge-${validationStatus === 'validated' ? 'success' : validationStatus === 'false_positive' ? 'error' : 'info'}">
                        ${validationStatus === 'validated' ? '✓ Validated' : validationStatus === 'false_positive' ? '⚠ False Positive' : 'Pending'}
                    </span>
                </div>
                <div class="summary-item">
                    <strong>Confidence Score:</strong>
                    <span>${confidenceScore}%</span>
                </div>
            </div>
            ${complianceTags.length > 0 ? `
            <div class="compliance-section">
                <strong>Compliance Standards:</strong>
                <div class="compliance-badges">
                    ${complianceTags.map(tag => `<span class="badge badge-compliance">${tag}</span>`).join('')}
                </div>
            </div>
            ` : ''}
        </div>
        
        <h4>Vulnerabilities Found</h4>
        <div class="vulnerabilities-list">
    `;
    
    if (results.vulnerabilities && results.vulnerabilities.length > 0) {
        results.vulnerabilities.forEach((vuln, index) => {
            const isFalsePositive = vuln.false_positive || false;
            
            html += `
                <div class="vulnerability-card ${isFalsePositive ? 'false-positive' : ''}">
                    <div class="vuln-header">
                        <h5>${index + 1}. ${vuln.name}</h5>
                        <div class="badges-group">
                            <span class="badge badge-${getSeverityBadge(vuln.cvss_severity)}">
                                ${vuln.cvss_severity || 'MEDIUM'}
                            </span>
                            ${isFalsePositive ? '<span class="badge badge-error">⚠ False Positive</span>' : ''}
                        </div>
                    </div>
                    <div class="vuln-details">
                        <p><strong>URL:</strong> <code>${vuln.url || 'N/A'}</code></p>
                        <p><strong>Parameter:</strong> ${vuln.parameter || 'N/A'}</p>
                        <p><strong>CVSS Score:</strong> ${vuln.cvss_score || 'N/A'}</p>
                        <p><strong>Description:</strong> ${vuln.description || 'No description'}</p>
                        <p><strong>Impact:</strong> ${vuln.impact || 'No impact information'}</p>
                        ${vuln.compliance_tags && vuln.compliance_tags.length > 0 ? `
                        <p><strong>Compliance:</strong> 
                            ${vuln.compliance_tags.map(tag => `<span class="badge badge-compliance">${tag}</span>`).join('')}
                        </p>
                        ` : ''}
                        
                        ${vuln.remediation ? `
                        <details open>
                            <summary><strong>✅ How to Fix</strong></summary>
                            <div class="remediation">${formatRemediation(vuln.remediation)}</div>
                        </details>
                        ` : ''}
                        
                        ${vuln.safe_poc ? `
                        <details>
                            <summary><strong>🔬 Safe Proof of Concept (PoC)</strong></summary>
                            <div class="poc-section">
                                <p><strong>Purpose:</strong> ${vuln.poc_purpose || 'Verification only - safe payload'}</p>
                                <p><strong>Impact:</strong> ${vuln.poc_impact || 'Demonstrates vulnerability without causing harm'}</p>
                                <pre><code>${escapeHtml(vuln.safe_poc)}</code></pre>
                                <p class="warning-note">⚠️ <em>Only use on systems you own or have explicit permission to test.</em></p>
                            </div>
                        </details>
                        ` : ''}
                        
                        ${vuln.exploitation ? `
                        <details>
                            <summary><strong>⚠️ Exploitation Example (Educational Only)</strong></summary>
                            <div class="exploitation-section">
                                <p><strong>Warning:</strong> This is for educational purposes to understand the attack vector.</p>
                                <pre><code>${escapeHtml(vuln.exploitation)}</code></pre>
                                <p class="warning-note">🔒 <em>Never use this on unauthorized systems. Illegal activity will be prosecuted.</em></p>
                            </div>
                        </details>
                        ` : ''}
                        
                        ${!isFalsePositive ? `
                        <div class="actions">
                            <button class="btn btn-small btn-warning" onclick="markFalsePositive('${results.id}', ${index}, 'User marked as false positive')">
                                ⚠ Mark as False Positive
                            </button>
                        </div>
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

// Add CSS styles for PoC and Exploitation sections dynamically
const style = document.createElement('style');
style.textContent = `
    .poc-section, .exploitation-section {
        background: #f8f9fa;
        border-left: 4px solid #17a2b8;
        padding: 15px;
        margin: 10px 0;
        border-radius: 4px;
    }
    
    .exploitation-section {
        border-left-color: #dc3545;
        background: #fff5f5;
    }
    
    .warning-note {
        color: #856404;
        font-style: italic;
        margin-top: 10px;
        padding: 8px;
        background: #fff3cd;
        border-radius: 4px;
    }
    
    .remediation {
        background: #d4edda;
        border-left: 4px solid #28a745;
        padding: 15px;
        margin: 10px 0;
        border-radius: 4px;
    }
    
    details > summary {
        cursor: pointer;
        padding: 8px;
        background: #e9ecef;
        border-radius: 4px;
        margin: 5px 0;
    }
    
    details[open] > summary {
        background: #dee2e6;
        margin-bottom: 10px;
    }
    
    .compliance-section {
        margin-top: 15px;
        padding: 10px;
        background: #f8f9fa;
        border-radius: 4px;
    }
    
    .compliance-badges {
        display: flex;
        gap: 5px;
        flex-wrap: wrap;
        margin-top: 8px;
    }
    
    .badge-compliance {
        background: #6f42c1;
        color: white;
        padding: 3px 8px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    .badges-group {
        display: flex;
        gap: 8px;
        align-items: center;
    }
    
    .vulnerability-card.false-positive {
        opacity: 0.6;
        background: #f8f9fa;
    }
    
    .actions {
        margin-top: 15px;
        padding-top: 15px;
        border-top: 1px solid #dee2e6;
    }
`;
document.head.appendChild(style);

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

// Generate report function
async function generateReport(jobId, formatType) {
    try {
        const response = await fetch(`/api/report/${jobId}?format=${formatType}`, {
            method: 'GET'
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            if (formatType === 'html') {
                window.open(data.view_url, '_blank');
                showNotification('HTML report generated successfully!', 'success');
            } else {
                // For PDF, create download link
                const link = document.createElement('a');
                link.href = data.download_url;
                link.download = `report_${jobId}.pdf`;
                link.click();
                showNotification('PDF report generated successfully!', 'success');
            }
        } else {
            showNotification(`Error generating report: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        console.error('Error generating report:', error);
        showNotification('Failed to generate report', 'error');
    }
}

// Mark vulnerability as false positive
async function markFalsePositive(jobId, vulnIndex, reason) {
    try {
        const response = await fetch('/api/mark-false-positive', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                job_id: jobId,
                vuln_index: vulnIndex,
                reason: reason || 'User marked as false positive'
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            showNotification('Vulnerability marked as false positive', 'success');
            // Refresh results to show updated status
            viewResults(jobId);
        } else {
            showNotification(`Error: ${data.error || 'Failed to mark as false positive'}`, 'error');
        }
    } catch (error) {
        console.error('Error marking false positive:', error);
        showNotification('Failed to mark as false positive', 'error');
    }
}

// Auto-refresh running scans every 30 seconds
setInterval(async () => {
    const monitorButtons = document.querySelectorAll('.btn-monitor');
    monitorButtons.forEach(btn => {
        // Could implement auto-refresh for running scans here
    });
}, 30000);
