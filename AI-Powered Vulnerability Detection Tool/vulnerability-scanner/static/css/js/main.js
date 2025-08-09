document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scan-form');
    const loadingDiv = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');
    const vulnerabilitiesDiv = document.getElementById('vulnerabilities');
    const aiSummaryDiv = document.getElementById('ai-summary');
    const viewReportBtn = document.getElementById('view-report');
    
    let currentScanId = null;
    
    scanForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const url = document.getElementById('url').value.trim();
        if (!url) {
            alert('Please enter a valid URL');
            return;
        }
        
        // Show loading
        scanForm.style.display = 'none';
        loadingDiv.classList.remove('hidden');
        resultsDiv.classList.add('hidden');
        
        
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `url=${encodeURIComponent(url)}`
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            
            currentScanId = data.scan_id;
            
            // Display AI summary
            const aiAnalysis = data.ai_analysis;
            aiSummaryDiv.innerHTML = `
                <div class="ai-summary-card">
                    <h4>AI Analysis</h4>
                    <p><strong>Risk Level:</strong> <span class="risk ${aiAnalysis.risk_level}">${aiAnalysis.risk_level.toUpperCase()}</span></p>
                    <p><strong>Confidence:</strong> ${Math.round(aiAnalysis.confidence * 100)}%</p>
                </div>
            `;
            
            // Display vulnerabilities
            vulnerabilitiesDiv.innerHTML = '';
            if (data.results.length === 0) {
                vulnerabilitiesDiv.innerHTML = '<p class="no-vuln-message">No vulnerabilities detected!</p>';
            } else {
                data.results.forEach(vuln => {
                    const vulnCard = document.createElement('div');
                    vulnCard.className = `vuln-card ${vuln.severity.toLowerCase()}`;
                    vulnCard.innerHTML = `
                        <div class="vuln-header">
                            <h4>${vuln.type}</h4>
                            <span class="severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                        </div>
                        <div class="vuln-details">
                            <p>${vuln.description}</p>
                            <p><strong>URL:</strong> <a href="${vuln.url}" target="_blank">${vuln.url}</a></p>
                        </div>
                    `;
                    vulnerabilitiesDiv.appendChild(vulnCard);
                });
            }
            
            // Update report button
            viewReportBtn.href = `/report/${currentScanId}`;
            
            // Show results
            loadingDiv.classList.add('hidden');
            resultsDiv.classList.remove('hidden');
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred during the scan: ' + error.message);
            
            // Reset form
            scanForm.style.display = 'block';
            loadingDiv.classList.add('hidden');
        });
    });
});