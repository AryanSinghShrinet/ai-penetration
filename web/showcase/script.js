// AI-Pentester Showcase Website - Interactive Scripts

// API Base URL - when served from Flask
const API_BASE = '';

// FIX 4: Cached scope config
let scopeConfig = null;
let apiKey = localStorage.getItem('ai_pentester_api_key') || '';

// Centralized fetch with API Key support
async function apiFetch(url, options = {}) {
    const headers = options.headers || {};
    if (apiKey) {
        headers['X-API-Key'] = apiKey;
    }
    
    return fetch(url, { ...options, headers });
}

document.addEventListener('DOMContentLoaded', () => {
    initTerminalAnimation();
    initSmoothScroll();
    initScrollAnimations();
    initScanForm();
    loadRecentRuns();
    loadScopeConfig();  // FIX 4: Load scope on init
});

// FIX 4: Load scope configuration
async function loadScopeConfig() {
    try {
        const response = await apiFetch(`${API_BASE}/api/config/scope`);
        if (response.ok) {
            scopeConfig = await response.json();
            console.log('Scope config loaded:', scopeConfig);
        }
    } catch (error) {
        console.log('Could not load scope config:', error);
    }
}

// FIX 4: Validate target against scope
function validateScope() {
    const target = document.getElementById('target-url').value.trim();
    const warning = document.getElementById('scope-warning');
    const statusSpan = document.getElementById('scope-status');

    if (!target || !scopeConfig) {
        if (warning) warning.style.display = 'none';
        return;
    }

    // Extract domain from target
    let domain = target;
    try {
        if (target.includes('://')) {
            domain = new URL(target).hostname;
        } else {
            domain = target.replace(/^[*.]/, '').split('/')[0];
        }
    } catch (e) {
        domain = target.split('/')[0];
    }

    // Check if domain matches any allowed pattern
    const allowedDomains = scopeConfig.allowed_domains || [];
    const isInScope = allowedDomains.some(pattern => {
        if (pattern.startsWith('*.')) {
            // Wildcard match
            const baseDomain = pattern.substring(2);
            return domain.endsWith(baseDomain) || domain === baseDomain;
        }
        return domain === pattern || domain.endsWith('.' + pattern);
    });

    if (warning && statusSpan) {
        if (!isInScope && allowedDomains.length > 0) {
            warning.style.display = 'block';
            statusSpan.textContent = 'outside configured scope';
            warning.className = 'scope-warning out-of-scope';
        } else if (isInScope) {
            warning.style.display = 'block';
            statusSpan.textContent = 'within scope ✓';
            warning.className = 'scope-warning in-scope';
        } else {
            warning.style.display = 'none';
        }
    }
}

// FIX 4: Show scope details
function loadScope() {
    if (scopeConfig) {
        const domains = scopeConfig.allowed_domains || [];
        const protocols = scopeConfig.allowed_protocols || [];
        alert(`Scope Configuration:\n\nAllowed Domains:\n${domains.map(d => '  • ' + d).join('\n') || '  (none configured)'}\n\nAllowed Protocols:\n${protocols.map(p => '  • ' + p).join('\n') || '  (none configured)'}`);
    } else {
        alert('Scope configuration not loaded. Check config/scope.yaml');
    }
}

// FIX 7: Select/deselect all vulnerability types
function selectAllVulns(selectAll) {
    const checkboxes = document.querySelectorAll('input[name="vuln-type"]');
    checkboxes.forEach(cb => cb.checked = selectAll);
}

// FIX 7: Get selected vulnerability types
function getSelectedVulnTypes() {
    const checkboxes = document.querySelectorAll('input[name="vuln-type"]:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

// Terminal typing animation
function initTerminalAnimation() {
    const terminalOutput = document.getElementById('terminal-output');
    if (!terminalOutput) return;

    const commands = [
        'python main.py',
        '🚀 Autonomous Bug Bounty AI',
        '=== Layer 1: Foundation ===',
        '[RECON] Crawling target...',
        '[RECON] Found 19 endpoints',
        '[RECON] Extracted parameters: goButton, searchFor',
        '[ML] Analyzing response patterns...',
        '[HYPOTHESIS] XSS: 0.85 confidence',
        '[EXEC] Testing XSS payloads...',
        '[CHAIN] XSS + CORS → Session theft',
        '✅ Report generated: report.md',
    ];

    let commandIndex = 0;
    let charIndex = 0;
    let currentText = '';
    let isDeleting = false;
    let pauseEnd = false;

    function type() {
        const currentCommand = commands[commandIndex];

        if (!isDeleting) {
            currentText = currentCommand.substring(0, charIndex + 1);
            charIndex++;

            if (charIndex === currentCommand.length) {
                pauseEnd = true;
                setTimeout(() => {
                    pauseEnd = false;
                    isDeleting = true;
                    type();
                }, 2000);
                terminalOutput.textContent = currentText;
                return;
            }
        } else {
            currentText = currentCommand.substring(0, charIndex - 1);
            charIndex--;

            if (charIndex === 0) {
                isDeleting = false;
                commandIndex = (commandIndex + 1) % commands.length;
            }
        }

        terminalOutput.textContent = currentText;

        const speed = isDeleting ? 30 : 50;
        if (!pauseEnd) {
            setTimeout(type, speed);
        }
    }

    type();
}

// Smooth scroll for navigation links
function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                const headerOffset = 80;
                const elementPosition = target.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });
}

// Scroll-triggered animations
function initScrollAnimations() {
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    const animatedElements = document.querySelectorAll(
        '.feature-card, .vuln-card, .arch-layer, .workflow-step, .tech-item'
    );

    animatedElements.forEach((el, index) => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = `all 0.6s ease-out ${index * 0.1}s`;
        observer.observe(el);
    });
}

// Add navbar background on scroll
window.addEventListener('scroll', () => {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.style.background = 'rgba(10, 10, 26, 0.95)';
    } else {
        navbar.style.background = 'rgba(10, 10, 26, 0.8)';
    }
});

// ==================== SCAN FUNCTIONALITY ====================

let currentScanId = null;
let pollInterval = null;

function initScanForm() {
    const form = document.getElementById('scan-form');
    if (!form) return;

    form.addEventListener('submit', handleScanSubmit);
}

async function handleScanSubmit(e) {
    e.preventDefault();

    const targetUrl = document.getElementById('target-url').value.trim();
    const dryRun = document.getElementById('dry-run').checked;
    const scanBtn = document.getElementById('scan-btn');

    if (!targetUrl) {
        alert('Please enter a target URL');
        return;
    }

    // Disable button
    scanBtn.disabled = true;
    scanBtn.querySelector('.btn-text').textContent = 'Starting...';

    // Hide results, show status and vulnerability panel
    document.getElementById('scan-results').style.display = 'none';
    document.getElementById('scan-status').style.display = 'block';
    document.getElementById('scan-status').classList.remove('error');

    // Show vulnerability panel
    const vulnPanel = document.getElementById('vuln-panel');
    if (vulnPanel) {
        vulnPanel.style.display = 'flex';
        document.getElementById('vuln-list').innerHTML = `
            <div class="vuln-list-empty">
                <div class="empty-icon">⏳</div>
                <p>Waiting for scan to start...</p>
            </div>
        `;
        document.getElementById('panel-stats').textContent = '0/0';
    }

    try {
        const response = await apiFetch(`${API_BASE}/api/scan/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: targetUrl,
                dry_run: dryRun
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to start scan');
        }

        currentScanId = data.scan_id;
        document.getElementById('status-target').textContent = `Target: ${targetUrl}`;

        // Start polling for status
        startPolling();

    } catch (error) {
        showError(error.message);
        scanBtn.disabled = false;
        scanBtn.querySelector('.btn-text').textContent = 'Start Scan';
    }
}

function startPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
    }

    pollInterval = setInterval(checkScanStatus, 2000);
    checkScanStatus(); // Initial check
}

async function checkScanStatus() {
    if (!currentScanId) return;

    try {
        const response = await apiFetch(`${API_BASE}/api/scan/${currentScanId}/status`);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get status');
        }

        updateStatusUI(data);

        if (data.status === 'completed') {
            stopPolling();
            showResults(data);
            loadRecentRuns();
        } else if (data.status === 'error') {
            stopPolling();
            showError(data.error || 'Scan failed');
        }

    } catch (error) {
        console.error('Status check failed:', error);
    }
}

function updateStatusUI(data) {
    const statusText = document.getElementById('status-text');
    const statusTime = document.getElementById('status-time');
    const progressFill = document.getElementById('progress-fill');
    const progressMessage = document.getElementById('progress-message');

    // Update status text - now includes cancelling state
    const statusMap = {
        'starting': 'Initializing...',
        'running': 'Scanning...',
        'completed': 'Complete!',
        'cancelled': 'Cancelled',
        'cancelling': 'Cancelling...',
        'error': 'Error'
    };
    statusText.textContent = statusMap[data.status] || data.status;

    // Update time
    statusTime.textContent = formatTime(data.elapsed_seconds || 0);

    // FIX 1: Use REAL progress from pipeline data instead of fake hardcoded map
    let progressPercent = 0;
    let progressText = data.progress || 'Processing...';

    if (data.pipeline) {
        // Real pipeline progress from backend
        const layer = data.pipeline.current_layer || 1;
        const layerProgress = data.pipeline.progress || 0;
        const layerName = data.pipeline.layer_name || 'Processing';

        // Calculate overall progress: (layer-1)*20 + layerProgress*20
        progressPercent = Math.min(100, Math.round((layer - 1) * 20 + layerProgress * 20));
        progressText = `Layer ${layer}/5: ${layerName} (${Math.round(layerProgress * 100)}%)`;

        // Use pipeline message if available
        if (data.pipeline.message) {
            progressText = data.pipeline.message;
        }
    } else if (data.overall_progress !== undefined) {
        // Fallback to overall_progress from API
        progressPercent = data.overall_progress;
    } else {
        // Fallback for status without pipeline data
        if (data.status === 'completed') progressPercent = 100;
        else if (data.status === 'running') progressPercent = 50;
        else if (data.status === 'starting') progressPercent = 10;
    }

    progressFill.style.width = `${progressPercent}%`;

    // Update message - prefer pipeline message, then layer info
    if (data.layer) {
        progressMessage.textContent = `Layer ${data.layer_index}/5: ${data.layer}`;
    } else {
        progressMessage.textContent = progressText;
    }

    // Update vulnerability panel
    if (data.checklist) {
        updateVulnPanel(data.checklist, data.layer_4 || {});
    }
}


function updateVulnPanel(checklist, layer4Results) {
    const vulnList = document.getElementById('vuln-list');
    const panelStats = document.getElementById('panel-stats');

    if (!vulnList) return;

    const entries = Object.entries(checklist);
    if (entries.length === 0) {
        vulnList.innerHTML = `
            <div class="vuln-list-empty">
                <div class="empty-icon">⏳</div>
                <p>Scanning in progress...</p>
            </div>
        `;
        return;
    }

    // Calculate stats
    let found = 0, total = entries.length;
    entries.forEach(([_, status]) => {
        if (status === 'FOUND' || status === 'SUCCESS') found++;
    });
    panelStats.textContent = `${found}/${total}`;

    // Build vulnerability items
    vulnList.innerHTML = entries.map(([vuln, status]) => {
        const icon = getVulnIcon(vuln);
        const details = layer4Results[vuln] || [];
        const hasDetails = Array.isArray(details) ? details.length > 0 : !!details;

        return `
            <div class="vuln-item" data-vuln="${vuln}">
                <div class="vuln-item-header" onclick="toggleVulnDetails('${vuln}')">
                    <div class="vuln-name">
                        <span class="vuln-icon">${icon}</span>
                        <span class="vuln-label">${vuln.toUpperCase()}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="vuln-status ${status}">${status}</span>
                        ${hasDetails ? '<span class="expand-arrow">▼</span>' : ''}
                    </div>
                </div>
                ${hasDetails ? buildVulnDetails(vuln, details) : ''}
            </div>
        `;
    }).join('');
}

function getVulnIcon(vuln) {
    const icons = {
        'xss': '💉',
        'sqli': '🗃️',
        'idor': '🔓',
        'cors': '🌐',
        'ssrf': '🔗',
        'file_upload': '📁',
        'cmd_injection': '💻',
        'business_logic': '🧩',
        'lfi': '📂',
        'open_redirect': '↗️'
    };
    return icons[vuln.toLowerCase()] || '🔍';
}

function buildVulnDetails(vuln, results) {
    if (!results || (Array.isArray(results) && results.length === 0)) {
        return '';
    }

    const details = Array.isArray(results) ? results[0] : results;

    return `
        <div class="vuln-details">
            ${details.payload ? `
                <div class="detail-row">
                    <span class="detail-label">Payload:</span>
                    <span class="detail-value payload">${escapeHtml(String(details.payload).substring(0, 100))}</span>
                </div>
            ` : ''}
            ${details.endpoint || details.url ? `
                <div class="detail-row">
                    <span class="detail-label">Endpoint:</span>
                    <span class="detail-value">${escapeHtml(details.endpoint || details.url)}</span>
                </div>
            ` : ''}
            ${details.param ? `
                <div class="detail-row">
                    <span class="detail-label">Param:</span>
                    <span class="detail-value">${escapeHtml(details.param)}</span>
                </div>
            ` : ''}
            ${details.status ? `
                <div class="detail-row">
                    <span class="detail-label">Status:</span>
                    <span class="detail-value">${details.status}</span>
                </div>
            ` : ''}
        </div>
    `;
}

function toggleVulnDetails(vuln) {
    const item = document.querySelector(`.vuln-item[data-vuln="${vuln}"]`);
    if (item) {
        item.classList.toggle('expanded');
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(seconds) {
    if (seconds < 60) {
        return `${seconds}s`;
    }
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}m ${secs}s`;
}

function stopPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }

    // Re-enable button
    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = false;
    scanBtn.querySelector('.btn-text').textContent = 'Start Scan';

    // Hide stop button
    const stopBtn = document.getElementById('stop-btn');
    if (stopBtn) stopBtn.style.display = 'none';
}


// FIX 2: Stop Scan Function
async function stopScan() {
    if (!currentScanId) {
        alert('No active scan to stop');
        return;
    }

    // Confirmation dialog
    if (!confirm('Stop the current scan? Partial results will be saved.')) {
        return;
    }

    const stopBtn = document.getElementById('stop-btn');
    if (stopBtn) {
        stopBtn.disabled = true;
        stopBtn.textContent = '⏳ Stopping...';
    }

    try {
        const response = await fetch(`${API_BASE}/api/scan/${currentScanId}/stop`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (!response.ok) {
            alert('Failed to stop scan: ' + (data.error || 'Unknown error'));
            if (stopBtn) {
                stopBtn.disabled = false;
                stopBtn.textContent = '⬛ Stop Scan';
            }
            return;
        }

        // Update UI to show cancelling status
        document.getElementById('status-text').textContent = 'Cancelling...';
        document.getElementById('progress-message').textContent = 'Cancellation requested...';

    } catch (error) {
        alert('Error stopping scan: ' + error.message);
        if (stopBtn) {
            stopBtn.disabled = false;
            stopBtn.textContent = '⬛ Stop Scan';
        }
    }
}

function showResults(data) {
    document.getElementById('scan-status').style.display = 'none';
    document.getElementById('scan-results').style.display = 'block';

    // Update counts
    const checklist = data.checklist || {};
    let found = 0, blocked = 0, failed = 0;

    for (const status of Object.values(checklist)) {
        if (status === 'FOUND') found++;
        else if (status === 'BLOCKED') blocked++;
        else if (status === 'FAILED') failed++;
    }

    document.getElementById('found-count').textContent = found;
    document.getElementById('blocked-count').textContent = blocked;
    document.getElementById('failed-count').textContent = failed;

    // Update link
    if (data.run_id) {
        document.getElementById('view-full-results').href = `/run/${data.run_id}`;
    }

    // Final update of vulnerability panel with complete results
    if (data.checklist) {
        updateVulnPanel(data.checklist, data.layer_4 || {});
    }
}

function showError(message) {
    const statusDiv = document.getElementById('scan-status');
    statusDiv.classList.add('error');
    document.getElementById('status-text').textContent = 'Error';
    document.getElementById('progress-message').textContent = message;
    document.getElementById('progress-fill').style.width = '100%';

    // Re-enable button
    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = false;
    scanBtn.querySelector('.btn-text').textContent = 'Start Scan';
}

// Load recent runs
async function loadRecentRuns() {
    const runsList = document.getElementById('runs-list');
    if (!runsList) return;

    try {
        const response = await apiFetch(`${API_BASE}/api/runs`);

        if (!response.ok) {
            // Probably not running from Flask server
            return;
        }

        const runs = await response.json();

        if (runs.length === 0) {
            runsList.innerHTML = '<p class="no-runs">No scans yet. Start your first scan above!</p>';
            return;
        }

        runsList.innerHTML = runs.slice(0, 5).map(run => `
            <a href="/run/${run.run_id}" class="run-item">
                <div class="run-info">
                    <span class="run-target">${run.target}</span>
                    <div class="run-meta">
                        <span>ID: ${run.run_id.substring(0, 8)}...</span>
                    </div>
                </div>
                <span class="run-findings ${run.findings_count === 0 ? 'zero' : ''}">
                    ${run.findings_count} found
                </span>
            </a>
        `).join('');

    } catch (error) {
        // Silently fail - probably not running from Flask
        console.log('Could not load runs - API not available');
    }
}
