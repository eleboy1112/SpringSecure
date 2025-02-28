document.addEventListener('DOMContentLoaded', function() {
    // Initialize falling leaves animation
    initFallingLeaves();
    
    // Initialize tab switching
    initTabs();
    
    // Initialize form submission
    document.getElementById('check-button').addEventListener('click', checkWebsite);
    
    // Initialize contact form
    document.getElementById('contact-form').addEventListener('submit', function(e) {
        e.preventDefault();
        alert('Thank you for your message! We will get back to you soon.');
        this.reset();
    });
});

// Initialize falling leaves animation with random positions and delays
function initFallingLeaves() {
    const leaves = document.querySelectorAll('.leaf');
    leaves.forEach((leaf, index) => {
        const randomLeft = Math.random() * 100;
        const randomDelay = Math.random() * 10;
        const randomDuration = 5 + Math.random() * 10;
        
        leaf.style.left = `${randomLeft}%`;
        leaf.style.animationDelay = `${randomDelay}s`;
        leaf.style.animationDuration = `${randomDuration}s`;
    });
}

// Initialize tab switching functionality
function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Remove active class from all buttons and panes
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
            
            // Add active class to clicked button and corresponding pane
            this.classList.add('active');
            const tabId = this.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });
}

// Function to check website security
function checkWebsite() {
    const urlInput = document.getElementById('url-input').value.trim();
    
    // Validate URL
    if (!urlInput) {
        alert('Please enter a valid URL');
        return;
    }
    
    // Format URL if needed
    let url = urlInput;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }
    
    // Show results section and loader
    document.getElementById('results').classList.remove('hidden');
    document.querySelector('.loader').classList.remove('hidden');
    document.querySelector('.result-container').style.display = 'none';
    
    // Scroll to results
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
    
    // Initialize bot activities
    initializeBotActivities();
    
    // Simulate API call with setTimeout (in a real app, this would be an actual API call)
    setTimeout(() => {
        performSecurityCheck(url);
    }, 2000);
}

// Simulate security check (in a real app, this would call actual security APIs)
function performSecurityCheck(url) {
    // Hide loader and show results
    document.querySelector('.loader').classList.add('hidden');
    document.querySelector('.result-container').style.display = 'block';
    
    // Extract domain for display
    const domain = new URL(url).hostname;
    
    // Update site info
    document.getElementById('site-title').textContent = domain;
    document.getElementById('site-favicon').src = `https://www.google.com/s2/favicons?domain=${domain}`;
    
    // Generate random security score (in a real app, this would be calculated based on actual checks)
    const securityScore = Math.floor(Math.random() * 41) + 60; // Score between 60-100
    document.getElementById('security-score-value').textContent = securityScore;
    
    // Update score circle color based on score
    const scoreCircle = document.querySelector('.score-circle');
    if (securityScore >= 90) {
        scoreCircle.style.borderColor = '#4CAF50'; // Green for good
    } else if (securityScore >= 70) {
        scoreCircle.style.borderColor = '#FFC107'; // Yellow for medium
    } else {
        scoreCircle.style.borderColor = '#F44336'; // Red for poor
    }
    
    // Update security summary items
    updateSecuritySummary(securityScore);
    
    // Update AI status based on security score
    const aiStatus = document.getElementById('ai-status');
    if (securityScore >= 85) {
        aiStatus.textContent = 'Safe';
        aiStatus.style.color = '#4CAF50';
    } else if (securityScore >= 65) {
        aiStatus.textContent = 'Warning';
        aiStatus.style.color = '#FFC107';
    } else {
        aiStatus.textContent = 'Suspicious';
        aiStatus.style.color = '#F44336';
    }
    
    // Generate threats data
    generateThreatsData(securityScore);
    
    // Generate links data
    generateLinksData();
    
    // Generate details data
    generateDetailsData(domain);
    
    // Check for bot protection
    checkBotProtection(domain);
    
    // Check DNS records
    checkDNSRecords(domain);
    
    // Check technologies used
    checkTechnologies(domain);
    
    // Populate bot console with detailed activities
    populateBotConsole(url);
}

// Update security summary based on score
function updateSecuritySummary(score) {
    // SSL Certificate
    const sslStatus = document.getElementById('ssl-status');
    if (score >= 80) {
        sslStatus.textContent = 'Valid and Secure';
        sslStatus.style.color = '#4CAF50';
    } else if (score >= 60) {
        sslStatus.textContent = 'Valid but Outdated';
        sslStatus.style.color = '#FFC107';
    } else {
        sslStatus.textContent = 'Invalid or Missing';
        sslStatus.style.color = '#F44336';
    }
    
    // Malware Detection
    const malwareStatus = document.getElementById('malware-status');
    if (score >= 75) {
        malwareStatus.textContent = 'No Malware Detected';
        malwareStatus.style.color = '#4CAF50';
    } else if (score >= 50) {
        malwareStatus.textContent = 'Suspicious Content';
        malwareStatus.style.color = '#FFC107';
    } else {
        malwareStatus.textContent = 'Malware Detected';
        malwareStatus.style.color = '#F44336';
    }
    
    // Link Safety
    const linkStatus = document.getElementById('link-status');
    if (score >= 85) {
        linkStatus.textContent = 'All Links Safe';
        linkStatus.style.color = '#4CAF50';
    } else if (score >= 65) {
        linkStatus.textContent = 'Some Suspicious Links';
        linkStatus.style.color = '#FFC107';
    } else {
        linkStatus.textContent = 'Unsafe Links Detected';
        linkStatus.style.color = '#F44336';
    }
    
    // Phishing Risk
    const phishingStatus = document.getElementById('phishing-status');
    if (score >= 90) {
        phishingStatus.textContent = 'Low Risk';
        phishingStatus.style.color = '#4CAF50';
    } else if (score >= 70) {
        phishingStatus.textContent = 'Medium Risk';
        phishingStatus.style.color = '#FFC107';
    } else {
        phishingStatus.textContent = 'High Risk';
        phishingStatus.style.color = '#F44336';
    }
    
    // Server Security
    const serverSecurityStatus = document.getElementById('server-security-status');
    if (score >= 85) {
        serverSecurityStatus.textContent = 'Well Secured';
        serverSecurityStatus.style.color = '#4CAF50';
    } else if (score >= 65) {
        serverSecurityStatus.textContent = 'Moderate Security';
        serverSecurityStatus.style.color = '#FFC107';
    } else {
        serverSecurityStatus.textContent = 'Vulnerable';
        serverSecurityStatus.style.color = '#F44336';
    }
}

// Generate threats data based on security score
function generateThreatsData(score) {
    const threatsContainer = document.getElementById('threats-container');
    threatsContainer.innerHTML = '';
    
    if (score >= 90) {
        threatsContainer.innerHTML = '<p class="good-news">No significant threats detected.</p>';
        return;
    }
    
    const possibleThreats = [
        { name: 'Outdated SSL Certificate', severity: 'Medium', description: 'The SSL certificate is valid but using outdated encryption standards.' },
        { name: 'Cross-Site Scripting (XSS) Vulnerability', severity: 'High', description: 'The website may be vulnerable to XSS attacks, allowing attackers to inject malicious scripts.' },
        { name: 'Insecure Form Submission', severity: 'Medium', description: 'Forms on the website are submitted without proper encryption.' },
        { name: 'Outdated CMS Version', severity: 'High', description: 'The content management system is outdated and contains known security vulnerabilities.' },
        { name: 'Mixed Content', severity: 'Medium', description: 'The website loads some resources over insecure HTTP connections.' },
        { name: 'Suspicious External Scripts', severity: 'High', description: 'The website loads scripts from potentially malicious domains.' },
        { name: 'Missing Security Headers', severity: 'Medium', description: 'Important security headers like Content-Security-Policy are missing.' },
        { name: 'Insecure Cookies', severity: 'Medium', description: 'Cookies are set without secure and httpOnly flags.' }
    ];
    
    // Select random threats based on score
    const threatCount = Math.floor((100 - score) / 10);
    const selectedThreats = [];
    
    for (let i = 0; i < threatCount; i++) {
        const randomIndex = Math.floor(Math.random() * possibleThreats.length);
        selectedThreats.push(possibleThreats[randomIndex]);
        possibleThreats.splice(randomIndex, 1);
        
        if (possibleThreats.length === 0) break;
    }
    
    // Create threats HTML
    if (selectedThreats.length === 0) {
        threatsContainer.innerHTML = '<p class="good-news">No significant threats detected.</p>';
        return;
    }
    
    const threatsHTML = selectedThreats.map(threat => {
        const severityClass = threat.severity === 'High' ? 'high-severity' : 'medium-severity';
        return `
            <div class="threat-item">
                <div class="threat-header">
                    <h4>${threat.name}</h4>
                    <span class="${severityClass}">${threat.severity}</span>
                </div>
                <p>${threat.description}</p>
            </div>
        `;
    }).join('');
    
    threatsContainer.innerHTML = threatsHTML;
}

// Generate links data
function generateLinksData() {
    const linksContainer = document.getElementById('links-container');
    linksContainer.innerHTML = '';
    
    const possibleLinks = [
        { url: 'https://example.com/about', status: 'Safe', type: 'Internal' },
        { url: 'https://example.com/products', status: 'Safe', type: 'Internal' },
        { url: 'https://example.com/blog', status: 'Safe', type: 'Internal' },
        { url: 'https://partner-example.com', status: 'Safe', type: 'External' },
        { url: 'https://analytics-service.com', status: 'Safe', type: 'External' },
        { url: 'https://cdn-provider.com', status: 'Safe', type: 'External' },
        { url: 'https://suspicious-tracker.com', status: 'Suspicious', type: 'External' },
        { url: 'https://ad-network.com', status: 'Suspicious', type: 'External' }
    ];
    
    // Select random links
    const linkCount = 5 + Math.floor(Math.random() * 4); // 5-8 links
    const selectedLinks = [];
    
    for (let i = 0; i < linkCount; i++) {
        const randomIndex = Math.floor(Math.random() * possibleLinks.length);
        selectedLinks.push(possibleLinks[randomIndex]);
        possibleLinks.splice(randomIndex, 1);
        
        if (possibleLinks.length === 0) break;
    }
    
    // Create links HTML
    const linksHTML = selectedLinks.map(link => {
        const statusClass = link.status === 'Safe' ? 'safe-link' : 'suspicious-link';
        return `
            <div class="link-item">
                <div class="link-url">${link.url}</div>
                <div class="link-info">
                    <span class="${statusClass}">${link.status}</span>
                    <span class="link-type">${link.type}</span>
                </div>
            </div>
        `;
    }).join('');
    
    linksContainer.innerHTML = linksHTML;
}

// Generate details data
function generateDetailsData(domain) {
    // Generate random dates for domain registration
    const currentDate = new Date();
    const registrationDate = new Date(currentDate);
    registrationDate.setFullYear(registrationDate.getFullYear() - Math.floor(Math.random() * 10) - 1);
    
    const expirationDate = new Date(currentDate);
    expirationDate.setFullYear(expirationDate.getFullYear() + Math.floor(Math.random() * 5) + 1);
    
    // Format dates
    const regDateFormatted = registrationDate.toLocaleDateString();
    const expDateFormatted = expirationDate.toLocaleDateString();
    
    // Update domain info
    document.getElementById('domain-reg-date').textContent = regDateFormatted;
    document.getElementById('domain-exp-date').textContent = expDateFormatted;
    
    // Random registrar
    const registrars = ['GoDaddy', 'Namecheap', 'Google Domains', 'Cloudflare Registrar', 'Network Solutions'];
    const randomRegistrar = registrars[Math.floor(Math.random() * registrars.length)];
    document.getElementById('domain-registrar').textContent = randomRegistrar;
    
    // WHOIS Status
    const whoisStatuses = ['Active', 'clientTransferProhibited', 'clientUpdateProhibited', 'clientDeleteProhibited'];
    const randomStatuses = [];
    const statusCount = Math.floor(Math.random() * 3) + 1;
    
    for (let i = 0; i < statusCount; i++) {
        const randomIndex = Math.floor(Math.random() * whoisStatuses.length);
        randomStatuses.push(whoisStatuses[randomIndex]);
        whoisStatuses.splice(randomIndex, 1);
        
        if (whoisStatuses.length === 0) break;
    }
    
    document.getElementById('domain-whois-status').textContent = randomStatuses.join(', ');
    
    // Name Servers
    const nameServers = [`ns1.${domain}`, `ns2.${domain}`, `ns3.${domain}`];
    document.getElementById('domain-nameservers').textContent = nameServers.join(', ');
    
    // Server info
    const serverTypes = ['Apache', 'Nginx', 'Microsoft IIS', 'Cloudflare', 'LiteSpeed'];
    const randomServerType = serverTypes[Math.floor(Math.random() * serverTypes.length)];
    document.getElementById('server-type').textContent = randomServerType;
    
    // Random IP
    const ip = `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
    document.getElementById('server-ip').textContent = ip;
    
    // Random location
    const locations = ['United States', 'Germany', 'Netherlands', 'France', 'United Kingdom', 'Japan', 'Singapore', 'Australia'];
    const randomLocation = locations[Math.floor(Math.random() * locations.length)];
    document.getElementById('server-location').textContent = randomLocation;
    
    // Hosting Provider
    const hostingProviders = ['Amazon Web Services', 'Google Cloud Platform', 'Microsoft Azure', 'DigitalOcean', 'Linode', 'OVH', 'Hetzner', 'Vultr'];
    const randomProvider = hostingProviders[Math.floor(Math.random() * hostingProviders.length)];
    document.getElementById('server-hosting').textContent = randomProvider;
    
    // Operating System
    const operatingSystems = ['Ubuntu 22.04 LTS', 'CentOS 8', 'Debian 11', 'Windows Server 2022', 'Red Hat Enterprise Linux 9', 'Amazon Linux 2'];
    const randomOS = operatingSystems[Math.floor(Math.random() * operatingSystems.length)];
    document.getElementById('server-os').textContent = randomOS;
}

// Helper function to add bot actions
function addBotAction(containerId, message, className) {
    const container = document.getElementById(containerId);
    const actionDiv = document.createElement('div');
    actionDiv.className = `bot-action ${className}`;
    actionDiv.textContent = message;
    container.appendChild(actionDiv);
    container.scrollTop = container.scrollHeight;
}

// Add some CSS styles programmatically
document.addEventListener('DOMContentLoaded', function() {
    const style = document.createElement('style');
    style.textContent = `
        .good-news {
            color: #4CAF50;
            font-weight: bold;
        }
        
        .threat-item, .link-item {
            margin-bottom: 1rem;
            padding: 1rem;
            background: var(--light-bg);
            border-radius: 5px;
        }
        
        .threat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        
        .high-severity {
            color: #F44336;
            font-weight: bold;
        }
        
        .medium-severity {
            color: #FFC107;
            font-weight: bold;
        }
        
        .safe-link {
            color: #4CAF50;
            font-weight: bold;
        }
        
        .suspicious-link {
            color: #F44336;
            font-weight: bold;
        }
        
        .link-url {
            margin-bottom: 0.5rem;
            word-break: break-all;
        }
        
        .link-info {
            display: flex;
            gap: 1rem;
        }
    `;
});

// Check for bot protection mechanisms
function checkBotProtection(domain) {
    const botProtections = [
        { name: 'reCAPTCHA', detected: Math.random() > 0.5 },
        { name: 'hCaptcha', detected: Math.random() > 0.7 },
        { name: 'Bot Detection Script', detected: Math.random() > 0.4 },
        { name: 'IP Filtering', detected: Math.random() > 0.6 },
        { name: 'Rate Limiting', detected: Math.random() > 0.3 },
        { name: 'Browser Fingerprinting', detected: Math.random() > 0.6 }
    ];
    
    const detectedProtections = botProtections.filter(p => p.detected);
    document.getElementById('bot-protection-status').textContent = 
        detectedProtections.length > 0 ? 
        detectedProtections.map(p => p.name).join(', ') : 
        'No bot protection detected';
    
    // Add bot actions for bot protection check
    const botActionsContainer = document.getElementById('bot-protection-actions');
    if (botActionsContainer) {
        botActionsContainer.innerHTML = '';
        
        addBotAction('bot-protection-actions', 'Scanning for bot protection mechanisms...', 'action-info');
        setTimeout(() => {
            botProtections.forEach((protection, index) => {
                setTimeout(() => {
                    const actionClass = protection.detected ? 'action-warning' : 'action-success';
                    const actionText = protection.detected ? 
                        `${protection.name} detected` : 
                        `No ${protection.name} found`;
                    addBotAction('bot-protection-actions', actionText, actionClass);
                }, index * 400);
            });
        }, 600);
    }
}

// Initialize bot activities when starting security check
function initializeBotActivities() {
    // Clear previous bot actions
    document.getElementById('ssl-bot-actions').innerHTML = '';
    document.getElementById('malware-bot-actions').innerHTML = '';
    document.getElementById('phishing-bot-actions').innerHTML = '';
    document.getElementById('link-bot-actions').innerHTML = '';
    document.getElementById('ai-bot-actions').innerHTML = '';
    
    // Add initial connection messages
    addBotAction('ssl-bot-actions', 'Initializing SSL security check...', 'action-info');
    addBotAction('malware-bot-actions', 'Starting malware scan...', 'action-info');
    addBotAction('phishing-bot-actions', 'Beginning phishing analysis...', 'action-info');
    addBotAction('link-bot-actions', 'Preparing link safety check...', 'action-info');
    addBotAction('ai-bot-actions', 'Initializing AI-powered security analysis...', 'action-info');
}

// Populate bot console with detailed bot activities
function populateBotConsole(url) {
    // Add detailed bot activities with timing
    setTimeout(() => {
        // SSL Bot activities
        addBotAction('ssl-bot-actions', 'Checking SSL certificate...', 'action-info');
        setTimeout(() => {
            addBotAction('ssl-bot-actions', 'Verifying certificate validity...', 'action-info');
            setTimeout(() => {
                const sslStatus = document.getElementById('ssl-status').textContent;
                if (sslStatus === 'Valid and Secure') {
                    addBotAction('ssl-bot-actions', 'SSL certificate is valid and up to date', 'action-success');
                } else if (sslStatus === 'Valid but Outdated') {
                    addBotAction('ssl-bot-actions', 'SSL certificate needs updating', 'action-warning');
                } else {
                    addBotAction('ssl-bot-actions', 'SSL certificate issues detected', 'action-error');
                }
            }, 800);
        }, 600);

        // Malware Bot activities
        setTimeout(() => {
            addBotAction('malware-bot-actions', 'Scanning website content...', 'action-info');
            setTimeout(() => {
                addBotAction('malware-bot-actions', 'Analyzing script patterns...', 'action-info');
                setTimeout(() => {
                    const malwareStatus = document.getElementById('malware-status').textContent;
                    if (malwareStatus === 'No Malware Detected') {
                        addBotAction('malware-bot-actions', 'No malware found', 'action-success');
                    } else if (malwareStatus === 'Suspicious Content') {
                        addBotAction('malware-bot-actions', 'Suspicious patterns detected', 'action-warning');
                    } else {
                        addBotAction('malware-bot-actions', 'Malware detected!', 'action-error');
                    }
                }, 800);
            }, 600);
        }, 400);

        // Phishing Bot activities
        setTimeout(() => {
            addBotAction('phishing-bot-actions', 'Checking for phishing indicators...', 'action-info');
            setTimeout(() => {
                addBotAction('phishing-bot-actions', 'Analyzing domain reputation...', 'action-info');
                setTimeout(() => {
                    const phishingStatus = document.getElementById('phishing-status').textContent;
                    if (phishingStatus === 'Low Risk') {
                        addBotAction('phishing-bot-actions', 'No phishing indicators found', 'action-success');
                    } else if (phishingStatus === 'Medium Risk') {
                        addBotAction('phishing-bot-actions', 'Some suspicious indicators found', 'action-warning');
                    } else {
                        addBotAction('phishing-bot-actions', 'High phishing risk detected!', 'action-error');
                    }
                }, 800);
            }, 600);
        }, 800);

        // Link Safety Bot activities
        setTimeout(() => {
            addBotAction('link-bot-actions', 'Scanning external links...', 'action-info');
            setTimeout(() => {
                addBotAction('link-bot-actions', 'Verifying link destinations...', 'action-info');
                setTimeout(() => {
                    const linkStatus = document.getElementById('link-status').textContent;
                    if (linkStatus === 'All Links Safe') {
                        addBotAction('link-bot-actions', 'All links verified as safe', 'action-success');
                    } else if (linkStatus === 'Some Suspicious Links') {
                        addBotAction('link-bot-actions', 'Some suspicious links found', 'action-warning');
                    } else {
                        addBotAction('link-bot-actions', 'Unsafe links detected!', 'action-error');
                    }
                }, 800);
            }, 600);
        }, 1200);

        // AI Bot activities
        setTimeout(() => {
            addBotAction('ai-bot-actions', 'Analyzing website content...', 'action-info');
            setTimeout(() => {
                addBotAction('ai-bot-actions', 'Processing security patterns...', 'action-info');
                setTimeout(() => {
                    const aiStatus = document.getElementById('ai-status');
                    if (aiStatus && aiStatus.textContent === 'Safe') {
                        addBotAction('ai-bot-actions', 'No security concerns detected', 'action-success');
                    } else if (aiStatus && aiStatus.textContent === 'Warning') {
                        addBotAction('ai-bot-actions', 'Potential security risks identified', 'action-warning');
                    } else {
                        addBotAction('ai-bot-actions', 'Security vulnerabilities detected', 'action-error');
                    }
                }, 800);
            }, 600);
        }, 1600);

        // Add final analysis messages
        setTimeout(() => {
            addBotAction('ssl-bot-actions', 'SSL analysis complete', 'action-info');
            addBotAction('malware-bot-actions', 'Malware scan complete', 'action-info');
            addBotAction('phishing-bot-actions', 'Phishing analysis complete', 'action-info');
            addBotAction('link-bot-actions', 'Link safety check complete', 'action-info');
            addBotAction('ai-bot-actions', 'AI security analysis complete', 'action-info');
        }, 4000);
    }, 500);

}

// Check DNS records
function checkDNSRecords(domain) {
    // Simulate DNS record checks
    document.getElementById('dns-a-record').textContent = `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
    document.getElementById('dns-mx-records').textContent = `mail.${domain}`;
    document.getElementById('dns-txt-records').textContent = `v=spf1 include:_spf.${domain} ~all`;
    document.getElementById('dns-spf-record').textContent = `v=spf1 ip4:${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.0.0/16 -all`;
    document.getElementById('dns-dmarc-record').textContent = `v=DMARC1; p=reject; rua=mailto:dmarc@${domain}`;
}

// Check technologies used on the website
function checkTechnologies(domain) {
    const possibleTechnologies = [
        { name: 'WordPress', category: 'CMS', version: '6.2.2' },
        { name: 'Apache', category: 'Web Server', version: '2.4.52' },
        { name: 'PHP', category: 'Programming Language', version: '8.1.12' },
        { name: 'MySQL', category: 'Database', version: '8.0.31' },
        { name: 'jQuery', category: 'JavaScript Library', version: '3.6.4' },
        { name: 'Bootstrap', category: 'CSS Framework', version: '5.2.3' },
        { name: 'Cloudflare', category: 'CDN', version: null },
        { name: 'Google Analytics', category: 'Analytics', version: 'GA4' }
    ];
    
    // Randomly select 3-6 technologies
    const selectedTechnologies = [];
    const techCount = Math.floor(Math.random() * 4) + 3;
    
    for (let i = 0; i < techCount; i++) {
        const randomIndex = Math.floor(Math.random() * possibleTechnologies.length);
        selectedTechnologies.push(possibleTechnologies[randomIndex]);
        possibleTechnologies.splice(randomIndex, 1);
    }
    
    // Create technologies HTML
    const techHTML = selectedTechnologies.map(tech => `
        <div class="tech-item">
            <span class="tech-name">${tech.name}</span>
            <span class="tech-category">${tech.category}</span>
            ${tech.version ? `<span class="tech-version">${tech.version}</span>` : ''}
        </div>
    `).join('');
    
    document.getElementById('technologies-container').innerHTML = techHTML;
}