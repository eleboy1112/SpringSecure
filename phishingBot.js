// Enhanced Phishing Detection Bot

class PhishingBot {
    constructor() {
        this.phishingIndicators = [
            { pattern: /password|login|signin|verify|account|secure|update|confirm/gi, weight: 1 },
            { pattern: /bank|paypal|apple|microsoft|google|facebook|amazon|netflix/gi, weight: 1.5 },
            { pattern: /urgent|alert|warning|limited|expires|suspension|verify now/gi, weight: 2 },
            { pattern: /\.(tk|ml|ga|cf|gq|top)$/i, weight: 3 }, // Suspicious TLDs
            { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, weight: 2.5 } // IP address URLs
        ];
        
        this.trustedDomains = [
            'google.com',
            'gmail.com',
            'youtube.com',
            'microsoft.com',
            'apple.com',
            'amazon.com',
            'facebook.com',
            'twitter.com',
            'instagram.com',
            'linkedin.com',
            'github.com',
            'stackoverflow.com'
        ];

        // Add scan progress tracking
        this.scanProgress = 0;
        this.scanStatus = 'idle';
        this.scanDetails = [];
        this.lastScanResults = null;
    }

    async analyzePhishing(url) {
        try {
            this.scanStatus = 'scanning';
            this.scanProgress = 0;
            this.scanDetails = [];
            this.addScanDetail('Starting comprehensive phishing analysis...', 'info');
            
            const domain = this.extractDomain(url);
            this.scanProgress = 10;
            this.addScanDetail(`Analyzing domain: ${domain}`, 'info');
            
            // Check if it's a trusted domain
            if (this.isTrustedDomain(domain)) {
                this.scanProgress = 100;
                this.scanStatus = 'complete';
                this.addScanDetail(`Domain ${domain} is verified as trusted`, 'success');
                
                const result = {
                    status: 'Safe',
                    details: 'Verified legitimate domain',
                    confidence: 'High',
                    indicators: [],
                    recommendations: ['No action needed - this is a trusted domain']
                };
                
                this.lastScanResults = result;
                return result;
            }
            
            // Check for suspicious URL characteristics
            this.scanProgress = 30;
            this.addScanDetail('Analyzing URL structure and patterns...', 'info');
            const urlScore = this.analyzeUrl(url, domain);
            
            // Fetch and analyze content
            this.scanProgress = 50;
            this.addScanDetail('Fetching and analyzing page content...', 'info');
            const contentScore = await this.analyzeContent(url);
            
            // Calculate final phishing score
            this.scanProgress = 80;
            this.addScanDetail('Calculating final phishing risk score...', 'info');
            const totalScore = urlScore + contentScore;
            
            // Prepare detailed indicators
            const indicators = this.collectIndicators(urlScore, contentScore, domain);
            
            // Prepare recommendations based on score
            const recommendations = this.generateRecommendations(totalScore, indicators);
            
            this.scanProgress = 100;
            this.scanStatus = 'complete';
            
            let result;
            if (totalScore >= 10) {
                this.addScanDetail(`High phishing risk detected (Score: ${totalScore})`, 'danger');
                result = {
                    status: 'Dangerous',
                    details: 'High probability of phishing',
                    confidence: 'High',
                    indicators: indicators,
                    recommendations: recommendations
                };
            } else if (totalScore >= 5) {
                this.addScanDetail(`Moderate phishing risk detected (Score: ${totalScore})`, 'warning');
                result = {
                    status: 'Suspicious',
                    details: 'Moderate phishing indicators detected',
                    confidence: 'Medium',
                    indicators: indicators,
                    recommendations: recommendations
                };
            } else if (totalScore >= 2) {
                this.addScanDetail(`Low phishing risk detected (Score: ${totalScore})`, 'info');
                result = {
                    status: 'Warning',
                    details: 'Low phishing risk',
                    confidence: 'Medium',
                    indicators: indicators,
                    recommendations: recommendations
                };
            } else {
                this.addScanDetail(`No significant phishing risk detected (Score: ${totalScore})`, 'success');
                result = {
                    status: 'Safe',
                    details: 'No phishing indicators detected',
                    confidence: 'High',
                    indicators: indicators,
                    recommendations: ['Continue monitoring for potential security threats']
                };
            }
            
            this.lastScanResults = result;
            return result;
        } catch (error) {
            console.error('Phishing analysis error:', error);
            this.scanStatus = 'error';
            this.addScanDetail(`Error during phishing analysis: ${error.message}`, 'danger');
            
            const result = {
                status: 'Warning',
                details: 'Unable to analyze for phishing',
                confidence: 'Low',
                indicators: [],
                recommendations: ['Try scanning again', 'Consider manual review of the website']
            };
            
            this.lastScanResults = result;
            return result;
        }
    }

    extractDomain(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.hostname.toLowerCase();
        } catch (e) {
            return url.toLowerCase();
        }
    }

    isTrustedDomain(domain) {
        return this.trustedDomains.some(trusted => 
            domain === trusted || domain.endsWith('.' + trusted));
    }

    analyzeUrl(url, domain) {
        let score = 0;
        const indicators = [];
        
        // Check for subdomain abuse (e.g. google.com.phishing.com)
        this.trustedDomains.forEach(trusted => {
            if (domain.includes(trusted) && !domain.endsWith('.' + trusted) && domain !== trusted) {
                score += 5;
                this.addScanDetail(`Detected potential subdomain abuse with ${trusted}`, 'danger');
                indicators.push(`Subdomain abuse with ${trusted}`);
            }
        });
        
        // Check for typosquatting (e.g. g00gle.com, gooogle.com)
        this.trustedDomains.forEach(trusted => {
            const baseDomain = trusted.split('.')[0];
            if (this.calculateLevenshteinDistance(domain.split('.')[0], baseDomain) === 1) {
                score += 3;
                this.addScanDetail(`Detected potential typosquatting of ${trusted}`, 'danger');
                indicators.push(`Typosquatting of ${trusted}`);
            }
        });
        
        // Check for suspicious TLDs
        if (/\.(tk|ml|ga|cf|gq|top)$/i.test(domain)) {
            score += 2;
            this.addScanDetail('Detected suspicious top-level domain', 'warning');
            indicators.push('Suspicious top-level domain');
        }
        
        // Check for excessive subdomains
        const subdomainCount = domain.split('.').length - 2;
        if (subdomainCount > 3) {
            score += 2;
            this.addScanDetail(`Detected excessive subdomains (${subdomainCount})`, 'warning');
            indicators.push('Excessive number of subdomains');
        }
        
        // Check for IP address in URL
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(url)) {
            score += 3;
            this.addScanDetail('Detected IP address in URL', 'danger');
            indicators.push('IP address used instead of domain name');
        }
        
        // Check for URL encoding abuse
        if (/%[0-9a-f]{2}/i.test(url)) {
            score += 1;
            this.addScanDetail('Detected URL encoding potentially hiding malicious content', 'warning');
            indicators.push('Suspicious URL encoding');
        }
        
        return score;
    }

    async analyzeContent(url) {
        try {
            const response = await fetch(url);
            const html = await response.text();
            
            let score = 0;
            const indicators = [];
            
            // Check for login forms using safer regex patterns
            const formPattern = new RegExp('<form[^>]*>([\\s\\S]*?)</form>', 'gi');
            const loginPattern = new RegExp('password|login|signin|username', 'gi');
            
            if (formPattern.test(html) && loginPattern.test(html)) {
                score += 2;
                this.addScanDetail('Detected login form on page', 'warning');
                indicators.push('Login form detected');
            }
            
            // Check for phishing keywords in content with proper regex handling
            this.phishingIndicators.forEach(indicator => {
                const matches = html.match(indicator.pattern) || [];
                if (matches.length > 0) {
                    const points = matches.length * indicator.weight * 0.2;
                    score += points;
                    this.addScanDetail(`Detected ${matches.length} instances of phishing keywords`, 'warning');
                    indicators.push('Multiple phishing keywords detected');
                }
            });
            
            // Check for hidden elements with improved regex
            const hiddenPattern = new RegExp('style=["\'].*?display:\\s*none', 'gi');
            const hiddenElements = (html.match(hiddenPattern) || []).length;
            if (hiddenElements > 0) {
                score += hiddenElements * 0.5;
                this.addScanDetail(`Detected ${hiddenElements} hidden elements`, 'warning');
                indicators.push('Hidden elements detected');
            }
            
            // Check for password fields in unusual contexts with safer regex
            const passwordFieldPattern = new RegExp('<input[^>]*type=["\']password["\'][^>]*>', 'gi');
            const validFormPattern = new RegExp('<form[^>]*action=["\'][^"\']*/(?:login|signin|auth)["\']', 'gi');
            
            if (passwordFieldPattern.test(html) && !validFormPattern.test(html)) {
                score += 2;
                this.addScanDetail('Detected password field in unusual context', 'danger');
                indicators.push('Password field in suspicious context');
            }
            
            return score;
        } catch (error) {
            this.addScanDetail(`Error analyzing content: ${error.message}`, 'danger');
            return 0;
        }
    }

    calculateLevenshteinDistance(a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;

        const matrix = [];

        // Initialize matrix
        for (let i = 0; i <= b.length; i++) {
            matrix[i] = [i];
        }
        for (let j = 0; j <= a.length; j++) {
            matrix[0][j] = j;
        }

        // Fill matrix
        for (let i = 1; i <= b.length; i++) {
            for (let j = 1; j <= a.length; j++) {
                if (b.charAt(i - 1) === a.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1, // substitution
                        matrix[i][j - 1] + 1,     // insertion
                        matrix[i - 1][j] + 1      // deletion
                    );
                }
            }
        }

        return matrix[b.length][a.length];
    }

    // New methods for enhanced functionality
    addScanDetail(message, level = 'info') {
        const detail = {
            timestamp: new Date().toISOString(),
            message: message,
            level: level
        };
        this.scanDetails.push(detail);
        console.log(`PhishingBot: ${message}`);
    }

    collectIndicators(urlScore, contentScore, domain) {
        const indicators = [];
        
        // Add URL-based indicators
        if (urlScore >= 5) {
            indicators.push('High-risk URL structure');
        } else if (urlScore >= 2) {
            indicators.push('Suspicious URL characteristics');
        }
        
        // Add content-based indicators
        if (contentScore >= 5) {
            indicators.push('High-risk page content');
        } else if (contentScore >= 2) {
            indicators.push('Suspicious page content');
        }
        
        // Add domain-based indicators
        if (!this.isTrustedDomain(domain)) {
            indicators.push('Domain not in trusted list');
        }
        
        return indicators;
    }

    generateRecommendations(totalScore, indicators) {
        const recommendations = new Set();
        
        // Core security recommendations based on score
        if (totalScore >= 10) {
            recommendations.add('URGENT: Do not enter any personal information on this site');
            recommendations.add('Leave this website immediately');
            recommendations.add('Report this website to phishing databases and your IT security team');
        } else if (totalScore >= 5) {
            recommendations.add('Exercise extreme caution with this website');
            recommendations.add('Do not enter sensitive information like passwords or credit cards');
            recommendations.add('Verify the website\'s legitimacy through official channels');
        } else if (totalScore >= 2) {
            recommendations.add('Be cautious when interacting with this website');
            recommendations.add('Verify the website\'s identity before sharing any information');
        }

        // Add specific recommendations based on indicators
        indicators.forEach(indicator => {
            if (indicator.includes('URL structure')) {
                recommendations.add('The URL structure appears suspicious - verify you\'re on the intended website');
            }
            if (indicator.includes('password field') || indicator.includes('login form')) {
                recommendations.add('Do not enter login credentials - this may be a credential harvesting attempt');
            }
            if (indicator.includes('hidden elements')) {
                recommendations.add('This site contains hidden elements that may indicate malicious intent');
            }
        });

        // Always include basic security advice
        recommendations.add('Keep your browser and security software updated');
        recommendations.add('Enable two-factor authentication on your important accounts');
        
        return Array.from(recommendations);
    }

    getProgress() {
        return {
            progress: this.scanProgress,
            status: this.scanStatus,
            details: this.scanDetails,
            lastResults: this.lastScanResults
        };
    }
}

// Export the PhishingBot class
module.exports = PhishingBot;```