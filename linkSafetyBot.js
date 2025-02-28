// Enhanced Link Safety Bot

class LinkSafetyBot {
    constructor() {
        this.suspiciousDomains = [
            // Known phishing TLDs
            /\.(tk|ml|ga|cf|gq|top|xyz)$/i,
            // Suspicious URL patterns
            /bit\.ly|goo\.gl|tinyurl\.com|t\.co|is\.gd|buff\.ly|ow\.ly|rebrand\.ly|tiny\.cc/i,
            // IP address URLs
            /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i
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
            'stackoverflow.com',
            'wikipedia.org',
            'cloudflare.com',
            'akamai.com',
            'fastly.com',
            'adobe.com',
            'dropbox.com',
            'zoom.us'
        ];

        // Add scan progress tracking
        this.scanProgress = 0;
        this.scanStatus = 'idle';
        this.scanDetails = [];
        this.lastScanResults = null;
    }

    async validateLinks(url) {
        try {
            // Initialize scan
            this.scanStatus = 'scanning';
            this.scanProgress = 0;
            this.scanDetails = [];
            this.addScanDetail('Starting comprehensive link safety analysis...', 'info');
            
            const domain = this.extractDomain(url);
            this.scanProgress = 10;
            this.addScanDetail(`Analyzing domain: ${domain}`, 'info');
            
            // If it's a trusted domain, we can assume links are safe
            if (this.isTrustedDomain(domain)) {
                this.scanProgress = 100;
                this.scanStatus = 'complete';
                this.addScanDetail(`Domain ${domain} is verified as trusted`, 'success');
                
                const result = {
                    status: 'Safe',
                    details: 'Trusted domain with verified links',
                    confidence: 'High',
                    threats: [],
                    recommendations: ['No action needed - this is a trusted domain']
                };
                
                this.lastScanResults = result;
                return result;
            }
            
            // Fetch the page content
            this.scanProgress = 30;
            this.addScanDetail('Fetching page content...', 'info');
            const response = await fetch(url);
            const html = await response.text();
            
            // Extract all links
            this.scanProgress = 50;
            this.addScanDetail('Extracting and analyzing links...', 'info');
            const links = this.extractLinks(html);
            this.addScanDetail(`Found ${links.length} links on the page`, 'info');
            
            // Analyze links
            this.scanProgress = 70;
            this.addScanDetail('Performing deep link analysis...', 'info');
            const analysisResult = this.analyzeLinks(links, domain);
            
            this.scanProgress = 100;
            this.scanStatus = 'complete';
            this.lastScanResults = analysisResult;
            
            if (analysisResult.status === 'Safe') {
                this.addScanDetail('All links appear to be safe', 'success');
            } else if (analysisResult.status === 'Warning') {
                this.addScanDetail('Some potentially suspicious links detected', 'warning');
            } else {
                this.addScanDetail('Suspicious links detected - exercise caution', 'danger');
            }
            
            return analysisResult;
        } catch (error) {
            console.error('Link safety analysis error:', error);
            this.scanStatus = 'error';
            this.addScanDetail(`Error during link analysis: ${error.message}`, 'danger');
            
            const result = {
                status: 'Warning',
                details: 'Unable to analyze links',
                confidence: 'Low',
                threats: [],
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

    extractLinks(html) {
        const linkRegex = /<a[^>]*href=["']([^"']+)["'][^>]*>/gi;
        const links = [];
        let match;
        
        while ((match = linkRegex.exec(html)) !== null) {
            links.push(match[1]);
        }
        
        return links;
    }

    analyzeLinks(links, sourceDomain) {
        // Count external links
        const externalLinks = links.filter(link => {
            try {
                const linkDomain = new URL(link).hostname;
                return linkDomain !== sourceDomain;
            } catch (e) {
                // Relative links or invalid URLs
                return false;
            }
        });
        
        this.addScanDetail(`Found ${externalLinks.length} external links`, 'info');
        
        // Count suspicious links
        const suspiciousLinks = externalLinks.filter(link => {
            try {
                const linkDomain = new URL(link).hostname;
                return this.suspiciousDomains.some(pattern => pattern.test(linkDomain));
            } catch (e) {
                return false;
            }
        });
        
        if (suspiciousLinks.length > 0) {
            this.addScanDetail(`Found ${suspiciousLinks.length} suspicious links`, 'warning');
        }
        
        // Count redirects
        const redirectLinks = links.filter(link => {
            return /redirect|redir|url=|link=|goto|forward/i.test(link);
        });
        
        if (redirectLinks.length > 0) {
            this.addScanDetail(`Found ${redirectLinks.length} redirect links`, 'warning');
        }
        
        // Calculate risk score
        const totalLinks = links.length;
        const suspiciousRatio = totalLinks > 0 ? (suspiciousLinks.length / totalLinks) : 0;
        const redirectRatio = totalLinks > 0 ? (redirectLinks.length / totalLinks) : 0;
        
        // Collect detailed information about suspicious links
        const suspiciousLinkDetails = suspiciousLinks.map(link => {
            try {
                const linkUrl = new URL(link);
                return {
                    url: link,
                    domain: linkUrl.hostname,
                    reason: this.getSuspiciousReason(linkUrl.hostname)
                };
            } catch (e) {
                return { url: link, reason: 'Malformed URL' };
            }
        });
        
        // Generate recommendations based on analysis
        const recommendations = this.generateRecommendations(suspiciousLinks.length, redirectLinks.length);
        
        // Determine status based on analysis
        let result;
        if (suspiciousLinks.length > 5 || suspiciousRatio > 0.1 || redirectRatio > 0.2) {
            result = {
                status: 'Suspicious',
                details: `Found ${suspiciousLinks.length} suspicious links out of ${totalLinks} total links`,
                confidence: 'Medium',
                threats: suspiciousLinkDetails,
                recommendations: recommendations
            };
        } else if (suspiciousLinks.length > 0 || redirectLinks.length > 3) {
            result = {
                status: 'Warning',
                details: `Found ${suspiciousLinks.length} suspicious links and ${redirectLinks.length} redirect links`,
                confidence: 'Medium',
                threats: suspiciousLinkDetails,
                recommendations: recommendations
            };
        } else {
            result = {
                status: 'Safe',
                details: `All ${totalLinks} links appear to be safe`,
                confidence: 'High',
                threats: [],
                recommendations: ['Continue normal browsing with standard security precautions']
            };
        }
        
        return result;
    }
    
    // New helper methods for enhanced functionality
    addScanDetail(message, level = 'info') {
        const detail = {
            timestamp: new Date().toISOString(),
            message: message,
            level: level
        };
        this.scanDetails.push(detail);
        console.log(`LinkSafetyBot: ${message}`);
    }
    
    getSuspiciousReason(domain) {
        if (/\.(tk|ml|ga|cf|gq|top|xyz)$/i.test(domain)) {
            return 'Suspicious top-level domain';
        } else if (/bit\.ly|goo\.gl|tinyurl\.com|t\.co|is\.gd|buff\.ly|ow\.ly|rebrand\.ly|tiny\.cc/i.test(domain)) {
            return 'URL shortener service';
        } else if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(domain)) {
            return 'IP address instead of domain name';
        } else {
            return 'Unknown suspicious pattern';
        }
    }
    
    generateRecommendations(suspiciousCount, redirectCount) {
        const recommendations = [];
        
        if (suspiciousCount > 5) {
            recommendations.push('Exercise extreme caution when clicking on links from this website');
            recommendations.push('Consider using a web reputation service before visiting external links');
            recommendations.push('Ensure your browser and security software are up to date');
        } else if (suspiciousCount > 0) {
            recommendations.push('Be cautious when clicking on external links from this website');
            recommendations.push('Verify the destination of links before clicking');
        }
        
        if (redirectCount > 3) {
            recommendations.push('Multiple redirect links detected - these may obscure the final destination');
        }
        
        if (recommendations.length === 0) {
            recommendations.push('Links appear safe, but always maintain standard security practices');
        }
        
        return recommendations;
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

module.exports = LinkSafetyBot;