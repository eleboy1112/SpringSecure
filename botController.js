// Bot Controller for Website Security Scanning

class BotController {
    constructor() {
        this.trustedDomains = [
            'google.com',
            'gmail.com',
            'youtube.com',
            'drive.google.com',
            'docs.google.com',
            'microsoft.com',
            'github.com',
            'stackoverflow.com'
        ];
        
        // Initialize bots
        this.sslBot = new SSLBot();
        this.malwareBot = new MalwareBot();
        this.phishingBot = new PhishingBot();
        this.linkSafetyBot = new LinkSafetyBot();
        this.aiBot = new AIBot();
    }

    async analyzeSecurity(url) {
        const domain = this.extractDomain(url);
        
        if (this.isTrustedDomain(domain)) {
            return {
                score: 95,
                ssl: { status: 'Secure', details: 'Valid SSL Certificate' },
                malware: { status: 'Clean', details: 'Trusted Domain' },
                phishing: { status: 'Safe', details: 'Verified Domain' },
                linkSafety: { status: 'Safe', details: 'Verified Links' },
                ai: { status: 'Safe', details: 'Trusted Domain Analysis' }
            };
        }

        const results = await Promise.all([
            this.sslBot.checkSSL(url),
            this.malwareBot.scanMalware(url),
            this.phishingBot.analyzePhishing(url),
            this.linkSafetyBot.validateLinks(url),
            this.aiBot.analyzeContent(url)
        ]);

        return {
            score: this.calculateScore(results),
            ssl: results[0],
            malware: results[1],
            phishing: results[2],
            linkSafety: results[3],
            ai: results[4]
        };
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

    calculateScore(results) {
        const weights = {
            ssl: 0.25,
            malware: 0.3,
            phishing: 0.2,
            linkSafety: 0.15,
            ai: 0.1
        };

        let totalScore = 0;
        let detailedResults = [];

        results.forEach((result, index) => {
            const category = Object.keys(weights)[index];
            const categoryScore = this.getCategoryScore(result);
            totalScore += categoryScore * weights[category];

            detailedResults.push({
                category: category,
                score: categoryScore,
                status: result.status,
                details: result.details,
                confidence: result.confidence,
                threats: result.threats,
                recommendations: result.recommendations
            });
        });

        // Log detailed results for debugging
        console.log('Detailed Security Analysis:', detailedResults);

        return Math.round(totalScore);
    }

    getCategoryScore(result) {
        const statusScores = {
            'Secure': 100,
            'Clean': 100,
            'Safe': 100,
            'Active': 100,
            'Warning': 60,
            'Suspicious': 40,
            'Dangerous': 0
        };
        return statusScores[result.status] || 0;
    }
}

module.exports = BotController;