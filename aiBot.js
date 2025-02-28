// AI-powered Security Bot using Gemini Pro

class AIBot {
    constructor(apiKey) {
        this.apiKey = apiKey || 'AIzaSyBW47rCM2xYdKkO1_Buqr0hJ8gnuVC5rq8'; // Default API key from user's request
        this.apiUrl = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent';
        this.scanProgress = 0;
        this.scanStatus = 'idle';
        this.lastScanResults = null;
    }

    async analyzeContent(url) {
        try {
            this.scanStatus = 'scanning';
            this.scanProgress = 10;
            console.log('AI Bot: Starting comprehensive security analysis...');

            // Fetch the page content
            const response = await fetch(url);
            const html = await response.text();
            this.scanProgress = 30;
            console.log('AI Bot: Content fetched successfully, analyzing structure...');
            
            // Extract text content from HTML with enhanced cleaning
            const textContent = this.extractTextContent(html);
            const urlInfo = this.extractUrlInfo(url);
            this.scanProgress = 50;
            console.log('AI Bot: Content extracted and cleaned, preparing for AI analysis...');
            
            // Enhanced prompt for more detailed analysis
            const prompt = this.buildAnalysisPrompt(urlInfo, textContent);
            this.scanProgress = 70;
            console.log('AI Bot: Sending content to Gemini Pro for analysis...');
            
            // Call Gemini Pro API with enhanced error handling
            const aiResponse = await this.callGeminiAPI(prompt);
            this.scanProgress = 90;
            console.log('AI Bot: AI analysis complete, parsing results...');
            
            // Parse and enhance the AI response
            const result = this.parseAIResponse(aiResponse);
            this.scanProgress = 100;
            this.scanStatus = 'complete';
            this.lastScanResults = result;
            console.log('AI Bot: Analysis complete, results ready.');
            
            return result;
        } catch (error) {
            console.error('AI Bot error:', error);
            this.scanStatus = 'error';
            return {
                status: 'Warning',
                details: 'Unable to perform AI analysis',
                confidence: 'Low',
                threats: [],
                recommendations: ['Unable to complete the security analysis. Please try again.']
            };
        }
    }
    
    extractUrlInfo(url) {
        const urlObj = new URL(url);
        return {
            url: url,
            domain: urlObj.hostname,
            protocol: urlObj.protocol,
            path: urlObj.pathname,
            query: urlObj.search,
            timestamp: new Date().toISOString()
        };
    }

    buildAnalysisPrompt(urlInfo, textContent) {
        return `Perform a comprehensive security analysis of this website. Examine for:

1. Phishing Indicators:
   - Domain similarity to known brands
   - Suspicious URL patterns
   - Login form presence and context
   - Brand impersonation attempts

2. Malicious Content:
   - Suspicious script patterns
   - Hidden iframes or redirects
   - Malware distribution indicators
   - Exploit kit signatures

3. Scam/Fraud Detection:
   - High-pressure tactics
   - Unrealistic offers
   - Payment/financial information requests
   - Trust signal abuse

4. Misinformation Analysis:
   - Content authenticity
   - Source credibility
   - Fact verification indicators
   - Manipulation techniques

5. Privacy/Data Collection:
   - Tracking mechanisms
   - Data collection practices
   - Privacy policy presence
   - User data handling

Site Information:
${JSON.stringify(urlInfo, null, 2)}

Content Sample:
${textContent.substring(0, 2000)}... (truncated)

Provide a detailed security assessment with:
- Threat Level: (Safe, Warning, Suspicious, Dangerous)
- Confidence Level: (High, Medium, Low)
- Specific Threats: (List all identified threats)
- Recommendations: (Actionable security advice)
- Technical Details: (Relevant technical findings)`;
    }
    
    async callGeminiAPI(prompt) {
        try {
            const response = await fetch(`${this.apiUrl}?key=${this.apiKey}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    contents: [{
                        parts: [{
                            text: prompt
                        }]
                    }]
                })
            });
            
            if (!response.ok) {
                throw new Error(`API request failed with status ${response.status}`);
            }
            
            const data = await response.json();
            return data.candidates[0].content.parts[0].text;
        } catch (error) {
            console.error('Gemini API error:', error);
            return 'Unable to analyze content with AI';
        }
    }
    
    extractTextContent(html) {
        // Use regex-based extraction instead of DOM manipulation
        // First, remove script, style and other non-content tags
        let cleanedHtml = html
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
            .replace(/<noscript\b[^<]*(?:(?!<\/noscript>)<[^<]*)*<\/noscript>/gi, '')
            .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
        
        // Remove HTML tags while preserving content
        let textContent = cleanedHtml
            .replace(/<[^>]*>/g, ' ')
            .replace(/\s+/g, ' ')
            .replace(/[\r\n]+/g, '\n')
            .trim();
        
        return textContent;
    }
    
    parseAIResponse(aiResponse) {
        let result = {
            status: 'Warning',
            details: 'AI analysis inconclusive',
            confidence: 'Low',
            threats: [],
            recommendations: [],
            technicalDetails: [],
            scanTimestamp: new Date().toISOString()
        };
        
        try {
            if (aiResponse === 'Unable to analyze content with AI') {
                return result;
            }

            // Enhanced pattern matching for better accuracy
            const threatLevelMatch = aiResponse.match(/threat level:?\s*(safe|warning|suspicious|dangerous)/i);
            if (threatLevelMatch) {
                const threatLevel = threatLevelMatch[1].toLowerCase();
                result.status = {
                    'safe': 'Safe',
                    'warning': 'Warning',
                    'suspicious': 'Suspicious',
                    'dangerous': 'Dangerous'
                }[threatLevel] || 'Warning';
            }

            // Enhanced confidence level parsing
            const confidenceMatch = aiResponse.match(/confidence level:?\s*(high|medium|low)/i);
            if (confidenceMatch) {
                result.confidence = confidenceMatch[1].charAt(0).toUpperCase() + confidenceMatch[1].slice(1);
            }

            // Improved threat extraction
            const threatSection = aiResponse.match(/specific threats[^:]*:([^\n]*(?:\n(?!confidence|recommendations|technical)[^\n]*)*)/i);
            if (threatSection) {
                result.threats = threatSection[1]
                    .split(/\n|\*|•/)
                    .map(line => line.trim())
                    .filter(line => line && !line.toLowerCase().includes('none') && !line.toLowerCase().includes('no threats'));
            }

            // Enhanced recommendations parsing
            const recommendationSection = aiResponse.match(/recommendations[^:]*:([^\n]*(?:\n(?!threat|confidence|technical)[^\n]*)*)/i);
            if (recommendationSection) {
                result.recommendations = recommendationSection[1]
                    .split(/\n|\*|•/)
                    .map(line => line.trim())
                    .filter(line => line);
            }

            // New: Technical details parsing
            const technicalSection = aiResponse.match(/technical details[^:]*:([^\n]*(?:\n(?!threat|confidence|recommendations)[^\n]*)*)/i);
            if (technicalSection) {
                result.technicalDetails = technicalSection[1]
                    .split(/\n|\*|•/)
                    .map(line => line.trim())
                    .filter(line => line);
            }

            // Enhanced details compilation
            const details = [];
            if (result.threats.length > 0) {
                details.push(`Identified ${result.threats.length} threat(s)`);
            }
            if (result.confidence !== 'Low') {
                details.push(`${result.confidence} confidence assessment`);
            }
            if (result.recommendations.length > 0) {
                details.push(`${result.recommendations.length} security recommendation(s)`);
            }
            if (result.technicalDetails.length > 0) {
                details.push(`${result.technicalDetails.length} technical finding(s)`);
            }

            result.details = details.join('. ') || 'No immediate security concerns identified';
            
        } catch (error) {
            console.error('Error parsing AI response:', error);
        }
        
        return result;
    }

    getProgress() {
        return {
            progress: this.scanProgress,
            status: this.scanStatus,
            lastResults: this.lastScanResults
        };
    }
}

module.exports = AIBot;