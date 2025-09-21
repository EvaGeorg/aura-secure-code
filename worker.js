// Security-Focused Cloudflare Worker with Exact Output Format
export default {
  async fetch(request, env, ctx) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Only allow POST requests
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), { 
        status: 405, 
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    try {
      const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
      
      // Rate limiting: 20 analyses per hour for free tier
      if (env.KV) {
        const rateLimitKey = `security_analysis:${clientIP}`;
        const requestCount = parseInt(await env.KV.get(rateLimitKey) || '0');
        
        if (requestCount >= 20) {
          return new Response(JSON.stringify({
            error: 'Rate limit exceeded. Maximum 20 security analyses per hour for free tier.',
            retryAfter: 3600
          }), {
            status: 429,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
        
        await env.KV.put(rateLimitKey, (requestCount + 1).toString(), { expirationTtl: 3600 });
      }

      const body = await request.json();
      const { code, language, fileName, userApiKey } = body;
      
      console.log('Request received:', { 
        hasCode: !!code, 
        codeLength: code?.length, 
        language, 
        fileName, 
        hasUserApiKey: !!userApiKey 
      });

      // Input validation
      if (!code || typeof code !== 'string') {
        console.log('ERROR: Missing or invalid code');
        return new Response(JSON.stringify({ error: 'Code is required' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // Security: Limit code length (prevent abuse)
      if (code.length > 50000) {
        console.log('ERROR: Code too large:', code.length);
        return new Response(JSON.stringify({ error: 'Code too large (max 50KB per file)' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // Validate language parameter
      const supportedLanguages = [
        'javascript', 'typescript', 'python', 'java', 'php', 'csharp', 'cpp', 'c', 'go', 
        'rust', 'ruby', 'swift', 'kotlin', 'sql', 'html', 'css', 'shell', 'bash', 'yaml', 
        'json', 'dockerfile', 'xml', 'perl', 'scala', 'r'
      ];
      
      const detectedLanguage = language && supportedLanguages.includes(language.toLowerCase()) 
        ? language.toLowerCase() 
        : 'auto-detect';

      // API Key debugging
      const apiKey = userApiKey || env.GEMINI_API_KEY;
      console.log('API Key check:', { 
        hasUserKey: !!userApiKey, 
        hasEnvKey: !!env.GEMINI_API_KEY, 
        hasAnyKey: !!apiKey,
        userKeyLength: userApiKey?.length,
        envKeyLength: env.GEMINI_API_KEY?.length
      });
      
      if (!apiKey) {
        console.log('ERROR: No API key found - neither user key nor env key available');
        return new Response(JSON.stringify({ error: 'Service temporarily unavailable' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // Create the security analysis prompt with exact format requirements
      const codeBlock = `\`\`\`${detectedLanguage}\n${code}\n\`\`\``;
      const fileInfo = fileName ? `File: ${fileName}\n` : '';
      
      const prompt = `As a senior cybersecurity engineer, perform a comprehensive security vulnerability analysis of this code. You must follow the EXACT format specified below.

${fileInfo}${codeBlock}

You MUST provide your analysis in this EXACT format:

**Overall Security Score: [X]/10**

**Critical Vulnerabilities**
1. [Vulnerability Name]
[Description of the vulnerability]
OWASP Reference: [Reference if applicable]
Recommendation & Fix: [Specific fix recommendation]
\`\`\`${detectedLanguage}
[Code example of fix if applicable]
\`\`\`

**High Vulnerabilities**
1. [Vulnerability Name]
[Description]
OWASP Reference: [Reference]
Recommendation & Fix: [Fix recommendation]

**Medium Vulnerabilities**
1. [Vulnerability Name]
[Description]
OWASP Reference: [Reference]
Recommendation & Fix: [Fix recommendation]

**Low Vulnerabilities**
1. [Vulnerability Name]
[Description]
OWASP Reference: [Reference]
Recommendation & Fix: [Fix recommendation]

IMPORTANT FORMATTING RULES:
- Use the EXACT headers "Critical Vulnerabilities", "High Vulnerabilities", "Medium Vulnerabilities", "Low Vulnerabilities"
- Number each vulnerability starting from 1 within each section
- Always include "OWASP Reference:" and "Recommendation & Fix:" labels
- If no vulnerabilities exist for a severity level, write "None found" under that section
- Include code examples in fixes when applicable
- Focus on: SQL injection, XSS, authentication bypass, insecure cryptography, input validation, access control, buffer overflows, path traversal, CSRF, insecure deserialization, hardcoded secrets, and other OWASP Top 10 issues`;

      // Log request (without code content for privacy)
      console.log(`Security analysis starting: IP=${clientIP}, language=${detectedLanguage}, file=${fileName || 'direct'}, size=${code.length}chars`);

      // Call Gemini API with extended timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 45000); // 45 second timeout

      console.log(`Calling Gemini API with key: ${apiKey.substring(0, 10)}...`);
      
      const geminiResponse = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          signal: controller.signal,
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
              temperature: 0.1, // Very low temperature for consistent, structured output
              topK: 40,
              topP: 0.8,
              maxOutputTokens: 2048,
            },
            safetySettings: [
              {
                category: "HARM_CATEGORY_HARASSMENT",
                threshold: "BLOCK_MEDIUM_AND_ABOVE"
              },
              {
                category: "HARM_CATEGORY_HATE_SPEECH", 
                threshold: "BLOCK_MEDIUM_AND_ABOVE"
              },
              {
                category: "HARM_CATEGORY_DANGEROUS_CONTENT",
                threshold: "BLOCK_MEDIUM_AND_ABOVE"
              }
            ]
          })
        }
      );

      clearTimeout(timeoutId);
      
      console.log(`Gemini API response status: ${geminiResponse.status}`);

      if (!geminiResponse.ok) {
        const errorText = await geminiResponse.text();
        console.error(`Gemini API error: ${geminiResponse.status} - ${errorText}`);
        
        // Handle specific error cases
        if (geminiResponse.status === 429) {
          return new Response(JSON.stringify({
            error: 'AI service rate limit exceeded. Please try again in a few minutes.',
          }), {
            status: 429,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
        
        return new Response(JSON.stringify({
          error: 'Security analysis service temporarily unavailable'
        }), {
          status: 503,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      const data = await geminiResponse.json();
      const analysis = data.candidates?.[0]?.content?.parts?.[0]?.text;
      
      console.log('Gemini response received:', { 
        hasData: !!data, 
        hasCandidates: !!data.candidates,
        hasAnalysis: !!analysis,
        analysisLength: analysis?.length 
      });
      
      if (!analysis) {
        console.log('ERROR: No analysis text in Gemini response');
        return new Response(JSON.stringify({
          error: 'Security analysis could not be completed'
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      // Extract security score from analysis if present
      const scoreMatch = analysis.match(/\*\*Overall Security Score: (\d+)\/10\*\*/);
      const securityScore = scoreMatch ? parseInt(scoreMatch[1]) : null;

      // Count vulnerabilities by severity
      const criticalCount = (analysis.match(/\*\*Critical Vulnerabilities\*\*[\s\S]*?(?=\*\*High Vulnerabilities\*\*|$)/)?.[0]?.match(/^\d+\./gm) || []).length;
      const highCount = (analysis.match(/\*\*High Vulnerabilities\*\*[\s\S]*?(?=\*\*Medium Vulnerabilities\*\*|$)/)?.[0]?.match(/^\d+\./gm) || []).length;
      const mediumCount = (analysis.match(/\*\*Medium Vulnerabilities\*\*[\s\S]*?(?=\*\*Low Vulnerabilities\*\*|$)/)?.[0]?.match(/^\d+\./gm) || []).length;
      const lowCount = (analysis.match(/\*\*Low Vulnerabilities\*\*[\s\S]*?$/)?.[0]?.match(/^\d+\./gm) || []).length;

      // Log successful analysis
      console.log(`Security analysis completed: IP=${clientIP}, score=${securityScore}, vulnerabilities=C:${criticalCount},H:${highCount},M:${mediumCount},L:${lowCount}`);

      return new Response(JSON.stringify({
        success: true,
        analysis: analysis,
        metadata: {
          fileName: fileName || 'direct-input',
          language: detectedLanguage,
          codeLength: code.length,
          securityScore: securityScore,
          vulnerabilityCounts: {
            critical: criticalCount,
            high: highCount,
            medium: mediumCount,
            low: lowCount,
            total: criticalCount + highCount + mediumCount + lowCount
          },
          timestamp: new Date().toISOString(),
          mode: userApiKey ? 'user-key' : 'server-key'
        }
      }), {
        headers: { 
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          ...corsHeaders 
        }
      });

    } catch (error) {
      console.error('Worker error:', error.message, error.stack);
      
      if (error.name === 'AbortError') {
        return new Response(JSON.stringify({
          error: 'Security analysis timeout - code too complex or large'
        }), {
          status: 408,
          headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
      }

      return new Response(JSON.stringify({
        error: 'Internal server error during security analysis'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
};