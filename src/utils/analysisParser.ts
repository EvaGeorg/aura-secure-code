import { SecurityFinding } from '@/components/ResultsPanel';

export interface ParsedAnalysis {
  score: number;
  findings: SecurityFinding[];
  summary: string;
}

export const parseGeminiAnalysis = (rawAnalysis: string): ParsedAnalysis => {
  const lines = rawAnalysis.split('\n');
  const findings: SecurityFinding[] = [];
  let currentFinding: Partial<SecurityFinding> | null = null;
  let summary = '';
  let score = 7; // Default score

  // Extract overall security rating if mentioned
  const ratingMatch = rawAnalysis.match(/(?:security\s+)?(?:rating|score)(?:\s*:)?\s*(\d+)(?:\/10)?/i);
  if (ratingMatch) {
    score = parseInt(ratingMatch[1]);
  }

  // Extract summary from the first paragraph or overall assessment
  const summaryMatch = rawAnalysis.match(/(?:## )?(?:Summary|Overall|Analysis)[\s\S]*?\n\n(.*?)(?:\n\n|$)/i);
  if (summaryMatch) {
    summary = summaryMatch[1].trim();
  } else {
    // Fallback: use first meaningful paragraph
    const firstParagraph = rawAnalysis.split('\n\n')[0];
    summary = firstParagraph.length > 20 ? firstParagraph : 'Security analysis completed';
  }

  let findingId = 1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    // Skip empty lines
    if (!line) continue;

    // Detect vulnerability sections (various patterns)
    if (isVulnerabilityTitle(line)) {
      // Save previous finding if exists
      if (currentFinding && currentFinding.title) {
        findings.push(completeFinding(currentFinding, findingId++));
      }

      // Start new finding
      currentFinding = {
        title: cleanTitle(line),
        severity: extractSeverity(line, rawAnalysis.substring(rawAnalysis.indexOf(line))),
        category: extractCategory(line),
        description: '',
        recommendation: ''
      };
    }
    // Extract description content
    else if (currentFinding && isDescriptionContent(line)) {
      if (line.toLowerCase().includes('recommendation') || line.toLowerCase().includes('fix') || line.toLowerCase().includes('solution')) {
        currentFinding.recommendation = (currentFinding.recommendation || '') + ' ' + line.replace(/^[*-]\s*/, '').trim();
      } else {
        currentFinding.description = (currentFinding.description || '') + ' ' + line.replace(/^[*-]\s*/, '').trim();
      }
    }
    // Extract code snippets
    else if (line.startsWith('```') && currentFinding) {
      let codeBlock = '';
      i++; // Skip the opening ```
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeBlock += lines[i] + '\n';
        i++;
      }
      currentFinding.codeSnippet = codeBlock.trim();
    }
    // Extract CWE/OWASP references
    else if (currentFinding && (line.includes('CWE') || line.includes('OWASP'))) {
      const cweMatch = line.match(/CWE[:-]\s*(\d+)/i);
      const owaspMatch = line.match(/OWASP\s+([\w\s]+)/i);
      
      if (cweMatch) currentFinding.cweId = cweMatch[1];
      if (owaspMatch) currentFinding.owaspRef = owaspMatch[1].trim();
    }
  }

  // Don't forget the last finding
  if (currentFinding && currentFinding.title) {
    findings.push(completeFinding(currentFinding, findingId));
  }

  // If no structured findings found, create general findings from the analysis
  if (findings.length === 0) {
    findings.push(...extractGeneralFindings(rawAnalysis));
  }

  // Calculate score based on findings
  if (findings.length > 0) {
    const severityWeights = { critical: 0, high: 2, medium: 5, low: 7 };
    const avgSeverity = findings.reduce((sum, f) => sum + (severityWeights[f.severity] || 5), 0) / findings.length;
    score = Math.max(1, Math.min(10, Math.round(avgSeverity)));
  }

  return {
    score,
    findings,
    summary: summary || 'Code analysis completed successfully'
  };
};

function isVulnerabilityTitle(line: string): boolean {
  const patterns = [
    /^\s*[-*]\s*\*\*.*\*\*/,  // - **Title**
    /^\s*\d+\.\s*\*\*.*\*\*/, // 1. **Title**
    /^\s*#+\s+/,              // ## Title
    /vulnerability|injection|xss|csrf|authentication|authorization|hardcoded|insecure|weak/i
  ];
  
  return patterns.some(pattern => pattern.test(line)) && line.length > 10;
}

function cleanTitle(line: string): string {
  return line
    .replace(/^\s*[-*]\s*/, '')
    .replace(/^\s*\d+\.\s*/, '')
    .replace(/^\s*#+\s*/, '')
    .replace(/\*\*/g, '')
    .replace(/:/g, '')
    .trim();
}

function extractSeverity(line: string, context: string): 'critical' | 'high' | 'medium' | 'low' {
  const text = (line + ' ' + context.substring(0, 500)).toLowerCase();
  
  if (text.includes('critical') || text.includes('severe')) return 'critical';
  if (text.includes('high') || text.includes('dangerous')) return 'high';
  if (text.includes('medium') || text.includes('moderate')) return 'medium';
  if (text.includes('low') || text.includes('minor')) return 'low';
  
  // Severity based on vulnerability type
  if (text.includes('sql injection') || text.includes('xss') || text.includes('command injection')) return 'critical';
  if (text.includes('hardcoded') || text.includes('weak password') || text.includes('authentication')) return 'high';
  if (text.includes('path traversal') || text.includes('information disclosure')) return 'medium';
  
  return 'medium'; // Default
}

function extractCategory(line: string): string {
  const text = line.toLowerCase();
  
  if (text.includes('injection')) return 'Injection';
  if (text.includes('xss') || text.includes('cross-site')) return 'Cross-Site Scripting';
  if (text.includes('authentication') || text.includes('auth')) return 'Authentication';
  if (text.includes('authorization') || text.includes('access')) return 'Authorization';
  if (text.includes('hardcoded') || text.includes('credential')) return 'Hardcoded Secrets';
  if (text.includes('path') || text.includes('traversal')) return 'Path Traversal';
  if (text.includes('validation') || text.includes('input')) return 'Input Validation';
  if (text.includes('encryption') || text.includes('crypto')) return 'Cryptography';
  
  return 'Security Misconfiguration';
}

function isDescriptionContent(line: string): boolean {
  return line.length > 5 && 
         !line.startsWith('#') && 
         !line.startsWith('```') &&
         !line.match(/^\s*[-*]\s*\*\*/) &&
         !line.match(/^\s*\d+\.\s*\*\*/);
}

function completeFinding(finding: Partial<SecurityFinding>, id: number): SecurityFinding {
  return {
    id: `finding-${id}`,
    title: finding.title || 'Security Issue',
    severity: finding.severity || 'medium',
    category: finding.category || 'Security Misconfiguration',
    description: finding.description?.trim() || 'Security vulnerability detected',
    recommendation: finding.recommendation?.trim() || 'Review and fix this security issue',
    lineNumber: finding.lineNumber,
    codeSnippet: finding.codeSnippet,
    cweId: finding.cweId,
    owaspRef: finding.owaspRef
  };
}

function extractGeneralFindings(analysis: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  
  // Look for common vulnerability mentions
  const vulnerabilities = [
    { pattern: /sql injection/gi, title: 'SQL Injection Vulnerability', severity: 'critical' as const, category: 'Injection' },
    { pattern: /xss|cross-site scripting/gi, title: 'Cross-Site Scripting (XSS)', severity: 'critical' as const, category: 'XSS' },
    { pattern: /command injection/gi, title: 'Command Injection', severity: 'critical' as const, category: 'Injection' },
    { pattern: /hardcoded.*(?:password|secret|key|credential)/gi, title: 'Hardcoded Credentials', severity: 'high' as const, category: 'Hardcoded Secrets' },
    { pattern: /path traversal/gi, title: 'Path Traversal Vulnerability', severity: 'medium' as const, category: 'Path Traversal' },
    { pattern: /insecure.*authentication/gi, title: 'Insecure Authentication', severity: 'high' as const, category: 'Authentication' }
  ];

  vulnerabilities.forEach((vuln, index) => {
    if (vuln.pattern.test(analysis)) {
      findings.push({
        id: `general-${index + 1}`,
        title: vuln.title,
        severity: vuln.severity,
        category: vuln.category,
        description: `${vuln.title} detected in the code analysis.`,
        recommendation: `Address the ${vuln.title.toLowerCase()} by implementing proper security measures.`
      });
    }
  });

  // If still no findings, create a general one
  if (findings.length === 0) {
    findings.push({
      id: 'general-1',
      title: 'Code Analysis Complete',
      severity: 'low',
      category: 'General',
      description: 'Code analysis has been completed. Review the full analysis for details.',
      recommendation: 'Review the complete analysis and implement suggested improvements.'
    });
  }

  return findings;
}