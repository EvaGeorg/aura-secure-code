import { SecurityFinding } from '@/components/ResultsPanel';

export interface ParsedAnalysis {
  score: number;
  findings: SecurityFinding[];
  summary: string;
}

export const parseGeminiAnalysis = (rawAnalysis: string): ParsedAnalysis => {
  const findings: SecurityFinding[] = [];
  let summary = '';
  let score = 7;

  // Extract overall security rating
  const ratingMatch = rawAnalysis.match(/(?:security\s+)?(?:rating|score)(?:\s*:)?\s*(\d+)(?:\/10)?/i);
  if (ratingMatch) {
    score = parseInt(ratingMatch[1]);
  }

  // Extract summary
  const summaryMatch = rawAnalysis.match(/(?:## )?(?:Summary|Overall|Analysis)[\s\S]*?\n\n(.*?)(?:\n\n|$)/i);
  if (summaryMatch) {
    summary = summaryMatch[1].trim();
  } else {
    const firstParagraph = rawAnalysis.split('\n\n')[0];
    summary = firstParagraph.length > 20 ? firstParagraph : 'Security analysis completed';
  }

  // Split analysis into sections by numbered items, bullet points, or headers
  const sections = rawAnalysis.split(/(?:\n\s*(?:\d+\.|\*\*|\#{1,3}|\-)\s*)|(?:\n\n)/);
  
  let findingId = 1;
  let currentSection = '';
  
  for (const section of sections) {
    const trimmed = section.trim();
    if (!trimmed || trimmed.length < 20) continue;
    
    currentSection += trimmed + '\n\n';
    
    // Check if this section contains vulnerability indicators
    if (hasVulnerabilityIndicators(trimmed)) {
      const finding = extractVulnerabilityFromSection(currentSection, findingId++);
      if (finding) {
        findings.push(finding);
      }
      currentSection = '';
    }
  }

  // Process any remaining section
  if (currentSection.trim() && hasVulnerabilityIndicators(currentSection)) {
    const finding = extractVulnerabilityFromSection(currentSection, findingId);
    if (finding) {
      findings.push(finding);
    }
  }

  // If no structured findings found, create general findings
  if (findings.length === 0) {
    findings.push(...extractGeneralFindings(rawAnalysis));
  }

  // Calculate score based on findings
  if (findings.length > 0) {
    const severityWeights = { critical: 1, high: 3, medium: 6, low: 8 };
    const avgSeverity = findings.reduce((sum, f) => sum + (severityWeights[f.severity] || 5), 0) / findings.length;
    score = Math.max(1, Math.min(10, Math.round(avgSeverity)));
  }

  return {
    score,
    findings,
    summary: summary || 'Code analysis completed successfully'
  };
};

function hasVulnerabilityIndicators(text: string): boolean {
  const vulnerabilityKeywords = [
    'vulnerability', 'injection', 'xss', 'csrf', 'authentication', 'authorization',
    'hardcoded', 'insecure', 'weak', 'exposed', 'security', 'risk', 'threat',
    'exploit', 'attack', 'malicious', 'unsafe', 'deprecated', 'outdated'
  ];
  
  const lowerText = text.toLowerCase();
  return vulnerabilityKeywords.some(keyword => lowerText.includes(keyword));
}

function extractVulnerabilityFromSection(section: string, id: number): SecurityFinding | null {
  const lines = section.split('\n').map(line => line.trim()).filter(line => line);
  if (lines.length === 0) return null;

  // Extract title from first significant line
  let title = lines[0];
  title = cleanTitle(title);
  
  if (!title || title.length < 5) return null;

  // Extract severity and category
  const severity = extractSeverity(title, section);
  const category = extractCategory(title);
  
  // Extract description and recommendation
  let description = '';
  let recommendation = '';
  let codeSnippet = '';
  let lineNumber: number | undefined;
  let cweId: string | undefined;
  let owaspRef: string | undefined;
  
  let isInCodeBlock = false;
  let currentCodeBlock = '';
  
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    
    // Handle code blocks
    if (line.startsWith('```')) {
      if (isInCodeBlock) {
        codeSnippet = currentCodeBlock.trim();
        currentCodeBlock = '';
        isInCodeBlock = false;
      } else {
        isInCodeBlock = true;
      }
      continue;
    }
    
    if (isInCodeBlock) {
      currentCodeBlock += line + '\n';
      continue;
    }
    
    // Extract line numbers
    const lineMatch = line.match(/line\s*(\d+)/i);
    if (lineMatch && !lineNumber) {
      lineNumber = parseInt(lineMatch[1]);
    }
    
    // Extract CWE/OWASP references
    const cweMatch = line.match(/CWE[:-]\s*(\d+)/i);
    const owaspMatch = line.match(/OWASP\s+([\w\s-]+)/i);
    
    if (cweMatch && !cweId) cweId = cweMatch[1];
    if (owaspMatch && !owaspRef) owaspRef = owaspMatch[1].trim();
    
    // Categorize content as description or recommendation
    const lowerLine = line.toLowerCase();
    if (lowerLine.includes('fix') || lowerLine.includes('solution') || 
        lowerLine.includes('recommendation') || lowerLine.includes('should') ||
        lowerLine.includes('mitigation') || lowerLine.includes('prevent')) {
      recommendation += ' ' + line.replace(/^[*-]\s*/, '').trim();
    } else if (line.length > 10 && !line.match(/^\s*[*-]\s*$/)) {
      description += ' ' + line.replace(/^[*-]\s*/, '').trim();
    }
  }
  
  // Clean up final values
  description = description.trim();
  recommendation = recommendation.trim();
  
  // Ensure we have meaningful content
  if (!description) {
    description = `Security issue identified: ${title}`;
  }
  
  if (!recommendation) {
    recommendation = `Review and address the ${category.toLowerCase()} vulnerability.`;
  }

  return {
    id: `finding-${id}`,
    title,
    severity,
    category,
    description,
    recommendation,
    lineNumber,
    codeSnippet: codeSnippet || undefined,
    cweId,
    owaspRef
  };
}

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