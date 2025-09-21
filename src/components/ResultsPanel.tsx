import { useState } from 'react';
import { motion } from 'framer-motion';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { 
  Shield, 
  AlertTriangle, 
  AlertCircle, 
  Info, 
  CheckCircle, 
  ChevronDown,
  Copy,
  Download,
  Zap,
  Code
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

export interface SecurityFinding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  description: string;
  lineNumber?: number;
  codeSnippet?: string;
  recommendation: string;
  cweId?: string;
  owaspRef?: string;
}

interface ResultsPanelProps {
  isAnalyzing: boolean;
  results: {
    score: number;
    findings: SecurityFinding[];
    summary: string;
  } | null;
}

export const ResultsPanel = ({ isAnalyzing, results }: ResultsPanelProps) => {
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const { toast } = useToast();

  const toggleFinding = (id: string) => {
    const newExpanded = new Set(expandedFindings);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedFindings(newExpanded);
  };

  const copyFinding = (finding: SecurityFinding) => {
    const text = `${finding.title}\n\nSeverity: ${finding.severity.toUpperCase()}\nCategory: ${finding.category}\n\nDescription: ${finding.description}\n\nRecommendation: ${finding.recommendation}`;
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "Finding details have been copied.",
    });
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertCircle className="h-4 w-4" />;
      case 'high': return <AlertTriangle className="h-4 w-4" />;
      case 'medium': return <Info className="h-4 w-4" />;
      case 'low': return <CheckCircle className="h-4 w-4" />;
      default: return <Info className="h-4 w-4" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'secondary';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 8) return 'text-success';
    if (score >= 6) return 'text-warning';
    return 'text-destructive';
  };

  const severityCounts = results?.findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>) || {};

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-5 w-5 text-primary" />
          <h2 className="text-xl font-semibold text-neon">Security Analysis</h2>
        </div>
        
        {results && (
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => copyFinding(results.findings[0])}
              className="glass border-primary/30"
            >
              <Copy className="h-4 w-4 mr-2" />
              Copy
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="glass border-primary/30"
            >
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        )}
      </div>

      {/* Loading State */}
      {isAnalyzing && (
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex-1 flex flex-col items-center justify-center space-y-6"
        >
          <motion.div
            animate={{ 
              rotate: 360,
              scale: [1, 1.1, 1]
            }}
            transition={{ 
              rotate: { duration: 2, repeat: Infinity, ease: "linear" },
              scale: { duration: 1, repeat: Infinity }
            }}
            className="relative"
          >
            <div className="w-16 h-16 rounded-full bg-gradient-to-r from-primary to-primary-glow flex items-center justify-center">
              <Zap className="h-8 w-8 text-primary-foreground" />
            </div>
            <div className="absolute inset-0 w-16 h-16 rounded-full animate-ping bg-primary/30" />
          </motion.div>
          
          <div className="text-center space-y-2">
            <h3 className="text-lg font-medium text-neon">AI Analyzing Your Code</h3>
            <p className="text-muted-foreground">
              Scanning for vulnerabilities, performance issues, and best practices...
            </p>
          </div>

          <div className="w-full max-w-md space-y-2">
            <Progress value={65} className="h-2" />
            <div className="flex justify-between text-sm text-muted-foreground">
              <span>Analyzing patterns...</span>
              <span>65%</span>
            </div>
          </div>
        </motion.div>
      )}

      {/* Empty State */}
      {!isAnalyzing && !results && (
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex-1 flex flex-col items-center justify-center space-y-4"
        >
          <div className="w-16 h-16 rounded-full bg-muted/20 flex items-center justify-center">
            <Shield className="h-8 w-8 text-muted-foreground" />
          </div>
          <div className="text-center">
            <h3 className="text-lg font-medium mb-2">Ready for Analysis</h3>
            <p className="text-muted-foreground">
              Paste your code and click "Analyze Code" to get started
            </p>
          </div>
        </motion.div>
      )}

      {/* Results */}
      {results && !isAnalyzing && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex-1 space-y-4 overflow-auto"
        >
          {/* Summary Card */}
          <Card className="glass-card">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    Security Score
                    <Badge variant="outline" className="text-xs">
                      {results.findings.length} issues found
                    </Badge>
                  </CardTitle>
                  <CardDescription>{results.summary}</CardDescription>
                </div>
                <div className="text-center">
                  <div className={`text-3xl font-bold ${getScoreColor(results.score)}`}>
                    {results.score}/10
                  </div>
                  <div className="text-sm text-muted-foreground">Overall</div>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-4 gap-4">
                {[
                  { key: 'critical', label: 'Critical', icon: AlertCircle },
                  { key: 'high', label: 'High', icon: AlertTriangle },
                  { key: 'medium', label: 'Medium', icon: Info },
                  { key: 'low', label: 'Low', icon: CheckCircle }
                ].map(({ key, label, icon: Icon }) => (
                  <div key={key} className="text-center">
                    <div className={`severity-${key} flex items-center justify-center gap-1 mb-1`}>
                      <Icon className="h-4 w-4" />
                      <span className="font-medium">{severityCounts[key] || 0}</span>
                    </div>
                    <div className="text-xs text-muted-foreground">{label}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Findings List */}
          <div className="space-y-3">
            {results.findings.map((finding) => (
              <Card key={finding.id} className="glass-card">
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <div className={`severity-${finding.severity} mt-1`}>
                      {getSeverityIcon(finding.severity)}
                    </div>
                    <div className="flex-1 space-y-3">
                      {/* Vulnerability Name & Severity */}
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <h3 className="text-base font-medium">{finding.title}</h3>
                          <Badge 
                            variant={getSeverityColor(finding.severity) as any}
                            className="text-xs"
                          >
                            {finding.severity.toUpperCase()}
                          </Badge>
                        </div>
                      </div>

                      {/* Recommendation & Fix */}
                      <div className="space-y-2">
                        <div>
                          <h4 className="text-sm font-medium text-muted-foreground mb-1">Fix:</h4>
                          <p className="text-sm text-success">{finding.recommendation}</p>
                        </div>
                      </div>

                      {/* Copy button */}
                      <div className="flex justify-end">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyFinding(finding)}
                          className="text-muted-foreground hover:text-foreground"
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
};