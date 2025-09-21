import { motion } from 'framer-motion';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  Copy,
  Download,
  Zap,
  CheckCircle
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface AnalysisDisplayProps {
  isAnalyzing: boolean;
  analysis: string | null;
}

export const AnalysisDisplay = ({ isAnalyzing, analysis }: AnalysisDisplayProps) => {
  const { toast } = useToast();

  const copyAnalysis = () => {
    if (analysis) {
      navigator.clipboard.writeText(analysis);
      toast({
        title: "Copied to clipboard",
        description: "Analysis has been copied to your clipboard.",
      });
    }
  };

  const downloadAnalysis = () => {
    if (analysis) {
      const blob = new Blob([analysis], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'security-analysis.md';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      toast({
        title: "Download started",
        description: "Analysis has been downloaded as a Markdown file.",
      });
    }
  };

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-5 w-5 text-primary" />
          <h2 className="text-xl font-semibold text-neon">Security Analysis</h2>
        </div>
        
        {analysis && (
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={copyAnalysis}
              className="glass border-primary/30"
            >
              <Copy className="h-4 w-4 mr-2" />
              Copy
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={downloadAnalysis}
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
      {!isAnalyzing && !analysis && (
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

      {/* Analysis Results */}
      {analysis && !isAnalyzing && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex-1 overflow-auto"
        >
          <Card className="glass-card h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-success" />
                Analysis Complete
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="prose prose-sm max-w-none text-foreground">
                <pre className="whitespace-pre-wrap text-sm leading-relaxed">
                  {analysis}
                </pre>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}
    </div>
  );
};