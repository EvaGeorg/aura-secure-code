import { useState } from 'react';
import { motion } from 'framer-motion';
import { CodeEditor } from '@/components/CodeEditor';
import { ResultsPanel, SecurityFinding } from '@/components/ResultsPanel';
import { APIKeyManager, APIMode } from '@/components/APIKeyManager';
import { Card } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Shield, Zap, Code, Settings } from 'lucide-react';

const Index = () => {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('javascript');
  const [apiMode, setApiMode] = useState<APIMode>('free');
  const [apiKey, setApiKey] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState<{
    score: number;
    findings: SecurityFinding[];
    summary: string;
  } | null>(null);

  const API_URL = 'https://secure-code-analyzer.your-username.workers.dev';

  // API function to analyze code
  const analyzeCode = async () => {
    if (!code.trim()) {
      return;
    }

    setIsAnalyzing(true);
    setResults(null);

    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code: code,
          language: language,
          analysisType: 'security',
          userApiKey: apiMode === 'user' ? apiKey : null
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      setResults(result);
    } catch (error) {
      console.error('API Error:', error);
      // You could add toast notification here for error handling
      setResults({
        score: 0,
        findings: [],
        summary: `Analysis failed: ${error.message}`
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background-secondary to-background">
      {/* Header */}
      <header className="border-b border-border/50 bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <motion.div 
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-center gap-3"
            >
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary to-primary-glow flex items-center justify-center glow">
                <Shield className="h-6 w-6 text-primary-foreground" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-neon">SecureCode AI</h1>
                <p className="text-sm text-muted-foreground">Find vulnerabilities in seconds</p>
              </div>
            </motion.div>

            <div className="flex items-center gap-3">
              <Badge variant="outline" className="glass">
                <Zap className="h-3 w-3 mr-1" />
                AI-Powered
              </Badge>
              <Badge variant="outline" className="glass">
                <Code className="h-3 w-3 mr-1" />
                15+ Languages
              </Badge>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Tabs defaultValue="analyze" className="space-y-6">
            <TabsList className="glass">
              <TabsTrigger value="analyze" className="flex items-center gap-2">
                <Code className="h-4 w-4" />
                Analyze Code
              </TabsTrigger>
              <TabsTrigger value="settings" className="flex items-center gap-2">
                <Settings className="h-4 w-4" />
                API Settings
              </TabsTrigger>
            </TabsList>

            <TabsContent value="analyze" className="space-y-6">
              {/* Hero Section */}
              <motion.div 
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.2 }}
                className="text-center space-y-4 mb-8"
              >
                <h2 className="text-3xl font-bold text-neon">
                  AI-powered security analysis for developers who care about security
                </h2>
                <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
                  Analyze your code in seconds. Find vulnerabilities, performance issues, and best practices violations with our advanced AI scanner.
                </p>
              </motion.div>

              {/* Main Analysis Interface */}
              <div className="grid lg:grid-cols-[1fr,400px] gap-6 min-h-[600px]">
                {/* Code Editor */}
                <motion.div
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.3 }}
                >
                  <Card className="glass-card h-full">
                    <div className="p-6 h-full">
                      <CodeEditor
                        code={code}
                        setCode={setCode}
                        language={language}
                        setLanguage={setLanguage}
                        onAnalyze={analyzeCode}
                        isAnalyzing={isAnalyzing}
                      />
                    </div>
                  </Card>
                </motion.div>

                {/* Results Panel */}
                <motion.div
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.4 }}
                >
                  <Card className="glass-card h-full">
                    <div className="p-6 h-full">
                      <ResultsPanel 
                        isAnalyzing={isAnalyzing}
                        results={results}
                      />
                    </div>
                  </Card>
                </motion.div>
              </div>
            </TabsContent>

            <TabsContent value="settings">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="max-w-4xl mx-auto"
              >
                <Card className="glass-card">
                  <div className="p-6">
                    <APIKeyManager
                      mode={apiMode}
                      setMode={setApiMode}
                      apiKey={apiKey}
                      setApiKey={setApiKey}
                    />
                  </div>
                </Card>
              </motion.div>
            </TabsContent>
          </Tabs>
        </motion.div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border/50 bg-card/30 backdrop-blur-sm mt-16">
        <div className="container mx-auto px-6 py-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-4 text-sm text-muted-foreground">
              <span>© 2024 SecureCode AI</span>
              <span>•</span>
              <a href="#" className="hover:text-primary transition-colors">Privacy Policy</a>
              <span>•</span>
              <a href="#" className="hover:text-primary transition-colors">Terms of Service</a>
            </div>
            <div className="flex items-center gap-4 text-sm text-muted-foreground">
              <span>Powered by AI</span>
              <div className="h-2 w-2 rounded-full bg-success animate-pulse" />
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;