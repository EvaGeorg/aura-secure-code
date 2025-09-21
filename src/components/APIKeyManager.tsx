import { useState } from 'react';
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Globe, Key, Zap, Eye, EyeOff, CheckCircle, AlertCircle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

export type APIMode = 'free' | 'user' | 'offline';

interface APIKeyManagerProps {
  mode: APIMode;
  setMode: (mode: APIMode) => void;
  apiKey: string;
  setApiKey: (key: string) => void;
}

export const APIKeyManager = ({ mode, setMode, apiKey, setApiKey }: APIKeyManagerProps) => {
  const [showKey, setShowKey] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [isValid, setIsValid] = useState<boolean | null>(null);
  const { toast } = useToast();

  const validateApiKey = async (key: string) => {
    if (!key.trim()) return;
    
    setIsValidating(true);
    // Simulate API validation
    setTimeout(() => {
      const valid = key.startsWith('AIza') || key.length > 20; // Simple validation
      setIsValid(valid);
      setIsValidating(false);
      
      toast({
        title: valid ? "API Key Valid" : "Invalid API Key",
        description: valid ? "Your API key has been validated successfully." : "Please check your API key and try again.",
        variant: valid ? "default" : "destructive",
      });
    }, 1500);
  };

  const modes = [
    {
      id: 'free' as APIMode,
      icon: Globe,
      title: 'Free Tier',
      description: 'Use our server API key with rate limits',
      badge: 'Rate Limited',
      badgeVariant: 'secondary' as const,
      features: ['5 analyses per hour', 'Basic security scanning', 'No API key required']
    },
    {
      id: 'user' as APIMode,
      icon: Key,
      title: 'Your API Key',
      description: 'Use your own Gemini API key for unlimited access',
      badge: 'Unlimited',
      badgeVariant: 'default' as const,
      features: ['Unlimited analyses', 'Full feature access', 'Faster processing']
    },
    {
      id: 'offline' as APIMode,
      icon: Zap,
      title: 'Offline Mode',
      description: 'Basic static analysis without AI',
      badge: 'No Internet',
      badgeVariant: 'outline' as const,
      features: ['Basic pattern detection', 'Offline processing', 'No API required']
    }
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Key className="h-5 w-5 text-primary" />
        <h2 className="text-xl font-semibold text-neon">API Configuration</h2>
      </div>

      {/* Mode Selection */}
      <div className="grid md:grid-cols-3 gap-4">
        {modes.map((modeOption) => {
          const Icon = modeOption.icon;
          const isSelected = mode === modeOption.id;
          
          return (
            <motion.div
              key={modeOption.id}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <Card 
                className={`cursor-pointer transition-all duration-300 ${
                  isSelected 
                    ? 'glass-card ring-2 ring-primary glow' 
                    : 'glass-card hover:ring-1 hover:ring-primary/50'
                }`}
                onClick={() => setMode(modeOption.id)}
              >
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <Icon className={`h-6 w-6 ${isSelected ? 'text-primary' : 'text-muted-foreground'}`} />
                    <Badge variant={modeOption.badgeVariant} className="text-xs">
                      {modeOption.badge}
                    </Badge>
                  </div>
                  <CardTitle className="text-lg">{modeOption.title}</CardTitle>
                  <CardDescription>{modeOption.description}</CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-1">
                    {modeOption.features.map((feature, idx) => (
                      <li key={idx} className="text-sm text-muted-foreground flex items-center gap-2">
                        <div className="h-1 w-1 rounded-full bg-primary" />
                        {feature}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </motion.div>
          );
        })}
      </div>

      {/* API Key Input */}
      {mode === 'user' && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          exit={{ opacity: 0, height: 0 }}
          className="space-y-4"
        >
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Key className="h-5 w-5" />
                Gemini API Key
              </CardTitle>
              <CardDescription>
                Enter your Google Gemini API key to enable unlimited analysis.{' '}
                <a 
                  href="https://makersuite.google.com/app/apikey" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:underline"
                >
                  Get your API key here
                </a>
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="relative">
                <Input
                  type={showKey ? 'text' : 'password'}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="AIza..."
                  className="glass pr-20"
                />
                <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-2">
                  {isValid !== null && (
                    isValid ? (
                      <CheckCircle className="h-4 w-4 text-success" />
                    ) : (
                      <AlertCircle className="h-4 w-4 text-destructive" />
                    )
                  )}
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowKey(!showKey)}
                    className="h-8 w-8 p-0"
                  >
                    {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>

              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => validateApiKey(apiKey)}
                  disabled={!apiKey.trim() || isValidating}
                  className="glass border-primary/30"
                >
                  {isValidating ? (
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                      className="h-4 w-4"
                    >
                      <Zap className="h-4 w-4" />
                    </motion.div>
                  ) : (
                    'Validate Key'
                  )}
                </Button>

                {apiKey.trim() && (
                  <Button
                    variant="ghost"
                    onClick={() => {
                      setApiKey('');
                      setIsValid(null);
                    }}
                    className="text-muted-foreground"
                  >
                    Clear
                  </Button>
                )}
              </div>

              {/* Usage Stats (Mock) */}
              {isValid && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="p-4 glass rounded-lg"
                >
                  <h4 className="font-medium mb-2">Usage Statistics</h4>
                  <div className="grid grid-cols-3 gap-4 text-sm">
                    <div>
                      <p className="text-muted-foreground">Today</p>
                      <p className="font-medium">12 requests</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">This Month</p>
                      <p className="font-medium">347 requests</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Remaining</p>
                      <p className="font-medium text-success">Unlimited</p>
                    </div>
                  </div>
                </motion.div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Rate Limit Info for Free Tier */}
      {mode === 'free' && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="glass p-4 rounded-lg"
        >
          <div className="flex items-center gap-3 mb-2">
            <Globe className="h-5 w-5 text-primary" />
            <h4 className="font-medium">Free Tier Usage</h4>
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-muted-foreground">Requests Used</p>
              <p className="font-medium">3 / 5 this hour</p>
            </div>
            <div>
              <p className="text-muted-foreground">Next Reset</p>
              <p className="font-medium">42 minutes</p>
            </div>
          </div>
          <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
            <div className="h-full w-3/5 bg-primary rounded-full" />
          </div>
        </motion.div>
      )}
    </div>
  );
};