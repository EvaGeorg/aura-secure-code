import { useState, useCallback, useRef } from 'react';
import { motion } from 'framer-motion';
import { useDropzone } from 'react-dropzone';
import Monaco from '@monaco-editor/react';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card } from '@/components/ui/card';
import { Upload, FileCode, Zap, FolderOpen } from 'lucide-react';

const SUPPORTED_LANGUAGES = [
  { value: 'javascript', label: 'JavaScript', ext: ['.js', '.mjs'] },
  { value: 'typescript', label: 'TypeScript', ext: ['.ts', '.tsx'] },
  { value: 'python', label: 'Python', ext: ['.py'] },
  { value: 'java', label: 'Java', ext: ['.java'] },
  { value: 'php', label: 'PHP', ext: ['.php'] },
  { value: 'csharp', label: 'C#', ext: ['.cs'] },
  { value: 'cpp', label: 'C++', ext: ['.cpp', '.cc'] },
  { value: 'go', label: 'Go', ext: ['.go'] },
  { value: 'rust', label: 'Rust', ext: ['.rs'] },
  { value: 'ruby', label: 'Ruby', ext: ['.rb'] },
  { value: 'swift', label: 'Swift', ext: ['.swift'] },
  { value: 'kotlin', label: 'Kotlin', ext: ['.kt'] },
  { value: 'sql', label: 'SQL', ext: ['.sql'] },
  { value: 'html', label: 'HTML', ext: ['.html'] },
  { value: 'css', label: 'CSS', ext: ['.css'] },
];

const EXAMPLE_CODE = {
  javascript: `// Example: Potential XSS vulnerability
function displayUserInput(userInput) {
  document.getElementById('content').innerHTML = userInput;
}

// Example: SQL injection risk
function getUserData(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return database.query(query);
}

// Example: Insecure authentication
function authenticate(password) {
  if (password === "admin123") {
    return true;
  }
  return false;
}`,
  python: `# Example: Command injection vulnerability
import os

def execute_user_command(user_input):
    os.system("echo " + user_input)

# Example: Hardcoded credentials
def connect_to_database():
    password = "secretpass123"
    return connect("admin", password)

# Example: Path traversal
def read_file(filename):
    with open("/uploads/" + filename) as f:
        return f.read()`,
};

interface CodeEditorProps {
  code: string;
  setCode: (code: string) => void;
  language: string;
  setLanguage: (language: string) => void;
  onAnalyze: () => void;
  isAnalyzing: boolean;
}

export const CodeEditor = ({ 
  code, 
  setCode, 
  language, 
  setLanguage, 
  onAnalyze, 
  isAnalyzing 
}: CodeEditorProps) => {
  const [charCount, setCharCount] = useState(0);
  const maxChars = 50000;
  const fileInputRef = useRef<HTMLInputElement>(null);

  const detectLanguage = (filename: string) => {
    const extension = filename.substring(filename.lastIndexOf('.'));
    const detected = SUPPORTED_LANGUAGES.find(lang => 
      lang.ext.includes(extension)
    );
    return detected?.value || 'javascript';
  };

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setCode(content);
        setCharCount(content.length);
        
        // Auto-detect language
        const detectedLang = detectLanguage(file.name);
        setLanguage(detectedLang);
      };
      reader.readAsText(file);
    }
  }, [setCode, setLanguage]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/*': ['.js', '.ts', '.py', '.java', '.php', '.cs', '.cpp', '.go', '.rs', '.rb', '.swift', '.kt', '.sql', '.html', '.css']
    },
    maxSize: 50 * 1024 * 1024, // 50MB
    multiple: false
  });

  const handleCodeChange = (value: string | undefined) => {
    const newCode = value || '';
    setCode(newCode);
    setCharCount(newCode.length);
  };

  const loadExample = (lang: string) => {
    const exampleCode = EXAMPLE_CODE[lang as keyof typeof EXAMPLE_CODE] || EXAMPLE_CODE.javascript;
    setCode(exampleCode);
    setCharCount(exampleCode.length);
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setCode(content);
        setCharCount(content.length);
        
        // Auto-detect language
        const detectedLang = detectLanguage(file.name);
        setLanguage(detectedLang);
      };
      reader.readAsText(file);
    }
    // Reset the input so the same file can be selected again
    event.target.value = '';
  };

  const openFileDialog = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Header Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <FileCode className="h-5 w-5 text-primary" />
          <h2 className="text-xl font-semibold text-neon">Code Input</h2>
        </div>
        
        <div className="flex items-center gap-3">
          <Select value={language} onValueChange={setLanguage}>
            <SelectTrigger className="w-40 glass">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="glass">
              {SUPPORTED_LANGUAGES.map(lang => (
                <SelectItem key={lang.value} value={lang.value}>
                  {lang.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Button
            variant="outline" 
            size="sm"
            onClick={() => loadExample(language)}
            className="glass border-primary/30 hover:border-primary/60"
          >
            Load Example
          </Button>

          <Button
            variant="outline" 
            size="sm"
            onClick={openFileDialog}
            className="glass border-primary/30 hover:border-primary/60"
          >
            <FolderOpen className="h-4 w-4 mr-2" />
            Load File
          </Button>

          <Button
            onClick={onAnalyze}
            disabled={!code.trim() || isAnalyzing}
            className="bg-primary hover:bg-primary/90 text-primary-foreground glow"
          >
            {isAnalyzing ? (
              <>
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                >
                  <Zap className="h-4 w-4 mr-2" />
                </motion.div>
                Analyzing...
              </>
            ) : (
              <>
                <Zap className="h-4 w-4 mr-2" />
                Analyze Code
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Code Editor */}
      <Card className="flex-1 glass-card overflow-hidden">
        {!code.trim() && (
          <div 
            {...getRootProps()} 
            className={`
              h-full flex flex-col items-center justify-center text-center p-8 cursor-pointer
              border-2 border-dashed transition-all duration-300
              ${isDragActive 
                ? 'border-primary bg-primary/10' 
                : 'border-border hover:border-primary/50'
              }
            `}
          >
            <input {...getInputProps()} />
            <Upload className={`h-12 w-12 mb-4 ${isDragActive ? 'text-primary' : 'text-muted-foreground'}`} />
            <h3 className="text-lg font-medium mb-2">
              {isDragActive ? 'Drop your code file here' : 'Drag & drop a code file'}
            </h3>
            <p className="text-sm text-muted-foreground mb-4">
              Or paste your code below to get started
            </p>
            <Button 
              variant="outline" 
              className="glass border-primary/30"
              onClick={openFileDialog}
            >
              Browse Files
            </Button>
          </div>
        )}

        {code.trim() && (
          <Monaco
            height="100%"
            language={language}
            value={code}
            onChange={handleCodeChange}
            theme="vs-dark"
            options={{
              minimap: { enabled: false },
              fontSize: 14,
              fontFamily: 'JetBrains Mono',
              lineNumbers: 'on',
              roundedSelection: false,
              scrollBeyondLastLine: false,
              automaticLayout: true,
              tabSize: 2,
            }}
          />
        )}
      </Card>

      {/* Hidden File Input */}
      <input
        ref={fileInputRef}
        type="file"
        onChange={handleFileSelect}
        accept=".js,.ts,.tsx,.py,.java,.php,.cs,.cpp,.cc,.go,.rs,.rb,.swift,.kt,.sql,.html,.css,.txt,.md"
        style={{ display: 'none' }}
      />

      {/* Character Count */}
      <div className="flex justify-between items-center text-sm">
        <span className="text-muted-foreground">
          Supported: JavaScript, Python, Java, PHP, C#, C++, Go, Rust, Ruby, Swift, Kotlin, SQL, HTML, CSS
        </span>
        <span className={`${charCount > maxChars * 0.9 ? 'text-warning' : 'text-muted-foreground'}`}>
          {charCount.toLocaleString()} / {maxChars.toLocaleString()} characters
        </span>
      </div>
    </div>
  );
};