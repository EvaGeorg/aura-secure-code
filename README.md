# aura-secure-code
AI-Powered Security Vulnerability Scanner - SecureCode AI is a specialized security vulnerability scanner that uses Google's Gemini AI to perform comprehensive security analysis on your code. Built for developers who prioritize security, this tool identifies critical vulnerabilities and provides actionable fix recommendations.

🛡️ SecureCode AI - AI-Powered Security Vulnerability Scanner


Find critical security vulnerabilities in your code in seconds using Google Gemini AI

## 🎯 What It Does
SecureCode AI does one thing exceptionally well: security vulnerability detection. It analyzes your code and provides:

<img width="1562" height="899" alt="image" src="https://github.com/user-attachments/assets/75403ffc-e5cc-48cc-a341-10ffcd8b3f96" />


<br>🚨 Critical Vulnerabilities - Immediate security threats (SQL injection, XSS, etc.)
<br>⚠️ High Risk Issues - Serious security concerns requiring attention
<br>💡 Medium Risk Items - Security improvements worth implementing
<br>📝 Low Risk Notes - Minor security enhancements

## 🔍 Security Analysis Focus
This tool specifically scans for:
🛡️ OWASP Top 10 Vulnerabilities

- SQL Injection
- Cross-Site Scripting (XSS)
- Authentication Bypass
- Insecure Direct Object References
- Security Misconfiguration
- Sensitive Data Exposure
- Missing Access Controls
- Cross-Site Request Forgery (CSRF)
- Insecure Deserialization
- Known Vulnerable Components

## 🔐 Additional Security Issues

- Hardcoded secrets and API keys
- Weak cryptographic practices
- Buffer overflow vulnerabilities
- Path traversal attacks
- Input validation flaws
- Insecure file operations
- Race condition vulnerabilities


## 💻 Supported Languages
20+ Programming Languages:
JavaScript    TypeScript    Python       Java         PHP
C#           C++           Go           Rust         Ruby
Swift        Kotlin        SQL          HTML         CSS  
Shell/Bash   YAML          JSON         Dockerfile   XML

## 🚀 How to Use
1️⃣ Direct Code Analysis

Paste your code into the editor
Select programming language (auto-detected)
Click "Analyze Security"
Get detailed vulnerability report

2️⃣ File Upload Analysis

Drag & drop files or click to upload
Supports multiple files simultaneously
Each file analyzed separately
Download comprehensive reports

3️⃣ API Key Options

🌐 Free Tier: Use our server (20 analyses/hour)
🔑 Your API Key: Unlimited with your Gemini API key
📱 Demo Mode: View sample results without API calls


## 🏗️ Architecture
### Frontend (Lovable)

Modern React-based UI
Syntax highlighting with Monaco Editor
Real-time analysis with debouncing
Responsive design with dark cybersecurity theme

### Backend (Cloudflare Worker)

Secure API proxy for Gemini AI
Rate limiting and abuse protection
Input validation and sanitization
No code storage - analyze and discard

### AI Engine (Google Gemini)

Advanced code understanding
Context-aware vulnerability detection
OWASP-compliant security recommendations
Structured analysis reports

[User] → [Lovable Frontend] → [Cloudflare Worker] → [Google Gemini AI]
         ↳ Code Input         ↳ Secure Proxy      ↳ Security Analysis

## 📋 Analysis Output Format
SecureCode AI provides structured, actionable reports.


## 🛠️ Setup & Deployment

### **Prerequisites**
- Google Gemini API key ([Get one here](https://ai.google.dev))
- Cloudflare account (free tier works)

### **Deploy the Backend**
```bash
1. Create Cloudflare Worker
npm create cloudflare@latest securecode-worker
cd securecode-worker

2. Add the worker code from this repository
3. Set your Gemini API key
npx wrangler secret put GEMINI_API_KEY

4. Deploy
npx wrangler deploy
Deploy the Frontend

Import this repository to Lovable
Update the API endpoint in the code
Deploy to Vercel/Netlify via Lovable's export feature

Environment Variables
envGEMINI_API_KEY=your_gemini_api_key_here
ALLOWED_ORIGIN=https://your-frontend-domain.com  # Optional
```

##🔒 Security & Privacy

No Code Storage: Code is analyzed in real-time and immediately discarded
API Key Security: Your Gemini API key is stored securely in Cloudflare Workers
No Logging: Code content is never logged or stored
