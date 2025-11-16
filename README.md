# 🛡️ Web Application Vulnerability Scanner — MVP

A lightweight, beginner-friendly vulnerability scanner for educational and authorized security testing.

## 🚀 Features
- Security header analysis (CSP, HSTS, XFO, XCTO)
- SQL Injection (error/reflection-based)
- Reflected XSS detection
- Directory Traversal testing
- HTML + JSON reporting system

## 📦 Installation
```bash
pip install -r requirements.txt
```

## ▶️ Usage
```bash
python main.py --url "http://example.com/?search=test"
```

## 📁 Project Structure
```
web-vuln-scanner-mvp/
│ main.py
│ config.py
│ payloads.py
│ requirements.txt
│
└── scanners/
       sqli.py
       xss.py
       traversal.py
       headers.py
```

## ⚠️ Legal Disclaimer
Use this tool **only** on websites you own or have **explicit written permission** to test.
Unauthorized scanning is illegal.
