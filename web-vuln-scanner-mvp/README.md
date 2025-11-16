# Web Vuln Scanner — MVP

Minimal Viable Product (MVP) of a Web Application Vulnerability Scanner.
**For authorised testbeds only** (DVWA, bWAPP, WebGoat, etc.).

## Features (MVP)
- Scans GET query parameters for:
  - SQL Injection (error + reflection)
  - Reflected XSS (simple reflection)
  - Directory Traversal (indicator-based)
- Basic security headers check (CSP, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security)
- Generates JSON and simple HTML reports in `reports/`

## Quick start
1. Create virtualenv: `python -m venv venv && source venv/bin/activate` (Linux/macOS) or `venv\Scripts\activate` (Windows)
2. Install: `pip install -r requirements.txt`
3. Run: `python main.py --url 'http://localhost/vuln.php?id=1' --timeout 8`
