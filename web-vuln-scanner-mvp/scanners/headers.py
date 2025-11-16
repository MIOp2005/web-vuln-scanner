# scanners/headers.py
import requests
import config as cfg

CHECKS = {
    'Strict-Transport-Security': 'Missing or weak HSTS',
    'X-Frame-Options': 'Missing X-Frame-Options',
    'X-Content-Type-Options': 'Missing X-Content-Type-Options',
    'Content-Security-Policy': 'Missing Content-Security-Policy (CSP)'
}

def scan_headers(url):
    try:
        r = requests.get(url, headers=cfg.HEADERS, timeout=cfg.TIMEOUT)
    except Exception as e:
        return [{'type':'headers','param':'N/A','payload':'N/A','evidence':f'Error fetching headers: {e}','status_code':None,'url':url}]
    findings = []
    for h, msg in CHECKS.items():
        if h not in r.headers:
            findings.append({'type':'Security Header Missing','param':h,'payload':'N/A','evidence':msg,'status_code':r.status_code,'url':url})
    return findings
