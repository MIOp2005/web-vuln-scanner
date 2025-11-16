# scanners/sqli.py
import requests
from payloads import SQLI_PAYLOADS
import config as cfg

SQL_ERRORS = [
    'you have an error in your sql syntax',
    'warning: mysql',
    'unclosed quotation mark',
    'quoted string not properly terminated',
    'pg_query()'
]

def scan_sqli(url, params=None):
    findings = []
    params = params or {}
    for param in list(params.keys()):
        original = params[param]
        for payload in SQLI_PAYLOADS:
            test = params.copy()
            test[param] = original + payload
            try:
                r = requests.get(url, params=test, headers=cfg.HEADERS, timeout=cfg.TIMEOUT)
            except Exception:
                continue
            body = r.text.lower()
            for err in SQL_ERRORS:
                if err in body:
                    findings.append({
                        'type': 'SQL Injection (error)',
                        'param': param,
                        'payload': payload,
                        'evidence': f'Matched DB error: {err}',
                        'status_code': r.status_code,
                        'url': r.url
                    })
            if payload.lower().strip("'\" ") in body:
                findings.append({
                    'type': 'SQL Injection (reflection)',
                    'param': param,
                    'payload': payload,
                    'evidence': 'Payload reflected in response',
                    'status_code': r.status_code,
                    'url': r.url
                })
    return findings
