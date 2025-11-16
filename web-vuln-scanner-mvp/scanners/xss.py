# scanners/xss.py
import requests
from payloads import XSS_PAYLOADS
import config as cfg

def scan_xss(url, params=None):
    findings = []
    params = params or {}
    for param in list(params.keys()):
        original = params[param]
        for payload in XSS_PAYLOADS:
            test = params.copy()
            test[param] = original + payload
            try:
                r = requests.get(url, params=test, headers=cfg.HEADERS, timeout=cfg.TIMEOUT)
            except Exception:
                continue
            if payload in r.text:
                findings.append({
                    'type': 'Reflected XSS',
                    'param': param,
                    'payload': payload,
                    'evidence': 'Payload appears verbatim in response',
                    'status_code': r.status_code,
                    'url': r.url
                })
    return findings
