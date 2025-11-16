# scanners/traversal.py
import requests
from payloads import TRAVERSAL_PAYLOADS
import config as cfg

INDICATORS = ['root:x', 'bin/bash']

def scan_traversal(url, params=None):
    findings = []
    params = params or {}
    for param in list(params.keys()):
        original = params[param]
        for payload in TRAVERSAL_PAYLOADS:
            test = params.copy()
            test[param] = original + payload
            try:
                r = requests.get(url, params=test, headers=cfg.HEADERS, timeout=cfg.TIMEOUT)
            except Exception:
                continue
            body = r.text.lower()
            for ind in INDICATORS:
                if ind in body:
                    findings.append({
                        'type': 'Directory Traversal',
                        'param': param,
                        'payload': payload,
                        'evidence': f'Found indicator: {ind}',
                        'status_code': r.status_code,
                        'url': r.url
                    })
    return findings
