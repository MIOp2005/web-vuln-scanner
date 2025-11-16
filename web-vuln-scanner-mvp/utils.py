import time, json, html
from datetime import datetime

def now_ts():
    return datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

def make_report_filename(prefix='report'):
    return f"{prefix}_{now_ts()}"

def save_json_report(data, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def save_html_report(data, path):
    parts = []
    parts.append('<html><head><meta charset="utf-8"><title>Scan Report</title></head><body>')
    parts.append(f"<h1>Scan Report - {html.escape(data.get('target',''))}</h1>")
    parts.append(f"<p>Generated: {data.get('generated_at')}</p>")
    parts.append('<h2>Findings</h2>')
    for f in data.get('findings', []):
        parts.append('<div style="border:1px solid #ddd;padding:8px;margin:8px;">')
        parts.append(f"<h3>{html.escape(f.get('type',''))} - {html.escape(f.get('param',''))}</h3>")
        parts.append(f"<p><strong>payload:</strong> {html.escape(f.get('payload',''))}</p>")
        parts.append(f"<p><strong>evidence:</strong> {html.escape(f.get('evidence',''))}</p>")
        parts.append('</div>')
    parts.append('</body></html>')
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(parts))
