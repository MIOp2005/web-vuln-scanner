import argparse
from urllib.parse import urlparse, parse_qs
from scanners.sqli import scan_sqli
from scanners.xss import scan_xss
from scanners.traversal import scan_traversal
from scanners.headers import scan_headers
import utils, os

def parse_params(url):
    p = urlparse(url)
    return {k: v[0] for k,v in parse_qs(p.query).items()}

def run(url):
    params = parse_params(url)
    all_findings = []
    all_findings += scan_headers(url)
    if params:
        all_findings += scan_sqli(url, params=params)
        all_findings += scan_xss(url, params=params)
        all_findings += scan_traversal(url, params=params)
    else:
        print('No query params found; header scan done. Provide ?param=val to test parameter-based checks.')

    report = {
        'target': url,
        'generated_at': utils.now_ts(),
        'summary': {'total_findings': len(all_findings)},
        'findings': all_findings
    }
    os.makedirs('reports', exist_ok=True)
    base = utils.make_report_filename('report')
    json_path = os.path.join('reports', base+'.json')
    html_path = os.path.join('reports', base+'.html')
    utils.save_json_report(report, json_path)
    utils.save_html_report(report, html_path)
    print('Scan complete. Reports:')
    print(json_path)
    print(html_path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True, help='Target URL with query params (e.g. http://localhost/vuln.php?id=1)')
    args = parser.parse_args()
    run(args.url)
