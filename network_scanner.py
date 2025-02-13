import time
import socket
import requests
from scapy.layers.inet import IP, TCP, ICMP, UDP, sr, sr1, RandShort
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import send
from scapy.volatile import RandIP
from colorama import init, Fore, Back, Style
import json
import csv
import whois
import ssl
import geoip2.database
import os
import sys
from jinja2 import Environment, FileSystemLoader
import random

# Initialize colorama
init(autoreset=True)

# Constants
TOP_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "Remote Desktop",
    445: "Microsoft-DS (SMB)",
    587: "Submission (SMTP over TLS)",
    993: "IMAP over SSL/TLS",
    995: "POP3 over SSL/TLS",
    1723: "PPTP",
    1900: "SSDP (UPnP)",
    2049: "NFS",
    2222: "Alternative SSH (common for custom setups)",
    3128: "Squid Proxy",
    3306: "MySQL",
    5060: "SIP (Session Initiation Protocol)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate (common for web servers)",
    8443: "HTTPS Alternate (common for web servers)",
    9090: "Web Administration (alternate HTTP)",
    9100: "Direct IP Printing",
    10000: "Webmin",
    27017: "MongoDB",
    50000: "IBM DB2",
}

# Load GeoIP database
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH) if os.path.exists(GEOIP_DB_PATH) else None

# Shodan API Key
SHODAN_API_KEY = ""

# Banner
def display_banner():
    print(Fore.CYAN + r"""
  ____   ____    _    _   _ _   _ _____ ____  
 / ___| / ___|  / \  | \ | | \ | | ____|  _ \ 
 \___ \| |     / _ \ |  \| |  \| |  _| | |_) |
  ___) | |___ / ___ \| |\  | |\  | |___|  _ < 
 |____/ \____/_/   \_\_| \_|_| \_|_____|_| \_\
                                              
""")
    print(Fore.YELLOW + "Made by: Diogo Lages")
    print(Fore.GREEN + "=" * 60)
    print(Fore.MAGENTA + "Welcome to my Network Scanner")
    print(Fore.GREEN + "=" * 60)





def scan_tcp_port(ip, port, service):
    try:
        tcp_packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(tcp_packet, timeout=1, verbose=False)

        if response and response.haslayer(TCP):
            tcp_layer = response[TCP]
            if tcp_layer.flags == "SA":
                print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] TCP Port {port} ({service}) is open.")
                return "open"
            elif tcp_layer.flags == "RA":
                print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] TCP Port {port} ({service}) is closed.")
                return "closed"
        else:
            print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] TCP Port {port} ({service}) is filtered (no response).")
            return "filtered"
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error scanning port {port}: {e}")
        return "error"






def scan_udp_port(ip, port, service):
    try:
        udp_packet = IP(dst=ip) / UDP(dport=port)
        response = sr1(udp_packet, timeout=1, verbose=False)

        if response and response.haslayer(UDP):
            print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] UDP Port {port} ({service}) is open.")
            return "open"
        elif response and response.haslayer(ICMP):
            icmp_type = response[ICMP].type
            if icmp_type == 3 and response[ICMP].code == 3:
                print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] UDP Port {port} ({service}) is closed.")
                return "closed"
        else:
            print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] UDP Port {port} ({service}) is filtered (no response).")
            return "filtered"
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error scanning UDP port {port}: {e}")
        return "error"


def is_ip_address(address):
    try:
        # Check if the address is a valid IPv4 or IPv6 address
        socket.inet_pton(socket.AF_INET, address)  # Validate IPv4
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, address)  # Validate IPv6
            return True
        except socket.error:
            return False



def nslookup(ip_or_domain):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Performing NSLookup for {ip_or_domain}...")
        if is_ip_address(ip_or_domain):  # Check if input is an IP address
            try:
                domain = socket.gethostbyaddr(ip_or_domain)[0]
                print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] NSLookup result: {domain}")
                return domain
            except Exception as e:
                print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error resolving IP to domain: {e}")
                return "No domain found"
        else:  # Input is a domain name
            try:
                ip = socket.gethostbyname(ip_or_domain)
                print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] NSLookup result: {ip}")
                return ip
            except Exception as e:
                print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error resolving domain to IP: {e}")
                return "No IP found"
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error during NSLookup: {e}")
        return "Error during NSLookup"







def query_website_vulnerabilities(domain):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Querying website vulnerabilities for {domain}...")
        cve_details_url = f"https://www.cvedetails.com/domain/{domain}/"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(cve_details_url, headers=headers, timeout=5)

        if response.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            vulnerabilities = []

            # Extract CVEs from the page
            for row in soup.select("table.listtable tr")[1:6]:  # Show top 5 vulnerabilities
                cols = row.find_all('td')
                if len(cols) >= 3:
                    cve_id = cols[0].text.strip()
                    summary = cols[2].text.strip()
                    vulnerabilities.append((cve_id, summary))

            if vulnerabilities:
                print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] Known vulnerabilities for {domain}:")
                for cve_id, summary in vulnerabilities:
                    print(Fore.CYAN + f"- {cve_id} - {summary}")
                return vulnerabilities
            else:
                print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] No known vulnerabilities found for {domain}.")
                return []
        else:
            print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] CVE Details returned status code {response.status_code}.")
            return []
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error querying website vulnerabilities: {e}")
        return []










def generate_html_report(ip, open_ports, os_guess, vulnerabilities, traceroute_results, geo_data, whois_data, ssl_info, nslookup_result, website_vulnerabilities):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Generating HTML report for {ip}...")
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('report_template.html')

        # Prepare data for the report
        report_data = {
            "ip": ip,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "open_ports": [(port, TOP_PORTS.get(port, "Unknown"), banner) for port, banner in open_ports.items()],
            "os_guess": os_guess,
            "vulnerabilities": vulnerabilities,
            "traceroute_results": traceroute_results,
            "geo_data": geo_data,
            "whois_data": whois_data,
            "ssl_info": ssl_info,
            "nslookup_result": nslookup_result,  # Add NSLookup result
            "website_vulnerabilities": website_vulnerabilities  # Add website vulnerabilities
        }

        # Render the template with the data
        html_report = template.render(report_data)

        # Save the report to a file
        report_filename = f"{ip}_scan_report.html"
        with open(report_filename, "w") as file:
            file.write(html_report)

        print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] HTML report generated: {report_filename}")
        return report_filename
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error generating HTML report: {e}")


def detect_service_version(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = ""

        # Define custom requests based on common services
        if port == 80 or port == 443:  # HTTP/HTTPS
            sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip.encode())
        elif port == 21:  # FTP
            sock.sendall(b"USER anonymous\r\n")
        elif port == 22:  # SSH
            sock.sendall(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8\r\n")
        elif port == 23:  # Telnet
            sock.sendall(b"\r\n")
        elif port == 25:  # SMTP
            sock.sendall(b"EHLO localhost\r\n")
        else:  # Generic banner grab
            sock.sendall(b"WhoAreYou\r\n")

        # Receive response from the service
        try:
            raw_banner = sock.recv(1024)
            # Attempt to decode using UTF-8 with error replacement
            banner = raw_banner.decode('utf-8', errors='replace').strip()
        except Exception as e:
            banner = f" ({e})"

        sock.close()

        # Print the detected service information
        if banner:
            print(Fore.BLUE + f"[{time.strftime('%H:%M:%S')}] Service on port {port}: {banner}")
        else:
            print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] No service banner detected on port {port}.")

        # Suggest exploits for the detected service
        suggest_exploits(banner, port)

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Failed to detect service version on port {port}: {e}")
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Unexpected error detecting service on port {port}: {e}")






def suggest_exploits(service_info, port):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Fetching exploit information for port {port}...")
        vulnerabilities = []

        # Query CIRCL for vulnerabilities
        circl_url = f"https://cve.circl.lu/api/search/{service_info}"
        circl_response = requests.get(circl_url, timeout=5)
        if circl_response.status_code == 200:
            circl_data = circl_response.json()
            if circl_data:
                print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] Potential vulnerabilities for port {port} (CIRCL):")
                for cve in circl_data[:3]:
                    cvss_score = cve.get('cvss', 'N/A')
                    summary = cve.get('summary', 'No summary available')
                    print(Fore.CYAN + f"- {cve['id']} - CVSS: {cvss_score} - {summary}")
                    vulnerabilities.append(("CIRCL", cve['id'], cvss_score, summary))
            else:
                print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] No vulnerabilities found for port {port} (CIRCL).")
        else:
            print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] CIRCL API returned status code {circl_response.status_code}.")

        # Query NVD for vulnerabilities
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service_info}"
        nvd_response = requests.get(nvd_url, timeout=5)
        if nvd_response.status_code == 200:
            nvd_data = nvd_response.json()
            if 'result' in nvd_data and 'CVE_Items' in nvd_data['result']:
                print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] Known vulnerabilities for port {port} (NVD):")
                for item in nvd_data['result']['CVE_Items'][:3]:
                    cve_id = item['cve']['CVE_data_meta']['ID']
                    summary = item['cve']['description']['description_data'][0]['value']
                    cvss_score = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 'N/A')
                    print(Fore.CYAN + f"- {cve_id} - CVSS: {cvss_score} - {summary}")
                    vulnerabilities.append(("NVD", cve_id, cvss_score, summary))
            else:
                print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] No known vulnerabilities found for port {port} (NVD).")
        else:
            print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] NVD API returned status code {nvd_response.status_code}.")

        return vulnerabilities
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Could not fetch exploit information for port {port}: {e}")
        return []






def scan_ports(ip, ports, protocol="tcp"):
    open_ports = []

    for port in ports:
        service = TOP_PORTS.get(port, "Unknown")
        if protocol == "tcp":
            state = scan_tcp_port(ip, port, service)
        elif protocol == "udp":
            state = scan_udp_port(ip, port, service)
        if state == "open":
            detect_service_version(ip, port)
            open_ports.append(port)
        time.sleep(0.1)  # Add a small delay to avoid overwhelming the target

    return open_ports






def os_fingerprinting(ip):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Starting advanced OS fingerprinting on {ip}...")

        # Define multiple probes with different TCP flags and options
        packets = [
            IP(dst=ip, ttl=64) / TCP(sport=12345, dport=80, flags="S", options=[("MSS", 1460)]),  # SYN with MSS
            IP(dst=ip, ttl=128) / TCP(sport=12345, dport=22, flags="S", options=[("MSS", 1460), ("Timestamp", (0, 0))]),  # SYN with Timestamp
            IP(dst=ip, ttl=64) / TCP(sport=12345, dport=80, flags="A"),  # ACK
            IP(dst=ip, ttl=64) / TCP(sport=12345, dport=80, flags="F"),  # FIN
            IP(dst=ip, ttl=64) / TCP(sport=12345, dport=80, flags=""),  # NULL
            IP(dst=ip, ttl=64) / ICMP(type=8, code=0),  # ICMP Echo Request
            IP(dst=ip, ttl=64) / UDP(dport=31337),  # UDP to closed port
        ]

        # Send packets and collect responses
        responses = sr(packets, timeout=2, verbose=False)
        os_guesses = []

        for sent, received in responses[0]:
            if received:
                if received.haslayer(TCP):
                    ttl = received[IP].ttl
                    window_size = received[TCP].window
                    tcp_options = received[TCP].options

                    print(Fore.BLUE + f"[{time.strftime('%H:%M:%S')}] Received TCP response:")
                    print(Fore.BLUE + f"  - TTL: {ttl}")
                    print(Fore.BLUE + f"  - Window Size: {window_size}")
                    print(Fore.BLUE + f"  - TCP Options: {tcp_options}")

                    # Analyze TTL, window size, and TCP options for Windows
                    if ttl == 128:  # Windows typically uses TTL 128
                        if window_size == 65535 and ("MSS", 1460) in tcp_options:
                            os_guesses.append("Windows XP")
                        elif window_size == 8192 and ("MSS", 1460) in tcp_options:
                            os_guesses.append("Windows 7/8")
                        elif window_size == 65535 and "Timestamp" in str(tcp_options):
                            os_guesses.append("Windows 10/11")
                        elif "WScale" in str(tcp_options):
                            os_guesses.append("Modern Windows")
                        elif "SAckOK" in str(tcp_options):
                            os_guesses.append("Windows Server")
                        elif "Timestamp" in str(tcp_options) and window_size == 65535:
                            os_guesses.append("VirtualBox/VMware (Windows)")

                    # Analyze for Linux
                    elif ttl <= 64:  # Linux typically uses TTL 64
                        if window_size == 5840 and ("MSS", 1460) in tcp_options:
                            os_guesses.append("Linux")
                        elif window_size == 5720 and ("MSS", 1460) in tcp_options:
                            os_guesses.append("Linux")
                        elif "Timestamp" in str(tcp_options) and window_size == 5840:
                            os_guesses.append("VirtualBox/VMware (Linux)")

                    # Analyze for FreeBSD
                    elif ttl > 64 and window_size == 5720 and "Timestamp" in str(tcp_options):
                        os_guesses.append("FreeBSD")

                elif received.haslayer(ICMP):
                    icmp_type = received[ICMP].type
                    icmp_code = received[ICMP].code
                    print(Fore.BLUE + f"[{time.strftime('%H:%M:%S')}] Received ICMP response:")
                    print(Fore.BLUE + f"  - Type: {icmp_type}, Code: {icmp_code}")
                    if icmp_type == 3 and icmp_code == 3:
                        os_guesses.append("Generic Unix")
                    elif icmp_type == 0:
                        os_guesses.append("Linux or Windows")

        # Determine the most likely OS using heuristic matching
        os_result = max(set(os_guesses), key=os_guesses.count) if os_guesses else "Unknown"
        print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] Likely OS: {os_result}")

    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error during advanced OS fingerprinting: {e}")





def query_shodan(ip):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Querying Shodan for {ip}...")
        shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(shodan_url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'vulns' in data:
                print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] Known vulnerabilities for {ip} (Shodan):")
                for vuln, info in data['vulns'].items():
                    cvss_score = info.get('cvss', 'N/A')
                    print(Fore.CYAN + f"- {vuln} - CVSS: {cvss_score}")
            else:
                print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] No known vulnerabilities found for {ip} (Shodan).")
        else:
            print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] Shodan API returned status code {response.status_code}.")
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Shodan API failed: {e}")





def query_nvd(service_info):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Querying NVD for {service_info}...")
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service_info}"
        response = requests.get(nvd_url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if 'result' in data and 'CVE_Items' in data['result']:
                print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] Known vulnerabilities for {service_info} (NVD):")
                for item in data['result']['CVE_Items'][:5]:  # Show top 5 vulnerabilities
                    cve_id = item['cve']['CVE_data_meta']['ID']
                    summary = item['cve']['description']['description_data'][0]['value']
                    cvss_score = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 'N/A')
                    print(Fore.CYAN + f"- {cve_id} - CVSS: {cvss_score} - {summary}")
            else:
                print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] No known vulnerabilities found for {service_info} (NVD).")
        else:
            print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] NVD API returned status code {response.status_code}.")
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error querying NVD: {e}")





def query_circl(service_info):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Querying CIRCL for {service_info}...")
        circl_url = f"https://cve.circl.lu/api/search/{service_info}"
        response = requests.get(circl_url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data:
                print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] Potential vulnerabilities for {service_info} (CIRCL):")
                for cve in data[:5]:  # Show top 5 vulnerabilities
                    cvss_score = cve.get('cvss', 'N/A')
                    summary = cve.get('summary', 'No summary available')
                    print(Fore.CYAN + f"- {cve['id']} - CVSS: {cvss_score} - {summary}")
            else:
                print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] No vulnerabilities found for {service_info} (CIRCL).")
        else:
            print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] CIRCL API returned status code {response.status_code}.")
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error querying CIRCL: {e}")



def query_exploit_db(service_info):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Querying Exploit-DB for {service_info}...")
        exploit_db_url = f"https://www.exploit-db.com/search?description={service_info}&cve=true"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(exploit_db_url, headers=headers, timeout=5)

        if response.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            exploits = []
            for item in soup.select(".exploit-list .d-flex"):
                title = item.select_one(".col-lg-8").text.strip()
                cve_id = item.select_one(".col-lg-2").text.strip()
                if cve_id:
                    exploits.append(f"- {cve_id} - {title}")
            if exploits:
                print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] Potential exploits for {service_info}:")
                for exploit in exploits[:5]:  # Show top 5 exploits
                    print(Fore.CYAN + exploit)
            else:
                print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] No exploits found for {service_info} (Exploit-DB).")
        else:
            print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] Exploit-DB returned status code {response.status_code}.")
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error querying Exploit-DB: {e}")





def vulnerability_scan(ip, open_ports):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Starting vulnerability scan for {ip}...")
        vulnerability_results = []

        # Query Shodan for host information
        query_shodan(ip)

        # Suggest exploits and query Exploit-DB for each open port
        for port in open_ports:
            service_info = TOP_PORTS.get(port, "Unknown")
            vulnerabilities = suggest_exploits(service_info, port)
            vulnerability_results.extend(vulnerabilities)

            # Query Exploit-DB
            query_exploit_db(service_info)

        print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] Vulnerability scan completed for {ip}.")
        return vulnerability_results
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error during vulnerability scan: {e}")
        return []







def traceroute(ip):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Starting traceroute to {ip}...")
        for ttl in range(1, 30):
            packet = IP(dst=ip, ttl=ttl) / ICMP()
            reply = sr1(packet, timeout=1, verbose=False)
            if reply is None:
                print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] TTL {ttl}: No response")
            elif reply.type == 0:
                print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] TTL {ttl}: Reached {reply.src}")
                break
            else:
                print(Fore.BLUE + f"[{time.strftime('%H:%M:%S')}] TTL {ttl}: {reply.src}")
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error during traceroute: {e}")




def geolocation(ip):
    try:
        if geoip_reader:
            response = geoip_reader.city(ip)
            print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] Geolocation for {ip}:")
            print(Fore.CYAN + f"  - Country: {response.country.name}")
            print(Fore.CYAN + f"  - City: {response.city.name}")
            print(Fore.CYAN + f"  - Latitude: {response.location.latitude}")
            print(Fore.CYAN + f"  - Longitude: {response.location.longitude}")
        else:
            print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] GeoIP database not found.")
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error during geolocation lookup: {e}")




def get_domain_from_ip(ip):
    try:
        # Perform reverse DNS lookup to resolve IP to domain
        domain = socket.gethostbyaddr(ip)[0]
        return domain
    except Exception:
        # If reverse DNS fails, return the original IP address
        return ip


def whois_lookup(ip_or_domain):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Starting WHOIS lookup for {ip_or_domain}...")

        # Resolve IP to domain if necessary
        if is_ip_address(ip_or_domain):  # Check if input is an IP address
            domain = get_domain_from_ip(ip_or_domain)
            ip = ip_or_domain
        else:  # Input is already a domain
            domain = ip_or_domain
            try:
                ip = socket.gethostbyname(domain)  # Resolve domain to IP
            except Exception:
                ip = "Could not resolve IP"

        # Perform WHOIS lookup
        w = whois.whois(domain)

        # Prepare WHOIS data for the report
        if w.domain_name:
            whois_data = {
                "Domain": w.domain_name,
                "IP Address": ip,  # Add the resolved IP address
                "Registrar": w.registrar or "N/A",
                "Creation Date": w.creation_date or "N/A",
                "Expiration Date": w.expiration_date or "N/A",
                "Name Servers": w.name_servers or "N/A",
                "Status": w.status or "N/A",
                "Updated Date": w.updated_date or "N/A",
                "Emails": w.emails or "N/A"
            }
        else:
            whois_data = {
                "Domain": "No WHOIS information found.",
                "IP Address": ip  # Include the IP even if WHOIS fails
            }

        # Print WHOIS information
        if isinstance(w.domain_name, list):
            domain_name = ", ".join(w.domain_name)
        else:
            domain_name = w.domain_name or "N/A"

        print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] WHOIS information for {domain}:")
        print(Fore.CYAN + f"  - Domain: {domain_name}")
        print(Fore.CYAN + f"  - IP Address: {ip}")  # Display the resolved IP
        print(Fore.CYAN + f"  - Registrar: {w.registrar or 'N/A'}")
        print(Fore.CYAN + f"  - Creation Date: {w.creation_date or 'N/A'}")
        print(Fore.CYAN + f"  - Expiration Date: {w.expiration_date or 'N/A'}")
        print(Fore.CYAN + f"  - Name Servers: {w.name_servers or 'N/A'}")
        print(Fore.CYAN + f"  - Status: {w.status or 'N/A'}")
        print(Fore.CYAN + f"  - Updated Date: {w.updated_date or 'N/A'}")
        print(Fore.CYAN + f"  - Emails: {w.emails or 'N/A'}")

        return whois_data  # Return the WHOIS data for the report

    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error during WHOIS lookup: {e}")
        return {"Domain": f"Error during WHOIS lookup: {e}", "IP Address": ip}





def ssl_tls_check(ip, port=443):
    try:
        if port not in scan_ports(ip, [443], protocol="tcp"):
            print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Skipping SSL/TLS check as port {port} is not open.")
            return

        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Starting SSL/TLS check for {ip}:{port}...")
        context = ssl.create_default_context()
        with socket.create_connection((ip, port)) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] SSL/TLS information for {ip}:{port}:")
                print(Fore.CYAN + f"  - Version: {ssock.version()}")
                print(Fore.CYAN + f"  - Cipher: {ssock.cipher()}")
    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error during SSL/TLS check: {e}")





def start_scan(ip, ports, protocol="tcp"):
    try:
        print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Starting scan on {ip}...")
        open_ports = scan_ports(ip, ports, protocol)
        print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] Open ports: {open_ports}")

        if not open_ports:
            print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] No open ports found on {ip}. Skipping further steps.")
            return

        # Perform NSLookup
        nslookup_result = ""
        try:
            domain = get_domain_from_ip(ip)
            print(Fore.CYAN + f"[{time.strftime('%H:%M:%S')}] NSLookup result: {domain}")
            nslookup_result = domain
        except Exception as e:
            print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error during NSLookup: {e}")
            nslookup_result = "Error during NSLookup"

        # Perform OS fingerprinting
        os_result = os_fingerprinting(ip)

        # Perform vulnerability scan
        vulnerability_results = vulnerability_scan(ip, open_ports)

        # Perform traceroute
        traceroute_results = []
        try:
            print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Starting traceroute to {ip}...")
            for ttl in range(1, 30):
                packet = IP(dst=ip, ttl=ttl) / ICMP()
                reply = sr1(packet, timeout=1, verbose=False)
                if reply is None:
                    traceroute_results.append(f"TTL {ttl}: No response")
                elif reply.type == 0:
                    traceroute_results.append(f"TTL {ttl}: Reached {reply.src}")
                    break
                else:
                    traceroute_results.append(f"TTL {ttl}: {reply.src}")
        except Exception as e:
            traceroute_results.append(f"Error during traceroute: {e}")

        # Perform geolocation lookup
        geo_data = {}
        try:
            if geoip_reader:
                response = geoip_reader.city(ip)
                geo_data = {
                    "Country": response.country.name,
                    "City": response.city.name,
                    "Latitude": response.location.latitude,
                    "Longitude": response.location.longitude
                }
            else:
                geo_data = "GeoIP database not found."
        except Exception as e:
            geo_data = f"Error during geolocation lookup: {e}"

        # Perform WHOIS lookup
        whois_data = {}
        try:
            domain = get_domain_from_ip(ip)
            w = whois.whois(domain)
            if w.domain_name:
                whois_data = {
                    "Domain": w.domain_name,
                    "Registrar": w.registrar or "N/A",
                    "Creation Date": w.creation_date or "N/A",
                    "Expiration Date": w.expiration_date or "N/A",
                    "Name Servers": w.name_servers or "N/A",
                    "Status": w.status or "N/A",
                    "Updated Date": w.updated_date or "N/A",
                    "Emails": w.emails or "N/A"
                }
            else:
                whois_data = "No WHOIS information found."
        except Exception as e:
            whois_data = f"Error during WHOIS lookup: {e}"

        # Perform SSL/TLS check (if port 443 is open)
        ssl_info = {}
        if 443 in open_ports:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((ip, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        ssl_info = {
                            "Version": ssock.version(),
                            "Cipher": ssock.cipher()
                        }
            except Exception as e:
                ssl_info = {"Version": f"Error during SSL/TLS check: {e}"}
        else:
            ssl_info = {"Version": "Skipping SSL/TLS check as port 443 is not open."}

        # Query website vulnerabilities
        website_vulnerabilities = []
        if nslookup_result != "Error during NSLookup":
            try:
                print(Fore.YELLOW + f"[{time.strftime('%H:%M:%S')}] Querying website vulnerabilities for {nslookup_result}...")
                cve_details_url = f"https://www.cvedetails.com/domain/{nslookup_result}/"
                headers = {"User-Agent": "Mozilla/5.0"}
                response = requests.get(cve_details_url, headers=headers, timeout=5)

                if response.status_code == 200:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for row in soup.select("table.listtable tr")[1:6]:  # Show top 5 vulnerabilities
                        cols = row.find_all('td')
                        if len(cols) >= 3:
                            cve_id = cols[0].text.strip()
                            summary = cols[2].text.strip()
                            website_vulnerabilities.append((cve_id, summary))
                    if not website_vulnerabilities:
                        print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] No website vulnerabilities found for {nslookup_result}.")
                else:
                    print(Fore.RED + f"[{time.strftime('%H:%M:%S')}] CVE Details returned status code {response.status_code}.")
            except Exception as e:
                print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error querying website vulnerabilities: {e}")

        # Collect banners for open ports
        port_banners = {}
        for port in open_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                banner = ""
                if port == 80 or port == 443:
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip.encode())
                elif port == 21:
                    sock.sendall(b"USER anonymous\r\n")
                elif port == 22:
                    sock.sendall(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8\r\n")
                elif port == 23:
                    sock.sendall(b"\r\n")
                elif port == 25:
                    sock.sendall(b"EHLO localhost\r\n")
                else:
                    sock.sendall(b"WhoAreYou\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                port_banners[port] = banner if banner else "No banner detected"
            except Exception as e:
                port_banners[port] = f"Error detecting service version: {e}"

        # Generate HTML report
        generate_html_report(
            ip,
            port_banners,
            os_result,
            vulnerability_results,
            traceroute_results,
            geo_data,
            whois_data,
            ssl_info,
            nslookup_result,  # Add NSLookup result
            website_vulnerabilities  # Add website vulnerabilities
        )

        print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] Scan completed.")

    except Exception as e:
        print(Fore.MAGENTA + f"[{time.strftime('%H:%M:%S')}] Error during scan: {e}")





if __name__ == "__main__":
    display_banner()
    target_ip = input(Fore.YELLOW + "Enter target IP address: ")
    port_range = input(Fore.YELLOW + "Enter port range (e.g., 1-100 or 'Top Ports'): ")
    if port_range.lower() == "top ports":
        ports = list(TOP_PORTS.keys())
        print(Fore.GREEN + f"[{time.strftime('%H:%M:%S')}] Scanning top ports: {ports}")
    else:
        try:
            start_port, end_port = map(int, port_range.split("-"))
            ports = list(range(start_port, end_port + 1))
        except ValueError:
            print(Fore.RED + "[ERROR] Invalid port range format.")
            exit()
    start_scan(target_ip, ports)
