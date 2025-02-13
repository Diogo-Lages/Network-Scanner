# Network Scanner

## Description

Python-based network scanning tool. It scans TCP/UDP ports, detects service versions, performs OS fingerprinting, and identifies vulnerabilities. Additional features include traceroute, geolocation, WHOIS lookup, SSL/TLS checks, and automated HTML report generation.

---

## **Key Features**
- **Port Scanning**: Scan TCP and UDP ports to identify open, closed, or filtered ports.
- **Service Detection**: Detect service versions running on open ports.
- **OS Fingerprinting**: Guess the operating system of the target using advanced techniques.
- **Vulnerability Scanning**: Query external APIs (Shodan, NVD, CIRCL) for potential vulnerabilities.
- **Traceroute**: Map the network path to the target IP.
- **Geolocation**: Determine the geographical location of the target IP.
- **WHOIS Lookup**: Retrieve domain registration details.
- **SSL/TLS Check**: Analyze SSL/TLS configurations for HTTPS services.
- **HTML Report**: Generate a detailed and visually appealing HTML report summarizing the scan results.

---

## **How to Use**
1. Clone the repository:
   ```bash
   git clone https://github.com/Diogo-Lages/Network-Scanner.py.git
   cd Network-Scanner.py
   ```
2. Run the script:
   ```bash
   python network_scanner.py
   ```
3. Enter the target IP address and port range (e.g., `1-100` or `Top Ports`).
4. Review the real-time command-line output and the generated HTML report.

---

## **Requirements**
- Python 3.x
- Required Python libraries: `scapy`, `requests`, `colorama`, `geoip2`, `jinja2`, `whois`, `ssl`
- GeoIP database (optional for geolocation)

Install dependencies:
```bash
pip install scapy requests colorama geoip2 jinja2 python-whois
```

---

## **Example Usage**
```bash
Enter target IP address: 192.168.1.1
Enter port range (e.g., 1-100 or 'Top Ports'): Top Ports
```

---

## **Report Example**
The tool generates an HTML report (`<target_ip>_scan_report.html`) with the following sections:
- **Scan Details**: Timestamp and target IP.
- **Open Ports**: List of open ports and service banners.
- **OS Fingerprinting**: Likely operating system of the target.
- **Vulnerabilities**: Potential vulnerabilities detected.
- **Traceroute**: Network path to the target.
- **Geolocation**: Geographical location of the target.
- **WHOIS Information**: Domain registration details.
- **SSL/TLS Check**: SSL/TLS configuration for HTTPS services.

---

## **Ethical Considerations**
- Always ensure you have proper authorization before scanning any network or system.
- Use this tool responsibly and in compliance with applicable laws and regulations.

---

## **License**
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

