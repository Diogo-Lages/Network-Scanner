# Network-Scanner

The **Network-Scanner** is an advanced tool designed to scan networks, identify open ports, detect services, analyze web technologies, and generate detailed reports. It supports both IPv4 and IPv6 scanning, geolocation, vulnerability checks, and more.

## Features

- **Port Scanning**: Scan default or custom ports to identify open ports and running services.
- **Service Detection**: Detect services like HTTP, SSH, FTP, and more using banners and extended probes.
- **Web Analysis**: Analyze websites for technologies, security headers, WAF detection, and potential vulnerabilities.
- **Geolocation**: Identify the physical location of IP addresses (requires `GeoLite2-City.mmdb`).
- **DNS Information**: Retrieve DNS records (A, MX, TXT) and perform reverse DNS lookups.
- **WHOIS Lookup**: Fetch domain registration details.
- **Reporting**: Generate professional HTML and JSON reports with risk assessments.
- **Customizable**: Configure timeouts, concurrent scans, and reporting formats via `config.yml`.
- **Cross-Platform**: Works on Windows, Linux, and macOS.

## Requirements

- Python 3.8 or higher
- GeoLite2 City Database (`GeoLite2-City.mmdb`) for geolocation features
- Templates: `report_template.html` and `report_style.css` for HTML report generation
- YAML configuration file (`config.yml`) for scanner settings

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Diogo-Lages/Network-Scanner.git
   cd Network-Scanner
   ```

2. Download the GeoLite2 City database (`GeoLite2-City.mmdb`) and place it in the root directory of the project:
   - You can download it from [MaxMind](https://www.maxmind.com).

3. Ensure all required templates (`report_template.html` and `report_style.css`) are in the `templates` folder.

4. Run the scanner:
   ```bash
   python scanner.py
   ```

## Usage

1. Launch the scanner:
   ```bash
   python scanner.py
   ```

2. Follow the interactive menu to:
   - Select scanning mode (IPv4 only, IPv6 only, or both).
   - Enter target hosts/IPs (comma-separated).
   - Optionally specify custom ports for scanning.

3. After the scan completes, view the results in the terminal and access generated reports in the `reports` folder.

### Example

```bash
Enter target hosts/IPs (comma-separated):
> example.com, 192.168.1.1

Use custom ports? (y/N):
> y
Enter ports (comma-separated, e.g., 80,443,8080):
> 22,80,443
```

## Code Structure

- **`scanner.py`**: Main entry point for the application. Handles user interaction and orchestrates the scanning process.
- **`utils/async_scanner.py`**: Implements asynchronous port scanning and service detection.
- **`utils/web_analyzer.py`**: Analyzes websites for technologies, vulnerabilities, and security headers.
- **`utils/reporter.py`**: Generates HTML and JSON reports based on scan results.
- **`utils/config_manager.py`**: Manages configuration loading and validation from `config.yml`.
- **`utils/logger.py`**: Handles logging to both console and file outputs.
- **`templates/`**: Contains HTML and CSS templates for report generation.
- **`GeoLite2-City.mmdb`**: GeoIP database for geolocation features.
- **`config.yml`**: Configuration file for scanner settings.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
