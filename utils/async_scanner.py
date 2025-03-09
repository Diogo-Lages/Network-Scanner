import asyncio
import aiohttp
import socket
import ipaddress
import ssl
from .logger import ScannerLogger
from .web_analyzer import WebAnalyzer
from typing import Dict, Set, List, Tuple
import time

TOP_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http-alt",
    8443: "https-alt"
}

class AsyncScanner:
    def __init__(self, config):
        self.config = config
        self.logger = ScannerLogger()
        self.scan_results: Dict[str, Dict[int, str]] = {}
        self._seen_results: Set[str] = set()
        self.rate_limiter = asyncio.Semaphore(self.config["scanner"].get("max_concurrent_scans", 10))
        self._last_scan_time = {}
        self.scan_stats = {
            "total_ports_scanned": 0,
            "open_ports_found": 0,
            "scan_duration": 0,
            "errors_encountered": 0,
            "web_services_analyzed": 0,
            "vulnerabilities_found": 0
        }
        self.web_analyzer = WebAnalyzer(self.logger)

    def validate_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            try:
                resolved = socket.getaddrinfo(ip, None)
                return any(family in (socket.AF_INET, socket.AF_INET6) for family, *_ in resolved)
            except socket.gaierror:
                return False

    async def _delay_if_needed(self, ip: str):
        """Implement rate limiting per host"""
        now = time.time()
        if ip in self._last_scan_time:
            elapsed = now - self._last_scan_time[ip]
            if elapsed < 0.1:  # Minimum 100ms between scans to same host
                await asyncio.sleep(0.1 - elapsed)
        self._last_scan_time[ip] = now

    async def scan_port(self, ip: str, port: int, semaphore: asyncio.Semaphore) -> Tuple[int, str]:
        self.scan_stats["total_ports_scanned"] += 1

        if not self.validate_ip(ip):
            self.logger.error(f"Invalid IP or hostname: {ip}")
            self.scan_stats["errors_encountered"] += 1
            return port, "error"

        result_key = f"{ip}:{port}"
        if result_key in self._seen_results:
            return port, "duplicate"

        async with semaphore, self.rate_limiter:
            await self._delay_if_needed(ip)
            try:
                max_retries = self.config["scanner"].get("max_retries", 3)
                retry_delay = self.config["scanner"].get("retry_delay", 1)

                for retry in range(max_retries):
                    try:
                        # Try both IPv4 and IPv6
                        for family in (socket.AF_INET, socket.AF_INET6):
                            try:
                                reader, writer = await asyncio.wait_for(
                                    asyncio.open_connection(ip, port, family=family),
                                    timeout=self.config["scanner"]["timeout"]
                                )

                                family_str = "IPv6" if family == socket.AF_INET6 else "IPv4"
                                self._seen_results.add(result_key)
                                self.logger.info(f"Port {port} is open on {ip} ({family_str})")
                                self.scan_stats["open_ports_found"] += 1

                                writer.close()
                                await writer.wait_closed()
                                return port, "open"
                            except (socket.gaierror, OSError):
                                continue

                        if retry < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                            continue

                        return port, "closed"

                    except asyncio.TimeoutError:
                        if retry < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                            continue
                        return port, "filtered"

                return port, "closed"

            except Exception as e:
                self.logger.error(f"Error scanning port {port}: {e}")
                self.scan_stats["errors_encountered"] += 1
                return port, "error"

    async def service_detection(self, ip: str, port: int) -> str:
        try:
            service_name = None
            try:
                service_name = socket.getservbyport(port)
            except (OSError, socket.error):
                service_name = TOP_PORTS.get(port, "unknown")

            service_info = []
            service_info.append(service_name)

            if self.config["fingerprinting"]["enable_extended_probes"]:
                # Web service analysis for HTTP/HTTPS ports
                if port in [80, 443, 8080, 8443]:
                    protocol = "https" if port in [443, 8443] else "http"
                    url = f"{protocol}://{ip}:{port}"

                    try:
                        web_analysis = await self.web_analyzer.analyze_website(url)
                        self.scan_stats["web_services_analyzed"] += 1

                        if web_analysis:
                            # Add WAF information
                            if web_analysis["waf"]["detected"]:
                                service_info.append(f"WAF Detected: {', '.join(web_analysis['waf']['identified_wafs'])}")

                            # Add technology stack
                            tech = web_analysis["technologies"]
                            if tech.get("frameworks"):
                                service_info.append(f"Frameworks: {', '.join(tech['frameworks'])}")
                            if tech.get("cms"):
                                service_info.append(f"CMS: {', '.join(tech['cms'])}")

                            # Add security headers status
                            missing_headers = web_analysis["security_headers"]["missing"]
                            if missing_headers:
                                service_info.append(f"Missing Security Headers: {', '.join(missing_headers)}")

                            # Add vulnerabilities
                            vulns = web_analysis["potential_vulnerabilities"]
                            if vulns:
                                self.scan_stats["vulnerabilities_found"] += len(vulns)
                                vuln_info = [f"{v['type']} ({v['severity']})" for v in vulns]
                                service_info.append(f"Potential Vulnerabilities: {', '.join(vuln_info)}")

                    except Exception as e:
                        self.logger.debug(f"Web analysis error for {url}: {e}")

                # SSL/TLS information
                elif port in [443, 8443]:
                    ssl_info = await self.get_ssl_info(ip, port)
                    if ssl_info:
                        service_info.append(ssl_info)

                # Banner information
                banner = await self.grab_generic_banner(ip, port)
                if banner:
                    service_info.append(banner)

            return " - ".join(filter(None, service_info))

        except Exception as e:
            self.logger.error(f"Error detecting service on port {port}: {e}")
            return TOP_PORTS.get(port, "unknown")

    async def get_ssl_info(self, ip: str, port: int) -> str:
        try:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            conn = await asyncio.open_connection(ip, port, ssl=ssl_context)
            reader, writer = conn

            try:
                ssl_obj = writer.get_extra_info('ssl_object')
                if ssl_obj:
                    info = []
                    info.append(f"TLS {ssl_obj.version()}")
                    info.append(f"Cipher: {ssl_obj.cipher()[0]}")
                    cert = ssl_obj.getpeercert(binary_form=True)
                    if cert:
                        info.append("Certificate present")
                    return ", ".join(info)
            finally:
                writer.close()
                await writer.wait_closed()

            return None
        except Exception as e:
            self.logger.debug(f"SSL info error: {e}")
            return None

    async def grab_http_banner(self, ip: str, port: int, secure: bool = False) -> str:
        try:
            url = f"{'https' if secure else 'http'}://{ip}:{port}"
            timeout = aiohttp.ClientTimeout(total=2)

            ssl_context = None
            if secure:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=ssl_context) as response:
                    info = []

                    # Server information
                    server = response.headers.get('Server', '')
                    if server:
                        info.append(f"Server: {server}")

                    # Additional headers of interest
                    interesting_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
                    for header in interesting_headers:
                        if header in response.headers:
                            info.append(f"{header}: {response.headers[header]}")

                    status_info = f"HTTP {response.status}"
                    if info:
                        status_info += f" ({', '.join(info)})"
                    return status_info
        except Exception as e:
            self.logger.debug(f"HTTP banner error: {e}")
            return None

    async def grab_generic_banner(self, ip: str, port: int) -> str:
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            try:
                # Send different probes based on the port
                if port == 21:  # FTP
                    pass  # FTP servers usually send banner automatically
                elif port == 22:  # SSH
                    pass  # SSH servers usually send banner automatically
                elif port == 25:  # SMTP
                    writer.write(b"EHLO scanner.local\r\n")
                elif port == 110:  # POP3
                    pass  # POP3 servers usually send banner automatically
                else:
                    writer.write(b"\r\n")
                await writer.drain()

                banner = await asyncio.wait_for(reader.read(1024), timeout=2)
                decoded = banner.decode('utf-8', errors='ignore').strip()
                if decoded:
                    # Clean up the banner - remove excessive whitespace and newlines
                    return ' '.join(decoded.split())
                return None
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            self.logger.debug(f"Generic banner error: {e}")
            return None

    async def scan_host(self, ip: str) -> Dict[int, str]:
        try:
            if not self.validate_ip(ip):
                self.logger.error(f"Invalid IP or hostname: {ip}")
                return {}

            start_time = time.time()
            semaphore = asyncio.Semaphore(self.config["scanner"]["max_concurrent_scans"])
            ports = self.config["scanner"]["default_ports"]

            scan_tasks = [
                self.scan_port(ip, port, semaphore)
                for port in ports
            ]

            results = await asyncio.gather(*scan_tasks)

            # Process results and de-duplicate
            open_ports = {}
            for port, status in results:
                if status == "open":
                    service = await self.service_detection(ip, port)
                    if service:  # Only add if service detection was successful
                        open_ports[port] = service

            if open_ports:  # Only store results if we found open ports
                self.scan_results[ip] = open_ports

            # Update scan duration
            self.scan_stats["scan_duration"] = time.time() - start_time
            return open_ports

        except Exception as e:
            self.logger.error(f"Error scanning host {ip}: {e}")
            self.scan_stats["errors_encountered"] += 1
            return {}

    def get_results(self) -> Dict[str, Dict[int, str]]:
        return self.scan_results

    def get_stats(self) -> Dict:
        return self.scan_stats