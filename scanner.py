import asyncio
from colorama import init, Fore, Style, Back
import sys
import os
from datetime import datetime
import socket
import dns.resolver
import dns.reversename
import whois
import requests
import geoip2.database
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.console import Console
from rich.table import Table
from typing import List, Dict, Optional
import subprocess
import platform

from utils.async_scanner import AsyncScanner
from utils.reporter import ScanReporter
from utils.config_manager import ConfigManager
from utils.logger import ScannerLogger

class NetworkScanner:
    GEOLITE_DB = "GeoLite2-City.mmdb"

    def __init__(self):
        init(autoreset=True)  
        self.config_manager = ConfigManager()
        self.logger = ScannerLogger()
        self.scanner = AsyncScanner(self.config_manager.get_config())
        self.reporter = ScanReporter()
        self._seen_dns = set()  
        self.console = Console()

        self.geolocation_enabled = os.path.exists(self.GEOLITE_DB)
        if not self.geolocation_enabled:
            self.logger.warning(f"GeoLite2 database not found at {self.GEOLITE_DB}. Geolocation features will be disabled.")

        self.config = self.config_manager.get_config()
        print(Style.BRIGHT + Fore.CYAN + "\nFeature Status:")
        features = [
            ("Geolocation", self.geolocation_enabled),
            ("Service Fingerprinting", self.config["fingerprinting"]["enable_extended_probes"]),
            ("Vulnerability Checking", self.config["vulnerability"]["enable_vuln_check"]),
            ("DNS Information", self.config["dns"]["enable_ptr"]),
            ("WHOIS Lookup", self.config["features"]["whois_lookup"])
        ]

        for feature, enabled in features:
            status = Fore.GREEN + "Enabled" if enabled else Fore.YELLOW + "Disabled"
            print(f"{Fore.WHITE}• {feature}: {status}")
        print(Style.RESET_ALL)

    def display_banner(self):
        banner = r"""
        ███▄    █ ▓█████▄▄▄█████▓  ██████  ▄████▄   ▄▄▄       ███▄    █ 
        ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ 
        ▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
        ▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░   ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
        ▒██░   ▓██░░▒████▒ ▒██▒ ░ ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
        ░ ▒░   ▒ ▒ ░░ ▒░ ░ ▒ ░░   ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
        ░ ░░   ░ ▒░ ░ ░  ░   ░    ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
        ░   ░ ░ ▒░ ░ ░    ░      ░  ░  ░  ░          ░   ▒      ░   ░ ░ 
        ░   ░ ░    ░  ░               ░  ░ ░ ░            ░  ░         ░ 
        """
        print(Fore.CYAN + banner)
        print(Style.BRIGHT + Fore.YELLOW + "Enhanced Network Scanner v2.0")
        print(Fore.GREEN + "=" * 70 + Style.RESET_ALL)

    def show_scan_statistics(self, stats: Dict):
        """Display scan statistics in a pretty table"""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Ports Scanned", str(stats["total_ports_scanned"]))
        table.add_row("Open Ports Found", str(stats["open_ports_found"]))
        table.add_row("Scan Duration", f"{stats['scan_duration']:.2f} seconds")
        table.add_row("Errors Encountered", str(stats["errors_encountered"]))

        self.console.print("\nScan Statistics:")
        self.console.print(table)

    async def get_geolocation(self, ip: str) -> Dict:
        """Get geolocation information for an IP address"""
        if not self.geolocation_enabled:
            return {}

        try:
            if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
                return {"city": "Local Network", "country": "Private IP"}

            reader = geoip2.database.Reader(self.GEOLITE_DB)
            response = reader.city(ip)
            reader.close()

            return {
                "city": response.city.name,
                "country": response.country.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }
        except Exception as e:
            self.logger.debug(f"Could not get geolocation info: {e}")
            return {}

    async def get_domain_info(self, domain: str) -> Dict:
        """Get additional domain information"""
        try:
            info = {}
            try:
                w = whois.whois(domain)
                info['registrar'] = w.registrar
                info['creation_date'] = w.creation_date
                info['expiration_date'] = w.expiration_date
            except Exception as e:
                self.logger.warning(f"Could not get WHOIS info: {e}")

            try:
                records = {}
                try:
                    answers = dns.resolver.resolve(domain, 'A')
                    records['A'] = [str(rdata) for rdata in answers]
                except Exception:
                    pass

                try:
                    answers = dns.resolver.resolve(domain, 'MX')  # Fixed: Using domain instead of database
                    records['MX'] = [str(rdata) for rdata in answers]
                except Exception:
                    pass

                try:
                    answers = dns.resolver.resolve(domain, 'TXT')
                    records['TXT'] = [str(rdata) for rdata in answers]
                except Exception:
                    pass

                info['dns_records'] = records
            except Exception as e:
                self.logger.warning(f"Could not get DNS info: {e}")

            return info
        except Exception as e:
            self.logger.error(f"Error getting domain info: {e}")
            return {}

    async def traceroute(self, target: str) -> List[str]:
        try:
            if platform.system().lower() == "windows":
                command = ["tracert", "-h", "30", target]
            else:
                command = ["traceroute", "-m", "30", target]

            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()
            if process.returncode == 0:
                return stdout.decode().split('\n')
            return []
        except Exception as e:
            self.logger.error(f"Error performing traceroute: {e}")
            return []

    async def resolve_target(self, target: str) -> List[str]:
        """Resolve hostname to both IPv4 and IPv6 addresses"""
        addresses = []
        try:
            print(Style.BRIGHT + Fore.CYAN + f"\n[*] Resolving {target}...")

            try:
                ipv4_addrs = await asyncio.get_event_loop().getaddrinfo(
                    target, None, family=socket.AF_INET
                )
                addresses.extend(addr[4][0] for addr in ipv4_addrs)
                print(Fore.GREEN + f"[+] Found IPv4 addresses: {', '.join(set(addr[4][0] for addr in ipv4_addrs))}")
            except socket.gaierror:
                print(Fore.YELLOW + f"[-] No IPv4 address found for {target}")

            try:
                ipv6_addrs = await asyncio.get_event_loop().getaddrinfo(
                    target, None, family=socket.AF_INET6
                )
                addresses.extend(addr[4][0] for addr in ipv6_addrs)
                print(Fore.GREEN + f"[+] Found IPv6 addresses: {', '.join(set(addr[4][0] for addr in ipv6_addrs))}")
            except socket.gaierror:
                print(Fore.YELLOW + f"[-] No IPv6 address found for {target}")

            if not addresses:
                print(Style.BRIGHT + Fore.RED + f"[!] Could not resolve {target} to any IP address")
                return []

            for addr in addresses:
                if addr not in self._seen_dns:
                    try:
                        hostname = socket.gethostbyaddr(addr)[0]
                        print(Fore.CYAN + f"[+] Reverse DNS: {addr} -> {hostname}")
                        self._seen_dns.add(addr)

                        if ':' not in addr:  
                            geo_info = await self.get_geolocation(addr)
                            if geo_info:
                                print(Fore.CYAN + f"[+] Location: {geo_info.get('city', 'Unknown')}, {geo_info.get('country', 'Unknown')}")
                    except socket.herror:
                        print(Fore.YELLOW + f"[-] Could not perform reverse DNS lookup for {addr}")

            return list(set(addresses))

        except Exception as e:
            self.logger.error(f"Error resolving target {target}: {e}")
            return []

    async def run_scan(self, targets: List[str], ipv4_only: bool = False, ipv6_only: bool = False, custom_ports: Optional[List[int]] = None):
        try:
            print(Style.BRIGHT + Fore.CYAN + "\n[*] Initializing scan...")
            self.logger.info(f"Starting scan for targets: {targets}")

            scan_metadata = {
                "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "targets": targets,
                "scanner_version": "2.0",
                "scan_options": {
                    "ipv4_only": ipv4_only,
                    "ipv6_only": ipv6_only,
                    "custom_ports": custom_ports
                }
            }

            if custom_ports:
                self.scanner.config["scanner"]["default_ports"] = custom_ports
                print(Style.BRIGHT + Fore.CYAN + f"[*] Using custom ports: {', '.join(map(str, custom_ports))}")


            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console
            ) as progress:
                resolve_task = progress.add_task("[cyan]Resolving targets...", total=len(targets))


                resolved_targets = []
                for target in targets:
                    try:
                        addresses = await self.resolve_target(target)
                        if addresses:
                            if ipv4_only:
                                addresses = [addr for addr in addresses if ':' not in addr]
                            elif ipv6_only:
                                addresses = [addr for addr in addresses if ':' in addr]

                            resolved_targets.extend(addresses)
                    except Exception as e:
                        print(Style.BRIGHT + Fore.RED + f"[!] Error resolving {target}: {e}")

                    progress.update(resolve_task, advance=1)

                if not resolved_targets:
                    print(Style.BRIGHT + Fore.RED + "[!] No valid targets to scan")
                    return

                print(Style.BRIGHT + Fore.CYAN + f"\n[*] Starting port scan for {len(resolved_targets)} hosts...")

                results_table = Table(show_header=True, header_style="bold magenta")
                results_table.add_column("Host", style="cyan")
                results_table.add_column("Open Ports", style="green")
                results_table.add_column("Services", style="yellow")

                scan_task = progress.add_task("[cyan]Scanning ports...", total=len(resolved_targets))
                scan_tasks = [self.scanner.scan_host(target) for target in resolved_targets]

                await asyncio.gather(*scan_tasks)
                progress.update(scan_task, completed=len(resolved_targets))

            scan_results = self.scanner.get_results()
            scan_stats = self.scanner.get_stats()

            scan_metadata["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            scan_metadata["resolved_targets"] = resolved_targets
            scan_metadata["statistics"] = scan_stats
            report_files = self.reporter.generate_reports(scan_results, scan_metadata)

            print(Style.BRIGHT + Fore.GREEN + "\n[+] Scan completed!")

            self.show_scan_statistics(scan_stats)

            for ip, ports in scan_results.items():
                if ports:
                    open_ports = list(ports.keys())
                    services = [service.split(' - ')[0] for service in ports.values()]
                    results_table.add_row(
                        ip,
                        ", ".join(map(str, open_ports)),
                        ", ".join(services)
                    )
                else:
                    results_table.add_row(ip, "None", "No open ports")

            self.console.print("\nScan Results Summary:")
            self.console.print(results_table)

            print(Style.BRIGHT + Fore.CYAN + "\nReport files generated:")
            for format, filepath in report_files.items():
                print(Fore.GREEN + f"[+] {format.upper()}: {filepath}")

        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            print(Style.BRIGHT + Fore.RED + f"[!] Error during scan: {e}")
            sys.exit(1)

    def get_target_input(self) -> List[str]:
        print(Style.BRIGHT + Fore.YELLOW + "\nEnter target hosts/IPs (comma-separated):")
        print(Style.RESET_ALL, end='')
        targets = input(Fore.CYAN + "> " + Style.RESET_ALL).strip()
        return [t.strip() for t in targets.split(",") if t.strip()]

    def get_port_input(self) -> Optional[List[int]]:
        print(Style.BRIGHT + Fore.YELLOW + "\nUse custom ports? (y/N):")
        print(Style.RESET_ALL, end='')
        choice = input(Fore.CYAN + "> " + Style.RESET_ALL).strip().lower()

        if choice == 'y':
            print(Style.BRIGHT + Fore.YELLOW + "Enter ports (comma-separated, e.g. 80,443,8080):")
            print(Style.RESET_ALL, end='')
            ports = input(Fore.CYAN + "> " + Style.RESET_ALL).strip()
            try:
                return [int(p.strip()) for p in ports.split(",") if p.strip()]
            except ValueError:
                print(Style.BRIGHT + Fore.YELLOW + "[-] Invalid port numbers. Using default ports.")
                return None
        return None

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_menu(self):
        ipv4_only = False
        ipv6_only = False

        while True:
            self.clear_screen()
            self.display_banner()

            mode_color = Fore.GREEN if ipv4_only or ipv6_only else Fore.CYAN
            if ipv4_only:
                mode = f"{mode_color}Current Mode: IPv4 Only"
            elif ipv6_only:
                mode = f"{mode_color}Current Mode: IPv6 Only"
            else:
                mode = f"{mode_color}Current Mode: Both IPv4 and IPv6"
            print(f"\n{mode}{Style.RESET_ALL}")

            # Display menu
            print(Style.BRIGHT + Fore.CYAN + "\nNetwork Scanner Menu:")
            print(Style.BRIGHT + Fore.WHITE + "1. " + Style.RESET_ALL +
                  f"[{Fore.GREEN + 'X' + Style.RESET_ALL if ipv4_only else ' '}] IPv4 Only")
            print(Style.BRIGHT + Fore.WHITE + "2. " + Style.RESET_ALL +
                  f"[{Fore.GREEN + 'X' + Style.RESET_ALL if ipv6_only else ' '}] IPv6 Only")
            print(Style.BRIGHT + Fore.WHITE + "3. " + Style.RESET_ALL + "Start Scan")
            print(Style.BRIGHT + Fore.WHITE + "4. " + Style.RESET_ALL + "View Configuration")
            print(Style.BRIGHT + Fore.WHITE + "5. " + Style.RESET_ALL + "Exit")

            choice = input(Fore.YELLOW + "\nEnter your choice (1-5): " + Style.RESET_ALL)

            if choice == "1":
                ipv4_only = not ipv4_only
                ipv6_only = False
            elif choice == "2":
                ipv6_only = not ipv6_only
                ipv4_only = False
            elif choice == "3":
                targets = self.get_target_input()
                if targets:
                    custom_ports = self.get_port_input()
                    asyncio.run(self.run_scan(targets, ipv4_only, ipv6_only, custom_ports))
                    print(Fore.GREEN + "\nPress Enter to return to the menu..." + Style.RESET_ALL)
                    input()
            elif choice == "4":
                config = self.config_manager.get_config()
                print(Style.BRIGHT + "\nCurrent Configuration:")
                print(Fore.CYAN + "=" * 40)
                print(Style.BRIGHT + "Default Ports: " + Style.RESET_ALL +
                      f"{', '.join(map(str, config['scanner']['default_ports']))}")
                print(Style.BRIGHT + "Timeout: " + Style.RESET_ALL +
                      f"{config['scanner']['timeout']} seconds")
                print(Style.BRIGHT + "Max Concurrent Scans: " + Style.RESET_ALL +
                      f"{config['scanner']['max_concurrent_scans']}")
                print(Style.BRIGHT + "Report Formats: " + Style.RESET_ALL +
                      f"{', '.join(config['reporting']['formats']).upper()}")
                print(Style.BRIGHT + "Service Fingerprinting: " + Style.RESET_ALL +
                      f"{'Enabled' if config['fingerprinting']['enable_extended_probes'] else 'Disabled'}")
                print(Style.BRIGHT + "Vulnerability Checking: " + Style.RESET_ALL +
                      f"{'Enabled' if config['vulnerability']['enable_vuln_check'] else 'Disabled'}")
                print(Fore.CYAN + "=" * 40)
                print(Fore.GREEN + "\nPress Enter to return to the menu..." + Style.RESET_ALL)
                input()
            elif choice == "5":
                print(Fore.YELLOW + "\nGoodbye!")
                sys.exit(0)
            else:
                print(Style.BRIGHT + Fore.YELLOW + "\nInvalid choice. Press Enter to continue..." + Style.RESET_ALL)
                input()

def main():
    scanner = NetworkScanner()
    scanner.show_menu()

if __name__ == "__main__":
    main()
