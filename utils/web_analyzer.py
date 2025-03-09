import asyncio
import aiohttp
import ssl
import json
from typing import Dict, List, Optional
import requests
import builtwith

class WebAnalyzer:
    def __init__(self, logger):
        self.logger = logger
        self._common_wafs = {
            "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status"],
            "AWS WAF": ["x-amzn-RequestId", "x-amz-cf-id", "x-amz-id-2"],
            "Akamai": ["akamai-origin-hop", "aka-", "x-akamai-transformed"],
            "ModSecurity": ["mod_security", "NOYB"],
            "Imperva": ["x-iinfo", "_imp_apg_r_", "visid_incap_"],
            "F5 BIG-IP": ["BigIP", "BIGipServer", "TS"],
            "Sucuri": ["x-sucuri-", "sucuri-"],
        }
        self.security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Feature-Policy",
            "Permissions-Policy",
            "Access-Control-Allow-Origin"
        ]

    async def analyze_website(self, url: str) -> Dict:
        try:
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'

            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False) as response:
                    headers = dict(response.headers)
                    html_content = await response.text()

            results = {
                "technologies": await self.detect_technologies(url, html_content),
                "waf": self.detect_waf(headers),
                "security_headers": self.analyze_security_headers(headers),
                "potential_vulnerabilities": await self.check_common_vulnerabilities(url),
                "server_info": headers.get("Server", "Not disclosed"),
                "powered_by": headers.get("X-Powered-By", "Not disclosed"),
            }

            return results

        except Exception as e:
            self.logger.error(f"Error analyzing website {url}: {e}")
            return {}

    async def detect_technologies(self, url: str, html_content: str) -> Dict:
        try:
            builtwith_results = builtwith.parse(url)

            technologies = {
                "frameworks": [],
                "cms": [],
                "languages": [],
                "servers": [],
                "javascript_libraries": []
            }

            for category, items in builtwith_results.items():
                if "framework" in category.lower():
                    technologies["frameworks"].extend(items)
                elif "cms" in category.lower():
                    technologies["cms"].extend(items)
                elif "programming-languages" in category.lower():
                    technologies["languages"].extend(items)
                elif "web-servers" in category.lower():
                    technologies["servers"].extend(items)
                elif "javascript" in category.lower():
                    technologies["javascript_libraries"].extend(items)

            for category in technologies:
                technologies[category] = list(set(technologies[category]))

            return technologies

        except Exception as e:
            self.logger.error(f"Error detecting technologies: {e}")
            return {}

    def detect_waf(self, headers: Dict) -> Dict:
        """Detect presence of Web Application Firewalls"""
        detected_wafs = []

        for waf_name, signatures in self._common_wafs.items():
            for signature in signatures:
                if any(signature.lower() in header.lower() for header in headers):
                    detected_wafs.append(waf_name)
                    break

        security_headers = [
            "x-security",
            "x-firewall",
            "x-waf",
            "x-protection",
            "x-protected-by"
        ]

        for header in headers:
            if any(sec_header in header.lower() for sec_header in security_headers):
                detected_wafs.append(f"Generic WAF (detected via {header})")

        return {
            "detected": bool(detected_wafs),
            "identified_wafs": list(set(detected_wafs))
        }

    def analyze_security_headers(self, headers: Dict) -> Dict:
        results = {
            "present": [],
            "missing": [],
            "analysis": {}
        }

        for header in self.security_headers:
            if header in headers:
                results["present"].append(header)
                results["analysis"][header] = {
                    "value": headers[header],
                    "status": "OK"
                }

                if header == "Content-Security-Policy":
                    results["analysis"][header]["recommendation"] = "Review CSP directives for unnecessary permissions"
                elif header == "X-Frame-Options" and headers[header].upper() not in ["DENY", "SAMEORIGIN"]:
                    results["analysis"][header]["status"] = "Warning"
                    results["analysis"][header]["recommendation"] = "Consider setting to DENY or SAMEORIGIN"
            else:
                results["missing"].append(header)

        return results

    async def check_common_vulnerabilities(self, url: str) -> List[Dict]:
        vulnerabilities = []

        checks = [
            self._check_cors_misconfig(url),
            self._check_information_disclosure(url),
            self._check_http_methods(url),
            self._check_ssl_tls(url)
        ]

        results = await asyncio.gather(*checks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result.get("vulnerable"):
                vulnerabilities.append(result)

        return vulnerabilities

    async def _check_cors_misconfig(self, url: str) -> Dict:
        try:
            headers = {
                "Origin": "https://evil.com"
            }
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, ssl=False) as response:
                    cors_header = response.headers.get("Access-Control-Allow-Origin")

                    if cors_header == "*" or cors_header == "https://evil.com":
                        return {
                            "vulnerable": True,
                            "type": "CORS Misconfiguration",
                            "details": f"Allows requests from {cors_header}",
                            "severity": "Medium"
                        }
            return {"vulnerable": False}
        except Exception as e:
            self.logger.debug(f"CORS check error: {e}")
            return {"vulnerable": False}

    async def _check_information_disclosure(self, url: str) -> Dict:
        """Check for common information disclosure patterns"""
        sensitive_paths = [
            "/robots.txt",
            "/.git/config",
            "/.env",
            "/sitemap.xml",
            "/.htaccess",
            "/crossdomain.xml",
            "/phpinfo.php"
        ]

        for path in sensitive_paths:
            try:
                full_url = f"{url.rstrip('/')}{path}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(full_url, ssl=False) as response:
                        if response.status == 200:
                            return {
                                "vulnerable": True,
                                "type": "Information Disclosure",
                                "details": f"Sensitive file accessible: {path}",
                                "severity": "Medium"
                            }
            except Exception:
                continue

        return {"vulnerable": False}

    async def _check_http_methods(self, url: str) -> Dict:
        """Check for dangerous HTTP methods"""
        dangerous_methods = ["PUT", "DELETE", "TRACE", "OPTIONS"]

        for method in dangerous_methods:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.request(method, url, ssl=False) as response:
                        if response.status not in [403, 405, 501]:
                            return {
                                "vulnerable": True,
                                "type": "Dangerous HTTP Method",
                                "details": f"Method {method} is enabled",
                                "severity": "High"
                            }
            except Exception:
                continue

        return {"vulnerable": False}

    async def _check_ssl_tls(self, url: str) -> Dict:
        try:
            hostname = url.split("://")[-1].split("/")[0]
            context = ssl.create_default_context()

            with context.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
                sock.connect((hostname, 443))
                cert = sock.getpeercert()

                if ssl.PROTOCOL_TLSv1 in context.supported_protocols():
                    return {
                        "vulnerable": True,
                        "type": "Weak SSL/TLS",
                        "details": "TLSv1.0 is supported",
                        "severity": "Medium"
                    }

                import datetime
                exp_date = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if exp_date - datetime.datetime.now() < datetime.timedelta(days=30):
                    return {
                        "vulnerable": True,
                        "type": "SSL Certificate",
                        "details": "Certificate expires soon",
                        "severity": "Medium"
                    }

        except Exception as e:
            self.logger.debug(f"SSL/TLS check error: {e}")

        return {"vulnerable": False}
