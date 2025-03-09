import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import yaml

class ScanReporter:
    def __init__(self, config_path="config.yml"):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)

        self.env = Environment(loader=FileSystemLoader('templates'))
        self.report_dir = self.config["reporting"]["report_dir"]
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_risk_assessment(self, scan_results, metadata):
        """Generate risk assessment based on scan findings"""
        risk_assessment = {
            "high_risks": [],
            "medium_risks": [],
            "low_risks": []
        }

        for ip, ports in scan_results.items():
            for port, service_info in ports.items():
                # Check for critical services
                if port in [3389, 22, 23]:
                    risk_assessment["high_risks"].append(
                        f"Remote access service exposed on {ip}:{port} ({service_info})"
                    )

                # Check for database ports
                if port in [3306, 5432]:
                    risk_assessment["high_risks"].append(
                        f"Database service exposed on {ip}:{port} ({service_info})"
                    )

                # Parse service info for vulnerabilities and security issues
                if isinstance(service_info, str):
                    if "Potential Vulnerabilities" in service_info:
                        risk_assessment["high_risks"].append(
                            f"Vulnerabilities detected on {ip}:{port}"
                        )
                    if "Missing Security Headers" in service_info:
                        risk_assessment["medium_risks"].append(
                            f"Missing security headers on {ip}:{port}"
                        )
                    if "WAF Detected" in service_info:
                        risk_assessment["low_risks"].append(
                            f"WAF protection detected on {ip}:{port}"
                        )

        return risk_assessment

    def generate_html_report(self, scan_results, metadata):
        try:
            template = self.env.get_template('report_template.html')

            # Generate risk assessment
            risk_assessment = self.generate_risk_assessment(scan_results, metadata)

            report_data = {
                "scan_results": scan_results,
                "metadata": metadata,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "config": self.config,
                "risk_assessment": risk_assessment
            }

            html_content = template.render(report_data)

            # Generate filename
            filename = f"{self.report_dir}/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

            with open(filename, 'w') as f:
                f.write(html_content)

            return filename

        except Exception as e:
            raise Exception(f"Error generating HTML report: {e}")

    def generate_json_report(self, scan_results, metadata):
        try:
            # Generate risk assessment
            risk_assessment = self.generate_risk_assessment(scan_results, metadata)

            report_data = {
                "scan_results": scan_results,
                "metadata": metadata,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "config": self.config,
                "risk_assessment": risk_assessment
            }

            filename = f"{self.report_dir}/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=4)

            return filename

        except Exception as e:
            raise Exception(f"Error generating JSON report: {e}")

    def generate_reports(self, scan_results, metadata=None):
        if metadata is None:
            metadata = {}

        reports = {}

        if "html" in self.config["reporting"]["formats"]:
            reports["html"] = self.generate_html_report(scan_results, metadata)

        if "json" in self.config["reporting"]["formats"]:
            reports["json"] = self.generate_json_report(scan_results, metadata)

        return reports