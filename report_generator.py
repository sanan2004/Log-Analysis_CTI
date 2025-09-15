"""
Module for generating security reports with improved Talos display
"""

import os
from datetime import datetime

class ReportGenerator:
    def generate(self, analysis_data, output_dir="reports"):
        """Generate a comprehensive security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(output_dir, f"security_report_{timestamp}.md")

        with open(report_path, 'w') as f:
            self._write_header(f, timestamp)
            self._write_executive_summary(f, analysis_data)
            self._write_detailed_findings(f, analysis_data)
            self._write_recommendations(f)

        return report_path

    def _write_header(self, f, timestamp):
        f.write("# Cybersecurity Threat Analysis Report\n\n")
        f.write(f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## CTI Sources Used\n")
        f.write("- AbuseIPDB\n")
        f.write("- VirusTotal\n")
        f.write("- Cisco Talos Intelligence\n")
        f.write("- Local Llama AI Analysis\n\n")
        f.write("---\n\n")

    def _write_executive_summary(self, f, analysis_data):
        f.write("## Executive Summary\n\n")

        high_risk_ips = [ip for ip, data in analysis_data.items()
                        if ip != 'overall_analysis' and data.get('risk_score', 0) > 50]

        f.write(f"**High-Risk IP Addresses Identified:** {len(high_risk_ips)}\n\n")

        if high_risk_ips:
            f.write("The following IP addresses exhibited suspicious behavior and require further investigation:\n\n")
            for ip in high_risk_ips:
                risk_score = analysis_data[ip].get('risk_score', 0)
                f.write(f"- {ip} (Risk Score: {risk_score:.1f})\n")
        else:
            f.write("No high-risk IP addresses were identified in this analysis.\n")

        f.write("\n---\n\n")

    def _write_detailed_findings(self, f, analysis_data):
        f.write("## Detailed Findings\n\n")

        for ip, data in analysis_data.items():
            if ip == 'overall_analysis':
                continue

            risk_score = data.get('risk_score', 0)
            if risk_score < 30:
                continue  # Skip low-risk IPs for brevity

            f.write(f"### IP Address: {ip}\n\n")
            f.write(f"**Risk Score:** {risk_score:.1f}/100\n\n")

            # Activity summary
            activity = data['activity']
            f.write("**Activity Summary:**\n")
            f.write(f"- Total Requests: {activity['total_requests']}\n")
            f.write(f"- 4xx Errors: {activity['error_4xx']}\n")
            if activity['total_requests'] > 0:
                error_rate = (activity['error_4xx'] / activity['total_requests']) * 100
                f.write(f"- Error Rate: {error_rate:.1f}%\n")
            f.write(f"- Unique User Agents: {len(activity['user_agents'])}\n\n")

            # CTI findings
            f.write("**Threat Intelligence:**\n")

            # AbuseIPDB
            abuse_data = data['cti']['abuseipdb']
            if 'error' not in abuse_data:
                f.write(f"- **AbuseIPDB**: Confidence {abuse_data.get('confidence_score', 'N/A')}%, ")
                f.write(f"Reports: {abuse_data.get('total_reports', 'N/A')}, ")
                f.write(f"Country: {abuse_data.get('country', 'N/A')}\n")
            else:
                f.write(f"- **AbuseIPDB**: {abuse_data.get('error', 'Error')}\n")

            # VirusTotal
            vt_data = data['cti']['virustotal']
            if 'error' not in vt_data:
                f.write(f"- **VirusTotal**: Malicious: {vt_data.get('malicious', 0)}, ")
                f.write(f"Suspicious: {vt_data.get('suspicious', 0)}, ")
                f.write(f"Reputation: {vt_data.get('reputation', 0)}\n")
            else:
                f.write(f"- **VirusTotal**: {vt_data.get('error', 'Error')}\n")

            # Cisco Talos - Improved display
            talos_data = data['cti']['cisco_talos']
            f.write(f"- **Cisco Talos**: Web Rep: {talos_data.get('web_reputation', 'N/A')}")

            # Only show additional Talos info if we have meaningful data
            owner = talos_data.get('owner', 'N/A')
            country = talos_data.get('country', 'N/A')

            if owner != 'N/A':
                f.write(f", Owner: {owner}")
            if country != 'N/A':
                f.write(f", Country: {country}")
            f.write("\n")

            # Show Talos URL and notes if available
            talos_url = talos_data.get('url', '')
            if talos_url:
                f.write(f"  [View on Talos]({talos_url})\n")

            note = talos_data.get('note', '')
            if note:
                f.write(f"  *Note: {note}*\n")

            # Suspicious user agents
            if data['suspicious_user_agents']:
                f.write("\n**Suspicious User Agents Detected:**\n")
                for agent in data['suspicious_user_agents']:
                    f.write(f"- `{agent}`\n")

            # AI analysis
            if 'ai_analysis' in data:
                f.write(f"\n**AI Analysis:** {data['ai_analysis']}\n")

            f.write("\n---\n\n")

    def _write_recommendations(self, f):
        f.write("## Recommendations\n\n")
        f.write("1. **Block High-Risk IPs**: Consider blocking the identified high-risk IP addresses at the firewall level.\n")
        f.write("2. **Enhanced Monitoring**: Increase monitoring for the suspicious IP addresses and similar patterns.\n")
        f.write("3. **Security Review**: Conduct a thorough security review of applications targeted by these requests.\n")
        f.write("4. **Incident Response**: If evidence of compromise is found, initiate incident response procedures.\n")
        f.write("5. **Threat Hunting**: Use these IOCs to hunt for additional related threats in your environment.\n")
        f.write("6. **Manual Talos Verification**: For comprehensive analysis, manually verify IP reputations on Cisco Talos using the provided URLs.\n")
        f.write("7. **Continuous Monitoring**: Implement ongoing monitoring of identified threat indicators.\n")