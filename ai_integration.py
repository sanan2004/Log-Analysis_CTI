"""
Module for AI integration using local Llama model via Ollama with encoding fixes
"""

import requests
import json
import os
import time

class AIIntegration:
    def __init__(self, base_url="http://localhost:11434", model="llama3:latest"):
        self.base_url = base_url
        self.model = model
        self.available = self._check_ollama_available()

    def _check_ollama_available(self):
        """Check if Ollama is running and available"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m.get('name', '') for m in models]

                if model_names:
                    print(f"Ollama is available! Models: {', '.join(model_names)}")

                    # Check if requested model is available
                    if self.model in model_names:
                        print(f"Using model: {self.model}")
                    else:
                        available_model = model_names[0] if model_names else "llama3:latest"
                        print(f"Warning: Model '{self.model}' not found. Using '{available_model}' instead.")
                        self.model = available_model
                    return True
            else:
                print("Ollama not responding. AI features disabled.")
                return False
        except requests.exceptions.ConnectionError:
            print("Ollama not running. Please start Ollama or install from https://ollama.com/")
            print("To start Ollama: run 'ollama serve' in your terminal")
            return False
        except Exception as e:
            print(f"Error checking Ollama: {str(e)}")
            return False

    def generate_with_llama(self, prompt, max_tokens=150):
        """Generate text using local Llama model via Ollama API"""
        if not self.available:
            return "AI analysis unavailable: Ollama not running. Install from https://ollama.com/"

        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "num_predict": max_tokens,
                    "top_p": 0.9,
                    "repeat_penalty": 1.1
                }
            }

            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=45  # Longer timeout for larger models
            )
            response.raise_for_status()

            result = response.json()
            # Clean the response to handle Unicode characters properly
            cleaned_response = result['response'].strip().encode('utf-8', 'ignore').decode('utf-8')
            return cleaned_response

        except Exception as e:
            return f"Error generating AI explanation: {str(e)}"

    def generate_threat_explanation(self, ip_data):
        """Generate a plain English explanation of the threat"""
        tech_info = f"""
IP Address: {ip_data.get('ip', 'Unknown')}
Abuse Confidence Score: {ip_data.get('abuse_confidence', 'N/A')}%
VirusTotal Malicious Flags: {ip_data.get('vt_malicious', 0)}
Cisco Talos Web Reputation: {ip_data.get('talos_web_reputation', 'N/A')}
Total Requests: {ip_data.get('total_requests', 0)}
4xx Errors: {ip_data.get('error_4xx', 0)}
Suspicious User Agents: {', '.join(ip_data.get('suspicious_agents', [])) or 'None detected'}
        """.strip()

        prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are a cybersecurity expert who explains technical concepts in simple, clear terms for non-technical people. You specialize in threat intelligence from sources like AbuseIPDB, VirusTotal, and Cisco Talos.
<|eot_id|>
<|start_header_id|>user<|end_header_id|>
Translate this technical information about a potential cybersecurity threat into a single, clear English sentence that a non-technical person can understand. Be concise and focus on the risk level.

Technical data:
{tech_info}

Explanation:<|eot_id|>
<|start_header_id|>assistant<|end_header_id|>"""

        return self.generate_with_llama(prompt)

    def detect_anomalies(self, log_summary):
        """Use AI to detect anomalous patterns in the log data"""
        prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are a SOC analyst with expertise in multiple threat intelligence sources (AbuseIPDB, VirusTotal, Cisco Talos). Analyze web server logs and identify anomalous patterns that could represent coordinated attacks or security threats.
<|eot_id|>
<|start_header_id|>user<|end_header_id|>
Analyze this web server log summary and identify any anomalous patterns that could represent coordinated attacks or security threats. Provide a brief analysis in clear, concise language.

Log summary:
{log_summary}

Analysis:<|eot_id|>
<|start_header_id|>assistant<|end_header_id|>"""

        return self.generate_with_llama(prompt, max_tokens=250)

    def generate_insights(self, enriched_data):
        """Generate AI insights for all high-risk IPs"""
        if not self.available:
            print("AI features disabled. Continuing without AI analysis.")
            return enriched_data

        print(f"Generating AI insights with {self.model}...")

        analyzed_count = 0
        for ip, data in enriched_data.items():
            if ip == 'overall_analysis':
                continue

            if data['risk_score'] > 40:  # Only analyze high-risk IPs
                ip_info = {
                    'ip': ip,
                    'abuse_confidence': data['cti']['abuseipdb'].get('confidence_score', 'N/A'),
                    'vt_malicious': data['cti']['virustotal'].get('malicious', 0),
                    'talos_web_reputation': data['cti']['cisco_talos'].get('web_reputation', 'N/A'),
                    'total_requests': data['activity']['total_requests'],
                    'error_4xx': data['activity']['error_4xx'],
                    'suspicious_agents': data['suspicious_user_agents']
                }

                print(f"  Analyzing IP {ip} (risk score: {data['risk_score']})...")
                data['ai_analysis'] = self.generate_threat_explanation(ip_info)
                analyzed_count += 1
                print(f"  AI analysis complete for IP {ip}")

        # Generate overall anomaly detection
        if analyzed_count > 0:
            log_summary = self._create_log_summary(enriched_data)
            print("Generating overall log analysis...")
            enriched_data['overall_analysis'] = self.detect_anomalies(log_summary)
        else:
            enriched_data['overall_analysis'] = "No high-risk IPs detected for AI analysis."

        print("AI analysis complete!")
        return enriched_data

    def _create_log_summary(self, enriched_data):
        """Create a summary of log activities for anomaly detection"""
        total_requests = sum(data['activity']['total_requests'] for ip, data in enriched_data.items() if ip != 'overall_analysis')
        total_errors = sum(data['activity']['error_4xx'] for ip, data in enriched_data.items() if ip != 'overall_analysis')
        unique_ips = len([ip for ip in enriched_data.keys() if ip != 'overall_analysis'])

        high_risk_ips = []
        for ip, data in enriched_data.items():
            if ip != 'overall_analysis' and data['risk_score'] > 50:
                high_risk_ips.append({
                    'ip': ip,
                    'score': data['risk_score'],
                    'requests': data['activity']['total_requests'],
                    'errors': data['activity']['error_4xx'],
                    'abuse_score': data['cti']['abuseipdb'].get('confidence_score', 'N/A'),
                    'vt_malicious': data['cti']['virustotal'].get('malicious', 0),
                    'talos_rep': data['cti']['cisco_talos'].get('web_reputation', 'N/A')
                })

        error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0

        summary = f"""
Total Log Analysis Summary:
- Total Requests: {total_requests:,}
- Total 4xx Errors: {total_errors:,}
- Error Rate: {error_rate:.2f}%
- Unique IP Addresses: {unique_ips:,}
- High-Risk IPs (score > 50): {len(high_risk_ips):,}
        """

        if high_risk_ips:
            summary += "\n\nHigh-Risk IP Details:"
            for ip_data in high_risk_ips:
                summary += f"\n- {ip_data['ip']}: Score {ip_data['score']}, "
                summary += f"Requests: {ip_data['requests']}, "
                summary += f"Errors: {ip_data['errors']}, "
                summary += f"AbuseIPDB: {ip_data['abuse_score']}%, "
                summary += f"VT Malicious: {ip_data['vt_malicious']}, "
                summary += f"Talos: {ip_data['talos_rep']}"

        return summary