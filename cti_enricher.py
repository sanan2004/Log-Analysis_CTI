"""
Module for enriching IP data with Cyber Threat Intelligence using APIs
"""

import requests
import time
import json
import random
import re
from bs4 import BeautifulSoup


class CTIEnricher:
    def __init__(self, virustotal_api_key=None, abuseipdb_api_key=None):
        # Rotating user agents to avoid blocking
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]

        # Add your API keys directly here
        self.virustotal_api_key = virustotal_api_key or ""
        self.abuseipdb_api_key = abuseipdb_api_key or ""

        self.request_delay = 3
        self.talos_failures = 0
        self.max_talos_failures = 3

    def get_random_headers(self):
        """Get random headers to avoid blocking"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }

    def check_abuseipdb_api(self, ip):
        """Check IP reputation on AbuseIPDB using API"""
        if not self.abuseipdb_api_key or self.abuseipdb_api_key == "your_abuseipdb_api_key_here":
            return {'source': 'AbuseIPDB', 'error': 'API key not configured', 'confidence_score': 0}

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_api_key
            }

            response = requests.get(url, headers=headers, params=querystring, timeout=15)

            if response.status_code == 429:
                print(f"  AbuseIPDB rate limit exceeded. Waiting 10 seconds...")
                time.sleep(10)
                return {'source': 'AbuseIPDB', 'error': 'Rate limit exceeded', 'confidence_score': 0}

            response.raise_for_status()
            data = response.json()

            result = data.get('data', {})
            return {
                'source': 'AbuseIPDB',
                'confidence_score': result.get('abuseConfidenceScore', 0),
                'total_reports': result.get('totalReports', 0),
                'country': result.get('countryCode', 'N/A'),
                'isp': result.get('isp', 'N/A'),
                'domain': result.get('domain', 'N/A'),
                'last_reported': result.get('lastReportedAt', 'N/A'),
                'is_public': result.get('isPublic', 'N/A'),
                'is_whitelisted': result.get('isWhitelisted', 'N/A')
            }

        except requests.exceptions.RequestException as e:
            print(f"  Error querying AbuseIPDB API: {str(e)}")
            return {'source': 'AbuseIPDB', 'error': f'API request failed', 'confidence_score': 0}
        except Exception as e:
            print(f"  Error processing AbuseIPDB response: {str(e)}")
            return {'source': 'AbuseIPDB', 'error': 'Processing error', 'confidence_score': 0}

    def check_abuseipdb_web(self, ip):
        """Fallback: Check IP reputation on AbuseIPDB via web scraping"""
        try:
            url = f"https://www.abuseipdb.com/check/{ip}"
            response = requests.get(url, headers=self.get_random_headers(), timeout=15)

            if response.status_code == 403:
                return {'source': 'AbuseIPDB', 'error': 'Access forbidden', 'confidence_score': 0}
            if response.status_code == 429:
                return {'source': 'AbuseIPDB', 'error': 'Rate limit exceeded', 'confidence_score': 0}

            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract data from AbuseIPDB webpage
            confidence_score = 0
            total_reports = 0
            country = "N/A"

            # Try to find confidence score
            score_elem = soup.find('div', class_='progress-bar')
            if score_elem and 'aria-valuenow' in score_elem.attrs:
                try:
                    confidence_score = int(score_elem['aria-valuenow'])
                except (ValueError, TypeError):
                    confidence_score = 0

            # Try to find reports count
            reports_elem = soup.find('td', string=lambda x: x and 'report' in x.lower())
            if reports_elem:
                try:
                    reports_text = reports_elem.find_next('td').text.strip()
                    total_reports = int(''.join(filter(str.isdigit, reports_text)) or 0)
                except (ValueError, TypeError):
                    total_reports = 0

            # Try to find country
            country_elem = soup.find('a', href=lambda x: x and '/country/' in x)
            if country_elem:
                country = country_elem.text.strip()

            return {
                'source': 'AbuseIPDB (Web)',
                'confidence_score': confidence_score,
                'total_reports': total_reports,
                'country': country
            }

        except Exception as e:
            print(f"  Error querying AbuseIPDB web: {str(e)}")
            return {'source': 'AbuseIPDB', 'error': 'Web scraping failed', 'confidence_score': 0}

    def check_virustotal(self, ip):
        """Check IP reputation on VirusTotal"""
        if not self.virustotal_api_key:
            return {'source': 'VirusTotal', 'error': 'API key not configured', 'malicious': 0, 'suspicious': 0}

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {
                'x-apikey': self.virustotal_api_key,
                'User-Agent': random.choice(self.user_agents)
            }

            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code == 429:
                print(f"  VirusTotal rate limit exceeded. Waiting 60 seconds...")
                time.sleep(60)
                return {'source': 'VirusTotal', 'error': 'Rate limit exceeded', 'malicious': 0, 'suspicious': 0}

            response.raise_for_status()
            data = response.json()

            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            reputation = attributes.get('reputation', 0)

            return {
                'source': 'VirusTotal',
                'harmless': stats.get('harmless', 0),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': reputation,
                'as_owner': attributes.get('as_owner', 'N/A'),
                'country': attributes.get('country', 'N/A'),
                'last_analysis_results': stats
            }

        except requests.exceptions.RequestException as e:
            print(f"  Error querying VirusTotal: {str(e)}")
            return {'source': 'VirusTotal', 'error': 'API request failed', 'malicious': 0, 'suspicious': 0}
        except Exception as e:
            print(f"  Error processing VirusTotal response: {str(e)}")
            return {'source': 'VirusTotal', 'error': 'Processing error', 'malicious': 0, 'suspicious': 0}

    def check_cisco_talos(self, ip):
        """Check IP reputation on Cisco Talos Intelligence with multiple approaches"""
        # If we've had too many failures, skip Talos to save time
        if self.talos_failures >= self.max_talos_failures:
            return self._get_talos_fallback_data(ip, "Disabled due to repeated failures")

        try:
            # Try multiple approaches to get Talos data
            approaches = [
                self._check_talos_direct,
                self._check_talos_via_archive,
                self._check_talos_via_search
            ]

            for approach in approaches:
                result = approach(ip)
                if result and not result.get('error'):
                    self.talos_failures = 0  # Reset on success
                    return result
                time.sleep(1)  # Brief delay between approaches

            # All approaches failed
            self.talos_failures += 1
            return self._get_talos_fallback_data(ip, "All access methods failed")

        except Exception as e:
            self.talos_failures += 1
            return self._get_talos_fallback_data(ip, f"Exception: {str(e)}")

    def _check_talos_direct(self, ip):
        """Direct approach to check Talos"""
        try:
            url = f"https://talosintelligence.com/reputation_center/lookup?search={ip}"
            headers = self.get_random_headers()
            headers.update({
                'Referer': 'https://talosintelligence.com/',
                'Origin': 'https://talosintelligence.com',
            })

            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code != 200:
                return None

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract information using multiple strategies
            data = self._parse_talos_page(soup, ip)
            if data:
                data['url'] = url
                data['source'] = 'Cisco Talos (Direct)'
                return data

        except:
            pass

        return None

    def _check_talos_via_archive(self, ip):
        """Check if Talos data is available via archive services"""
        try:
            # Try Wayback Machine or other archives
            archive_url = f"https://web.archive.org/web/20230000000000*/https://talosintelligence.com/reputation_center/lookup?search={ip}"
            headers = self.get_random_headers()

            response = requests.get(archive_url, headers=headers, timeout=10)
            if response.status_code == 200:
                # Check if archive has the page
                if 'available' in response.text.lower():
                    return {
                        'source': 'Cisco Talos (Archive)',
                        'web_reputation': 'Check Archive',
                        'email_reputation': 'N/A',
                        'owner': 'N/A',
                        'country': 'N/A',
                        'url': archive_url,
                        'note': 'Available via web archive'
                    }

        except:
            pass

        return None

    def _check_talos_via_search(self, ip):
        """Try to find Talos data via search engines"""
        try:
            # Try Google search for Talos results
            search_url = f"https://www.google.com/search?q=site:talosintelligence.com+{ip}"
            headers = self.get_random_headers()

            response = requests.get(search_url, headers=headers, timeout=10)
            if response.status_code == 200:
                if 'talosintelligence.com' in response.text:
                    return {
                        'source': 'Cisco Talos (Search)',
                        'web_reputation': 'Found in search',
                        'email_reputation': 'N/A',
                        'owner': 'N/A',
                        'country': 'N/A',
                        'url': f"https://talosintelligence.com/reputation_center/lookup?search={ip}",
                        'note': 'IP mentioned in Talos, check manually'
                    }

        except:
            pass

        return None

    def _parse_talos_page(self, soup, ip):
        """Parse Talos intelligence page with multiple extraction methods"""
        result = {
            'web_reputation': 'N/A',
            'email_reputation': 'N/A',
            'owner': 'N/A',
            'country': 'N/A'
        }

        # Method 1: Look for reputation in meta tags or specific elements
        reputation_selectors = [
            'meta[property="og:title"]',
            'meta[name="description"]',
            '.reputation',
            '.score',
            '.rating',
            '[class*="reputation"]',
            '[class*="score"]',
            'h1', 'h2', 'h3'
        ]

        for selector in reputation_selectors:
            elements = soup.select(selector)
            for element in elements:
                content = element.get('content', '') or element.text
                if ip in content and ('reputation' in content.lower() or 'score' in content.lower()):
                    result['web_reputation'] = content.strip()
                    break

        # Method 2: Look for organization/owner information
        owner_selectors = [
            '[class*="organization"]',
            '[class*="owner"]',
            '[class*="company"]',
            '[class*="isp"]',
            '.org-info',
            '.owner-info'
        ]

        for selector in owner_selectors:
            elements = soup.select(selector)
            for element in elements:
                text = element.text.strip()
                if text and len(text) < 100:  # Reasonable length for owner info
                    result['owner'] = text
                    break

        # Method 3: Look for country information
        country_selectors = [
            '[class*="country"]',
            '[class*="geo"]',
            '[class*="location"]',
            '.country-info',
            '.geo-info'
        ]

        for selector in country_selectors:
            elements = soup.select(selector)
            for element in elements:
                text = element.text.strip()
                if text and len(text) < 50:  # Reasonable length for country info
                    result['country'] = text
                    break

        # Method 4: Extract from page text using regex patterns
        page_text = soup.get_text()

        # Look for reputation patterns
        rep_patterns = [
            r'reputation[:\\s]+([\\w\\s]+)',
            r'score[:\\s]+([\\w\\s]+)',
            r'rating[:\\s]+([\\w\\s]+)',
            r'([\\w\\s]+)reputation',
            r'([\\w\\s]+)score'
        ]

        for pattern in rep_patterns:
            match = re.search(pattern, page_text, re.IGNORECASE)
            if match and match.group(1).strip():
                result['web_reputation'] = match.group(1).strip()
                break

        # Look for owner patterns
        owner_patterns = [
            r'organization[:\\s]+([\\w\\s\\.]+)',
            r'owner[:\\s]+([\\w\\s\\.]+)',
            r'isp[:\\s]+([\\w\\s\\.]+)',
            r'provider[:\\s]+([\\w\\s\\.]+)'
        ]

        for pattern in owner_patterns:
            match = re.search(pattern, page_text, re.IGNORECASE)
            if match and match.group(1).strip():
                result['owner'] = match.group(1).strip()
                break

        # Look for country patterns
        country_patterns = [
            r'country[:\\s]+([\\w\\s]+)',
            r'location[:\\s]+([\\w\\s]+)',
            r'geo[:\\s]+([\\w\\s]+)'
        ]

        for pattern in country_patterns:
            match = re.search(pattern, page_text, re.IGNORECASE)
            if match and match.group(1).strip():
                result['country'] = match.group(1).strip()
                break

        return result

    def _get_talos_fallback_data(self, ip, reason):
        """Provide meaningful fallback data when Cisco Talos is unavailable"""
        # Create a more informative fallback message
        return {
            'source': 'Cisco Talos',
            'web_reputation': 'Manual Check Required',
            'email_reputation': 'N/A',
            'owner': 'N/A',
            'country': 'N/A',
            'url': f"https://talosintelligence.com/reputation_center/lookup?search={ip}",
            'note': f'Automated access blocked. {reason}. Visit URL manually for complete analysis.',
            'manual_check_url': f"https://talosintelligence.com/reputation_center/lookup?search={ip}",
            'recommendation': 'Visit the Talos URL above to manually check this IP reputation'
        }

    def check_suspicious_user_agents(self, user_agents):
        """Check for known malicious user agents"""
        suspicious_patterns = [
            'sqlmap', 'nmap', 'hydra', 'nikto', 'metasploit',
            'wget', 'curl', 'dirbuster', 'gobuster', 'ffuf',
            'burpsuite', 'acunetix', 'nessus', 'openvas', 'zap',
            'havij', 'sqlninja', 'w3af', 'skipfish', 'arachni'
        ]

        suspicious = []
        for agent in user_agents:
            agent_lower = agent.lower()
            for pattern in suspicious_patterns:
                if pattern in agent_lower:
                    suspicious.append(agent)
                    break

        return suspicious

    def calculate_risk_score(self, activity_data, abuseipdb_data, virustotal_data, cisco_talos_data, suspicious_agents):
        """Calculate a comprehensive risk score based on various factors"""
        risk_score = 0

        # Activity-based scoring
        if activity_data['total_requests'] > 0:
            error_rate = activity_data['error_4xx'] / activity_data['total_requests']
            if error_rate > 0.7:  # Very high error rate
                risk_score += 40
            elif error_rate > 0.5:  # High error rate
                risk_score += 25
            elif error_rate > 0.3:  # Moderate error rate
                risk_score += 15

        # High volume of requests
        if activity_data['total_requests'] > 1000:
            risk_score += 20
        elif activity_data['total_requests'] > 100:
            risk_score += 10

        # AbuseIPDB scoring - with safe access
        confidence_score = abuseipdb_data.get('confidence_score', 0)
        if confidence_score not in ['N/A', 0, '0']:
            try:
                confidence = int(confidence_score)
                risk_score += min(confidence, 100) * 0.4  # 40% weight
            except (ValueError, TypeError):
                pass

        total_reports = abuseipdb_data.get('total_reports', 0)
        if total_reports not in ['N/A', 0, '0']:
            try:
                reports = int(total_reports)
                risk_score += min(reports * 2, 30)  # Cap at 30
            except (ValueError, TypeError):
                pass

        # VirusTotal scoring - with safe access
        malicious = virustotal_data.get('malicious', 0)
        if malicious > 0:
            risk_score += min(malicious * 8, 50)

        suspicious = virustotal_data.get('suspicious', 0)
        if suspicious > 0:
            risk_score += min(suspicious * 4, 20)

        # Negative reputation score
        reputation = virustotal_data.get('reputation', 0)
        if reputation < 0:
            risk_score += abs(reputation) / 2

        # Cisco Talos scoring - only if we have valid data
        if not cisco_talos_data.get('error'):
            web_reputation = cisco_talos_data.get('web_reputation', 'N/A')
            if web_reputation != 'N/A' and web_reputation != 'Unknown (Blocked)':
                web_rep = str(web_reputation).lower()
                if any(word in web_rep for word in ['poor', 'bad', 'malicious', 'block']):
                    risk_score += 30
                elif any(word in web_rep for word in ['suspicious', 'questionable', 'risk']):
                    risk_score += 20
                elif any(word in web_rep for word in ['good', 'excellent', 'trusted', 'clean']):
                    risk_score -= 15

        # Suspicious user agents
        if suspicious_agents:
            risk_score += len(suspicious_agents) * 15

        # Multiple user agents from same IP
        if len(activity_data['user_agents']) > 3:
            risk_score += 10

        return min(max(int(risk_score), 0), 100)  # Cap between 0-100 and convert to integer

    def enrich_ips(self, ip_activities):
        """Enrich IP data with CTI information from available sources"""
        enriched_data = {}

        print(f"Enriching {len(ip_activities)} IP addresses with CTI data...")
        print(f"Using VirusTotal API key: {self.virustotal_api_key[:10]}...")

        for i, (ip, data) in enumerate(ip_activities.items(), 1):
            print(f"  [{i}/{len(ip_activities)}] Enriching IP: {ip}")

            # Get CTI data from available sources
            abuseipdb_data = self.check_abuseipdb_api(ip)

            # Fallback to web scraping if API fails
            if abuseipdb_data.get('error'):
                abuseipdb_data = self.check_abuseipdb_web(ip)

            virustotal_data = self.check_virustotal(ip)

            # Get Cisco Talos data
            cisco_talos_data = self.check_cisco_talos(ip)

            # Check for suspicious user agents
            suspicious_agents = self.check_suspicious_user_agents(data['user_agents'])

            enriched_data[ip] = {
                'activity': data,
                'cti': {
                    'abuseipdb': abuseipdb_data,
                    'virustotal': virustotal_data,
                    'cisco_talos': cisco_talos_data
                },
                'suspicious_user_agents': suspicious_agents,
                'risk_score': self.calculate_risk_score(data, abuseipdb_data, virustotal_data, cisco_talos_data,
                                                        suspicious_agents)
            }

            # Be polite with delays
            time.sleep(self.request_delay)

        return enriched_data