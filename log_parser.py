"""
Module for parsing web server access logs in multiple formats with robust error handling
"""

import json
import re
from collections import defaultdict

class LogParser:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        # Common log format regex pattern
        self.common_log_pattern = r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'

    def detect_format(self, line):
        """Detect the log format of a line"""
        line = line.strip()

        # Skip empty lines
        if not line:
            return 'empty'

        # Try JSON format first
        if line.startswith('{') and line.endswith('}'):
            try:
                data = json.loads(line)
                if 'remote_addr' in data or 'ip' in data:
                    return 'json'
            except json.JSONDecodeError:
                pass

        # Try tab-separated format with JSON
        if '\t' in line and line.count('\t') >= 2:
            parts = line.split('\t')
            if len(parts) >= 3 and parts[2].strip().startswith('{'):
                return 'tab_json'

        # Try common log format
        if re.match(self.common_log_pattern, line):
            return 'common'

        return 'unknown'

    def parse_json_format(self, line):
        """Parse JSON format logs"""
        try:
            log_entry = json.loads(line)
            ip = log_entry.get('remote_addr') or log_entry.get('ip') or log_entry.get('client_ip') or ''
            timestamp = log_entry.get('timestamp') or log_entry.get('time') or ''
            method = log_entry.get('method') or ''
            uri = log_entry.get('uri') or log_entry.get('request') or ''
            status_code = str(log_entry.get('status') or log_entry.get('status_code') or '')
            user_agent = log_entry.get('user_agent') or log_entry.get('agent') or ''

            return ip, timestamp, method, uri, status_code, user_agent
        except Exception as e:
            raise ValueError(f"JSON parsing error: {str(e)}")

    def parse_tab_json_format(self, line):
        """Parse tab-separated format with JSON object"""
        try:
            parts = line.split('\t')
            if len(parts) < 3:
                raise ValueError("Not enough tab-separated parts")

            # The JSON part is the third column
            json_part = parts[2].strip()
            log_entry = json.loads(json_part)

            ip = log_entry.get('remote_addr') or log_entry.get('ip') or ''
            timestamp = log_entry.get('timestamp') or ''
            method = log_entry.get('method') or ''
            uri = log_entry.get('uri') or log_entry.get('request') or ''
            status_code = str(log_entry.get('status') or log_entry.get('status_code') or '')
            user_agent = log_entry.get('user_agent') or log_entry.get('agent') or ''

            return ip, timestamp, method, uri, status_code, user_agent
        except Exception as e:
            raise ValueError(f"Tab-JSON parsing error: {str(e)}")

    def parse_common_format(self, line):
        """Parse common log format"""
        match = re.match(self.common_log_pattern, line)
        if not match:
            raise ValueError("Line doesn't match common log format")

        ip, ident, authuser, timestamp, request, status_code, size, referer, user_agent = match.groups()

        # Parse the request field to get method and URI
        method, uri = self._parse_request_field(request)

        return ip, timestamp, method, uri, status_code, user_agent

    def _parse_request_field(self, request):
        """Parse the HTTP request field to extract method and URI"""
        parts = request.split()
        if len(parts) >= 2:
            return parts[0], parts[1]
        return '', request

    def parse(self):
        ip_activities = defaultdict(lambda: {
            'total_requests': 0,
            'error_4xx': 0,
            'user_agents': set(),
            'requests': []
        })

        format_counts = {'json': 0, 'tab_json': 0, 'common': 0, 'unknown': 0, 'empty': 0}
        error_count = 0

        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, 1):
                    try:
                        # Skip empty lines
                        if not line.strip():
                            format_counts['empty'] += 1
                            continue

                        # Detect format
                        log_format = self.detect_format(line)
                        format_counts[log_format] += 1

                        if log_format == 'unknown':
                            if line_num <= 5:  # Only show first few for debugging
                         #       print(f"Warning: Unknown format on line {line_num}")
                                continue

                        # Parse based on format
                        if log_format == 'json':
                            ip, timestamp, method, uri, status_code, user_agent = self.parse_json_format(line)
                        elif log_format == 'tab_json':
                            ip, timestamp, method, uri, status_code, user_agent = self.parse_tab_json_format(line)
                        else:  # common
                            ip, timestamp, method, uri, status_code, user_agent = self.parse_common_format(line)

                        # Skip if essential fields are missing
                        if not ip:
                            continue

                        # Update IP activity
                        ip_activities[ip]['total_requests'] += 1
                        if status_code.startswith('4'):
                            ip_activities[ip]['error_4xx'] += 1
                        ip_activities[ip]['user_agents'].add(user_agent)
                        ip_activities[ip]['requests'].append({
                            'timestamp': timestamp,
                            'method': method,
                            'uri': uri,
                            'status_code': status_code,
                            'user_agent': user_agent
                        })

                    except Exception as e:
                        error_count += 1
                        if error_count <= 10:  # Only show first 10 errors
                            print(f"")
                        continue

            # Print format detection summary
            print(f"\nLog format analysis: {format_counts}\n")
            print(f"\nTotal lines processed: {line_num}\n")
            print(f"\nSuccessfully parsed {sum(len(ip_activities[ip]['requests']) for ip in ip_activities)} log entries\n")
            print(f"Found {len(ip_activities)} unique IP addresses\n")

        except FileNotFoundError:
            raise FileNotFoundError(f"Log file {self.log_file_path} not found")
        except UnicodeDecodeError:
            raise ValueError("File encoding issue. This might not be a text log file.")
        except Exception as e:
            raise ValueError(f"Error reading file: {str(e)}")

        return ip_activities