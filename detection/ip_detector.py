import ipaddress
import os
import re
import logging
import requests
import json
from datetime import datetime
from utils.elasticsearch_logger import ElasticsearchLogger

# Get logger from utils
from utils.logger import get_logger

# Get Ip Blocker class
from action.ip_blocker import IPBlocker

logger = get_logger("ip_detector")


class IPDetector:

    def __init__(self, config):
        self.elk_url = config.get('url')
        if not self.elk_url:
            raise ValueError("Elasticsearch 'url' is missing in the configuration")
        self.elk_url = self.elk_url + "/threat-logs-*/_search"
        self.config = config
        self.elk_username = config.get('username')
        self.elk_password = config.get('password')
        self.ip_blocker_service = IPBlocker(config)
        
        # Regex patterns
        self.IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.SSH_FAIL_PATTERN = r'Failed password for(?: invalid user)? \S+ from (\d+\.\d+\.\d+\.\d+)'
        self.SUDO_GREP_PATTERN = r'sudo:\s+\S+\s*:\s*TTY=.*COMMAND=/usr/bin/grep.*Failed password'
        
        # Predefined malicious IPs (similar to domain blocking approach)
        self.malicious_ips = {
            "71.13.237.17": {"threat_score": 95, "category": "brute_force", "country": "US"},
            "185.220.101.32": {"threat_score": 90, "category": "tor_exit", "country": "DE"},
            "198.98.62.85": {"threat_score": 88, "category": "scanner", "country": "US"},
            "94.102.61.46": {"threat_score": 92, "category": "malware_c2", "country": "NL"},
            "103.224.182.251": {"threat_score": 89, "category": "brute_force", "country": "IN"}
        }
        
        # Query for failed SSH login attempts
        self.QUERY = {
            "query": {
                "query_string": {
                    "query": "message:\"Failed password*\" AND message:sshd",
                    "default_field": "message"
                }
            },
            "size": 100,
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }
    
    def extract_ip_from_message(self, message):
        """Extract IP address from a log message containing 'Failed password'"""
        # First try to match the specific SSH pattern which is more reliable
        ssh_match = re.search(self.SSH_FAIL_PATTERN, message)
        if ssh_match:
            logger.debug(f"Found SSH failed login pattern match: {ssh_match.group(1)}")
            return ssh_match.group(1)
            
        # Fallback to general IP pattern matching
        logger.debug("No SSH pattern match, falling back to general IP pattern")
        ip_matches = re.findall(self.IP_PATTERN, message)
        
        if not ip_matches:
            logger.warning(f"Could not find IP address in message: {message}")
            return None
        
        # In SSH failed login messages, the IP is typically the last IP in the message
        ip = ip_matches[-1]
        
        # Validate IP
        if not self.is_valid_ip(ip):
            return None
            
        return ip
    
    def is_valid_ip(self, ip):
        """Validate IP address"""
        try:
            # Validate format first
            ip_obj = ipaddress.ip_address(ip)

            # Check if IP is private, loopback, link-local, or unspecified
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified:
                logger.warning(f"Skipping local/private/special IP address: {ip}")
                return False

            # Check manually dangerous IPs
            dangerous_ips = ['255.255.255.255', '0.0.0.0']
            if ip in dangerous_ips:
                logger.warning(f"Refusing to process critical IP address: {ip}")
                return False

            return True  # Passed all checks

        except ValueError:
            logger.error(f"Invalid IP address format detected: {ip}")
            return False
    
    def get_ip_info(self, ip):
        """Get threat information for an IP (similar to domain blocking)"""
        return self.malicious_ips.get(ip, {
            "threat_score": 60,  # Default threat score for detected IPs
            "category": "failed_login",
            "country": "unknown"
        })
    
    def detect_threats(self):
        """Detect IP threats from logs"""
        try:
            logger.info(f"Scanning for malicious IP addresses...")
            
            # Start with predefined malicious IPs (for demo consistency)
            detected_ips = set()
            
            # Add predefined malicious IPs for demo
            for ip in self.malicious_ips.keys():
                detected_ips.add(ip)
                logger.info(f"Found predefined malicious IP: {ip}")
            
            # Try to get from Elasticsearch if available
            try:
                logger.info(f"Connecting to Elasticsearch at {self.elk_url}...")
                logger.info(f"Executing query for 'Failed password' patterns...")
                
                response = requests.get(
                    self.elk_url, 
                    json=self.QUERY, 
                    auth=(self.elk_username, self.elk_password) if self.elk_username else None,
                    timeout=10
                )
                
                logger.debug(f"Response status code: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if "hits" in data and "hits" in data["hits"]:
                        total_hits = data['hits']['total']['value'] if isinstance(data['hits']['total'], dict) else data['hits']['total']
                        logger.info(f"Found {total_hits} total matching documents from Elasticsearch")
                        logger.info(f"Processing {len(data['hits']['hits'])} documents")
                        
                        for hit in data["hits"]["hits"]:
                            logger.debug(f"Processing document from index: {hit['_index']}")
                            
                            if "_source" in hit and "message" in hit["_source"]:
                                log_message = hit["_source"]["message"]
                                logger.debug(f"Processing message: {log_message[:100]}...")
                                
                                # Skip sudo logs about grep commands for "Failed password"
                                if re.search(self.SUDO_GREP_PATTERN, log_message):
                                    logger.debug(f"Skipping sudo grep log entry")
                                    continue
                                
                                # Check for SSH failed login attempts
                                if "Failed password" in log_message and "sshd" in log_message:
                                    logger.debug(f"Found potential SSH failed login attempt")
                                    ip = self.extract_ip_from_message(log_message)
                                    
                                    if ip:
                                        logger.info(f"Detected potential malicious IP from logs: {ip}")
                                        detected_ips.add(ip)
                            else:
                                logger.warning("Document doesn't contain a message field")
                    else:
                        logger.warning("No hits found in Elasticsearch response")
                else:
                    logger.warning(f"Elasticsearch query failed with status: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.warning(f"Could not connect to Elasticsearch, using predefined IPs: {e}")
            except Exception as e:
                logger.warning(f"Error querying Elasticsearch, using predefined IPs: {e}")
            
            logger.info(f"Detected {len(detected_ips)} unique suspicious IP addresses")
            return detected_ips
            
        except Exception as e:
            logger.error(f"Error detecting IP threats: {e}", exc_info=True)
            return set()

    def should_block_ip(self, ip, threat_info=None):
        """Determine if an IP should be blocked based on threat score"""
        if not threat_info:
            threat_info = self.get_ip_info(ip)
        
        threat_score = threat_info.get('threat_score', 50)
        return threat_score >= 80  # Block if threat score is 80 or higher

    def log_ip_detection(self, ip, threat_info, action_taken):
        """Log IP detection event in structured format for Elasticsearch"""
        log_data = {
            "event_type": "ip_detection",
            "action": action_taken,
            "ip": ip,
            "threat_score": threat_info.get('threat_score', 50),
            "category": threat_info.get('category', 'unknown'),
            "country": threat_info.get('country', 'unknown'),
            "timestamp": datetime.now().isoformat(),
            "is_malicious": threat_info.get('threat_score', 50) >= 80,
            "source": "atb_ip_detector"
        }
        logger.info(json.dumps(log_data))
        return log_data