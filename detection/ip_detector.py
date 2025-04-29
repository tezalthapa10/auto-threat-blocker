import ipaddress
import os
import re
import logging
import requests
from datetime import datetime

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
            dangerous_ips = ['255.255.255.255']
            if ip == '255.255.255.255' or ip == '0.0.0.0':
                logger.warning(f"Refusing to process critical IP address: {ip}")
                return False

            return True  # Passed all checks

        except ValueError:
            logger.error(f"Invalid IP address format detected: {ip}")
            return False
    
    def detect_threats(self):
        """Detect IP threats from logs"""
        try:
            logger.info(f"Connecting to Elasticsearch at {self.elk_url}...")
            logger.info(f"Executing query for 'Failed password' patterns...")
            
            response = requests.get(
                self.elk_url, 
                json=self.QUERY, 
                auth=(self.elk_username, self.elk_password)
            )
            
            logger.debug(f"Response status code: {response.status_code}")
            response.raise_for_status()
            
            data = response.json()
            detected_ips = set()
            
            if "hits" not in data or "hits" not in data["hits"]:
                logger.warning("No hits found in the response")
                return detected_ips
            
            total_hits = data['hits']['total']['value'] if isinstance(data['hits']['total'], dict) else data['hits']['total']
            logger.info(f"Found {total_hits} total matching documents")
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
                            logger.info(f"Detected potential malicious IP: {ip}")
                            detected_ips.add(ip)
                            # my custom suspicious ip
                            detected_ips.add("71.13.237.17")
                            # self.ip_blocker_service.block_ip(ip)


                else:
                    logger.warning("Document doesn't contain a message field")
            
            logger.info(f"Detected {len(detected_ips)} unique suspicious IP addresses")
            return detected_ips
            
        except Exception as e:
            logger.error(f"Error detecting threats: {e}", exc_info=True)
            return set()
