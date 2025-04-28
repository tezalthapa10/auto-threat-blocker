import os
import requests
import sys
import re
import logging
import json
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("auto_block.log"),
        logging.StreamHandler()
    ]
)
# logging.getLogger("auto_blocker").setLevel(logging.DEBUG)
logger = logging.getLogger("auto_blocker")

# Elasticsearch configuration
ELK_URL = "http://localhost:9200/threat-logs-*/_search"
QUERY = {
    "query": {
        "query_string": {
            "query": "message:\"Failed password*\" AND message:sshd",
            "default_field": "message"
        }
    },
    "size": 100,  # Increase size to catch more failed attempts
    "sort": [
        {
            "@timestamp": {
                "order": "desc"
            }
        }
    ]
}

# Authentication credentials
USERNAME = "elastic"
PASSWORD = "hello12"

# IP regex pattern
# IP regex pattern
IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
# SSH failed login pattern - improved to catch more variations
SSH_FAIL_PATTERN = r'Failed password for(?: invalid user)? \S+ from (\d+\.\d+\.\d+\.\d+)'
# Pattern to exclude sudo log entries about grep commands
SUDO_GREP_PATTERN = r'sudo:\s+\S+\s*:\s*TTY=.*COMMAND=/usr/bin/grep.*Failed password'
def extract_ip_from_message(message):
    """Extract IP address from a log message containing 'Failed password'"""
    # First try to match the specific SSH pattern which is more reliable
    ssh_match = re.search(SSH_FAIL_PATTERN, message)
    if ssh_match:
        logger.debug(f"Found SSH failed login pattern match: {ssh_match.group(1)}")
        return ssh_match.group(1)
        
    # Fallback to general IP pattern matching
    logger.debug("No SSH pattern match, falling back to general IP pattern")
    ip_matches = re.findall(IP_PATTERN, message)
    
    if not ip_matches:
        logger.warning(f"Could not find IP address in message: {message}")
        return None
    
    # In SSH failed login messages, the IP is typically the last IP in the message
    ip = ip_matches[-1]
    
    # Basic validation - make sure it's not a local or private IP we don't want to block
    if ip.startswith(('127.', '192.168.', '10.', '169.254.')) or ip == '::1' or ip == 'localhost':
        logger.warning(f"Skipping local/private IP address: {ip}")
        return None
    
    # Additional validation to prevent blocking essential IPs
    dangerous_ips = ['0.0.0.0', '255.255.255.255']
    if ip in dangerous_ips:
        logger.warning(f"Refusing to block critical IP address: {ip}")
        return None
        
    return ip

def is_valid_ip(ip):
    """Additional validation to ensure IP is valid"""
    # Check if IP is in correct format with all octets between 0-255
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return False
        return all(0 <= int(octet) <= 255 for octet in octets)
    except (ValueError, AttributeError):
        return False

def block_ip(ip):
    """Block an IP address using iptables"""
    # Final validation before blocking
    if not is_valid_ip(ip):
        logger.error(f"Invalid IP format, refusing to block: {ip}")
        return
        
    # Extra check for localhost/private ranges
    if ip.startswith(('127.', '192.168.', '10.', '169.254.')) or ip == '::1':
        logger.error(f"Refusing to block local/private IP address: {ip}")
        return
        
    logger.info(f"Attempting to block IP: {ip}")
    
    # Check if IP is already blocked
    check_cmd = f"sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null"
    if os.system(check_cmd) == 0:
        logger.info(f"IP {ip} is already blocked")
        return
    
    # Block the IP
    block_cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    result = os.system(block_cmd)
    
    if result == 0:
        logger.info(f"Successfully blocked IP: {ip}")
    else:
        logger.error(f"Failed to block IP: {ip}")

def main():
    try:
        logger.info(f"Connecting to Elasticsearch at {ELK_URL}...")
        logger.info(f"Executing query for 'Failed password' patterns...")
        
        # Set to DEBUG to see detailed logs, or INFO for normal operation
        # logger.setLevel(logging.DEBUG)
        
        response = requests.get(ELK_URL, json=QUERY, auth=(USERNAME, PASSWORD))
        logger.debug(f"Response status code: {response.status_code}")
        
        response.raise_for_status()  # Raise an exception for 4XX/5XX responses
        
        data = response.json()
        
        if "hits" not in data or "hits" not in data["hits"]:
            logger.warning("No hits found in the response")
            return
        
        total_hits = data['hits']['total']['value'] if isinstance(data['hits']['total'], dict) else data['hits']['total']
        logger.info(f"Found {total_hits} total matching documents")
        logger.info(f"Processing {len(data['hits']['hits'])} documents")
        
        blocked_ips = set()  # Keep track of IPs we've already blocked
        
        for hit in data["hits"]["hits"]:
            logger.debug(f"Processing document from index: {hit['_index']}")
            
            # Check if the document contains a message field
            if "_source" in hit and "message" in hit["_source"]:
                log_message = hit["_source"]["message"]
                logger.debug(f"Processing message: {log_message[:100]}...")  # Log first 100 chars to avoid clutter
                
                # Skip sudo logs about grep commands for "Failed password"
                if re.search(SUDO_GREP_PATTERN, log_message):
                    logger.debug(f"Skipping sudo grep log entry: {log_message[:100]}...")
                    continue
                
                # Check for both patterns: "Failed password" and "Failed password for invalid user"
                if "Failed password" in log_message and "sshd" in log_message:
                    logger.debug(f"Found potential SSH failed login attempt")
                    ip = extract_ip_from_message(log_message)
                    
                    if ip and ip not in blocked_ips:
                        block_ip(ip)
                        blocked_ips.add(ip)
                else:
                    logger.debug("Log entry doesn't contain the expected pattern")
            else:
                logger.warning("Document doesn't contain a message field")
        
        if blocked_ips:
            logger.info(f"Blocked {len(blocked_ips)} unique IP addresses")
        else:
            logger.info("No new IP addresses blocked in this run")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to Elasticsearch: {e}")
        sys.exit(1)
    except KeyError as e:
        logger.error(f"Error parsing response data: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
