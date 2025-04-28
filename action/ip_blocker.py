import os
import logging
import json
from datetime import datetime

# Get logger from utils
from utils.logger import get_logger
logger = get_logger("ip_blocker")

class IPBlocker:
    def __init__(self, config):
        self.config = config
        self.blocked_ips_file = config.get('blocked_ips_file', '/var/tmp/blocked_ips.json')
        
        # Load previously blocked IPs
        self.blocked_ips = self._load_blocked_ips()
    
    def block_ip(self, ip, reason="Suspicious activity"):
        """Block an IP address using iptables"""
        # Check if IP is already blocked
        if ip in self.blocked_ips:
            logger.info(f"IP {ip} is already blocked")
            return False
            
        logger.info(f"Attempting to block IP: {ip}")
        
        # Check if IP is already blocked in iptables
        check_cmd = f"sudo iptables -C INPUT -s {ip} -j DROP 2>/dev/null"
        if os.system(check_cmd) == 0:
            logger.info(f"IP {ip} is already blocked in iptables")
            self._add_blocked_ip(ip, reason)
            return True
        
        # Block the IP
        block_cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
        result = os.system(block_cmd)
        
        if result == 0:
            logger.info(f"Successfully blocked IP: {ip}")
            self._add_blocked_ip(ip, reason)
            return True
        else:
            logger.error(f"Failed to block IP: {ip}")
            return False
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        if ip not in self.blocked_ips:
            logger.info(f"IP {ip} is not blocked")
            return False
            
        logger.info(f"Attempting to unblock IP: {ip}")
        
        # Remove from iptables
        unblock_cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
        result = os.system(unblock_cmd)
        
        if result == 0:
            logger.info(f"Successfully unblocked IP: {ip}")
            self._remove_blocked_ip(ip)
            return True
        else:
            logger.error(f"Failed to unblock IP: {ip}")
            return False
    
    def get_blocked_ips(self):
        """Get list of blocked IPs"""
        return self.blocked_ips
    
    def _add_blocked_ip(self, ip, reason):
        """Add IP to blocked IPs list"""
        self.blocked_ips[ip] = {
            "reason": reason,
            "blocked_at": datetime.now().isoformat(),
            "blocked_by": "auto_blocker"
        }
        self._save_blocked_ips()
        
        # Log in structured format for better Elasticsearch indexing
        log_data = {
            "action": "block",
            "ip": ip,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "is_malicious": True,
            "event_type": "ip_block"
        }
        logger.info(json.dumps(log_data))
    
    def _remove_blocked_ip(self, ip):
        """Remove IP from blocked IPs list"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self._save_blocked_ips()
            
            # Log in structured format
            log_data = {
                "action": "unblock",
                "ip": ip,
                "timestamp": datetime.now().isoformat(),
                "event_type": "ip_unblock"
            }
            logger.info(json.dumps(log_data))
    
    def _load_blocked_ips(self):
        """Load blocked IPs from file"""
        try:
            if os.path.exists(self.blocked_ips_file):
                with open(self.blocked_ips_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading blocked IPs: {e}")
            return {}
    
    def _save_blocked_ips(self):
        """Save blocked IPs to file"""
        try:
            with open(self.blocked_ips_file, 'w') as f:
                json.dump(self.blocked_ips, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving blocked IPs: {e}")
