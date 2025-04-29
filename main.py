
import os
import sys
import argparse
import yaml
import time
import logging
import json
import signal
import threading
from datetime import datetime
from dotenv import load_dotenv

# Import components
from utils.config import load_config
from utils.logger import get_logger
from detection.ip_detector import IPDetector
from detection.file_detector import FileDetector
from action.ip_blocker import IPBlocker
from action.file_quarantine import FileQuarantine
from intelligence.virustotal import VirusTotalClient
from intelligence.abuseipdb import AbuseIPDBClient
from mailer.smtp_mailer import Mailer

# Configure main logger
logger = get_logger("main")
load_dotenv()

class AutoThreatBlocker:
    def __init__(self, config):
        self.config = config
        self.running = False
        self.mailer = Mailer()

        # Initialize components
        self._init_components()
    
    def _init_components(self):
        """Initialize all components"""
        try:
            # Initialize intelligence components
            if self.config.get('threat_intelligence', {}).get('virustotal', {}).get('enabled', False):
                self.virustotal = VirusTotalClient(self.config['threat_intelligence']['virustotal']['api_key'])
            else:
                self.virustotal = None

            # Initialize threat intelligence components
            if self.config.get('threat_intelligence', {}).get('abuseipdb', {}).get('enabled', False):
                self.abuseipdb = AbuseIPDBClient(self.config['threat_intelligence']['abuseipdb'])
            else:
                self.abuseipdb = None

            # Initialize detection components
            self.ip_detector = IPDetector(self.config.get('elasticsearch', {}))
            self.file_detector = FileDetector(self.config['monitoring']['file'])

            # Initialize action components
            self.ip_blocker = IPBlocker(self.config['actions']['firewall'])
            self.file_quarantine = FileQuarantine(self.config['actions']['quarantine'])

            # Log the current configuration for debugging purposes
            logger.debug(f"Config contents: {self.config}")
            logger.debug(f"Elasticsearch config: {self.config.get('storage', {}).get('elasticsearch', 'Elasticsearch not configured')}")
            logger.info("All components initialized successfully")
        
        except Exception as e:
            logger.error(f"Error initializing components: {e}")
            raise

    
    def start(self):
        """Start the Auto Threat Blocker"""
        try:
            logger.info("Starting Auto Threat Blocker")
            self.running = True
            
            # Start monitoring threads
            self.ip_monitor_thread = threading.Thread(target=self._ip_monitoring_thread)
            self.ip_monitor_thread.daemon = True
            self.ip_monitor_thread.start()
            
            self.file_monitor_thread = threading.Thread(target=self._file_monitoring_thread)
            self.file_monitor_thread.daemon = True
            self.file_monitor_thread.start()
            
            logger.info("Auto Threat Blocker started")
        except Exception as e:
            logger.error(f"Error starting Auto Threat Blocker: {e}")
            self.stop()
            raise
    
    def stop(self):
        """Stop the Auto Threat Blocker"""
        logger.info("Stopping Auto Threat Blocker")
        self.running = False
        
        # Wait for monitoring threads to stop
        if hasattr(self, 'ip_monitor_thread') and self.ip_monitor_thread.is_alive():
            self.ip_monitor_thread.join(timeout=1)
            
        if hasattr(self, 'file_monitor_thread') and self.file_monitor_thread.is_alive():
            self.file_monitor_thread.join(timeout=1)
        
        logger.info("Auto Threat Blocker stopped")
    
    def _ip_monitoring_thread(self):
        """IP monitoring thread"""
        interval = self.config.get('ip_monitoring', {}).get('interval', 60)
        # email details
        subject = "IP Threat detected "
        message = "Hello! Some Malicious file is detcted please review it."

        while self.running:
            try:
                logger.info("Running IP threat detection cycle")

                # Detect threats
                suspicious_ips = self.ip_detector.detect_threats()

                # Process each suspicious IP
                for ip in suspicious_ips:
                    if self.is_valid_ip(ip):    # <-- ✅ Check here first
                        self._process_suspicious_ip(ip)
                    else:
                        logger.info(f"Skipping IP (invalid/private/dangerous): {ip}")
                
                self.mailer.send_email(subject, message)

                # Sleep until next cycle
                logger.info(f"IP monitoring sleeping for {interval} seconds")
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)

            except Exception as e:
                logger.error(f"Error in IP monitoring thread: {e}")
                time.sleep(60)  # Sleep for a minute on error

    def is_valid_ip(self, ip):
        """Validate IP address"""
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return False

            if ip.startswith(('127.', '192.168.', '10.', '169.254.')) or ip == '::1':
                logger.warning(f"Skipping local/private IP address: {ip}")
                return False

            dangerous_ips = ['0.0.0.0', '255.255.255.255']
            if ip in dangerous_ips:
                logger.warning(f"Refusing to process critical IP address: {ip}")
                return False

            return all(0 <= int(octet) <= 255 for octet in octets)
        except (ValueError, AttributeError):
            return False

    
    def _file_monitoring_thread(self):
        """File monitoring thread"""
        interval = self.config.get('file_monitoring', {}).get('interval', 60)  

        # email details
        subject = "File Threat detected "
        message = "Hello! Some Malicious file is detcted please review it"
        
        while self.running:
            try:
                logger.info("Running file threat detection cycle")
                
                # Detect threats
                suspicious_files = self.file_detector.scan_files()
                
                # Process each suspicious file
                for file_info in suspicious_files:
                    self._process_suspicious_file(file_info)
                        

                self.mailer.send_email(subject, message)
                
                # Sleep until next cycle
                logger.info(f"File monitoring sleeping for {interval} seconds")
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in file monitoring thread: {e}")
                time.sleep(60)  # Sleep for a minute on error
    
    def _process_suspicious_ip(self, ip):
        """Process a suspicious IP address"""
        try:
            logger.info(f"*********************************Processing suspicious IP: {ip} *********************************")

            threat_data = None
            source = "Unknown"

            # Check with AbuseIPDB
            if self.abuseipdb:
                logger.info(f"Checking IP with AbuseIPDB: {ip}")
                threat_data = self.abuseipdb.check_ip(ip)

                if threat_data and threat_data.get('is_malicious', False):
                    logger.warning(f"AbuseIPDB confirmed malicious IP: {ip}")
                    source = f"AbuseIPDB: Score {threat_data.get('threat_score', 0)}"
                    self.ip_blocker.block_ip(ip, source)
                    logger.info(f"Blocked and stored IP {ip} confirmed by AbuseIPDB.")
                    return

            # Check with VirusTotal if not already confirmed
            if self.virustotal and not (threat_data and threat_data.get('is_malicious', False)):
                logger.info(f"Checking IP with VirusTotal: {ip}")
                vt_data = self.virustotal.scan_ip(ip)

                if vt_data:
                    threat_data = vt_data

                    if vt_data.get('is_malicious', False):
                        logger.warning(f"VirusTotal confirmed malicious IP: {ip}")
                        source = f"VirusTotal: Score {vt_data.get('threat_score', 0)}"
                        self.ip_blocker.block_ip(ip, source)
                        logger.info(f"Blocked and stored IP {ip} confirmed by VirusTotal.")
                        return

            # No intelligence confirmation
            if not threat_data:
                logger.info(f"No threat intelligence data for IP {ip}, blocking based on failed login attempts")
                default_threat_info = {
                    "reason": "Multiple failed login attempts",
                    "threat_score": 50,  # default score
                    "is_malicious": True
                }
                self.ip_blocker.block_ip(ip, "Multiple failed login attempts")
                logger.info(f"Blocked and stored IP {ip} based on failed login detection.")

        except Exception as e:
            logger.error(f"Error processing suspicious IP {ip}: {e}")

    
    def _process_suspicious_file(self, file_info):
        """Process a suspicious file"""
        try:
            file_path = file_info.get('path')
            file_hash = file_info.get('hash')
            
            logger.info(f"Processing suspicious file: {file_path}")
            
            # Check with VirusTotal
            if self.virustotal:
                logger.info(f"Checking file with VirusTotal: {file_path}")
                vt_data = self.virustotal.scan_file(file_path)
                
                if vt_data and vt_data.get('is_malicious', False):
                    logger.warning(f"VirusTotal confirmed malicious file: {file_path}")
                    self.file_quarantine.quarantine_file(
                        file_path, 
                        f"VirusTotal: Score {vt_data.get('threat_score', 0)}"
                    )
                    return
            
            # If no threat intelligence data or not confirmed malicious,
            # decide based on file characteristics or patterns
            logger.info(f"No conclusive threat intelligence data for file {file_path}")
            
            # If file was flagged as suspicious by basic checks, quarantine it with a notice
            self.file_quarantine.quarantine_file(
                file_path,
                "Flagged as suspicious by pattern matching"
            )
            
        except Exception as e:
            logger.error(f"Error processing suspicious file {file_info.get('path')}: {e}")

    def load_config(file_path):
        """Load configuration from YAML file"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The configuration file '{file_path}' was not found.")
    
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Auto Threat Blocker")
    parser.add_argument("--config", default="config.yml", help="Path to configuration file")
    args = parser.parse_args()

    # Load the configuration from the provided file
    config = load_config(args.config)
        
    # Assuming you use the config dictionary somewhere later in your app
    atb = AutoThreatBlocker(config)
    
   
    
    # Handle signals
    def signal_handler(sig, frame):
        logger.info("Received shutdown signal")
        atb.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the Auto Threat Blocker
    atb.start()
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        atb.stop()

if __name__ == "__main__":
    main()
