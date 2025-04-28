
import os
import requests
import logging
import json
from datetime import datetime

# Get logger
from utils.logger import get_logger
logger = get_logger("abuseipdb")

class AbuseIPDBClient:
    """Client for interacting with the AbuseIPDB API"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, config):
        """
        Initialize AbuseIPDB client
        
        Args:
            config (dict): AbuseIPDB configuration from config
        """
        self.config = config
        self.api_key = config.get('api_key')
        
        if not self.api_key:
            logger.error("AbuseIPDB API key not found in configuration")
            raise ValueError("AbuseIPDB API key not found")
        
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        self.confidence_score_min = config.get('confidence_score_min', 80)
    
    def check_ip(self, ip_address):
        """
        Check an IP address with AbuseIPDB
        
        Args:
            ip_address (str): IP address to check
            
        Returns:
            dict: Processed results with threat information
        """
        try:
            url = f"{self.BASE_URL}/check"
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                return self._process_check_results(response.json())
            else:
                logger.error(f"Failed to check IP with AbuseIPDB: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error checking IP with AbuseIPDB: {e}")
            return None
    
    def report_ip(self, ip_address, categories, comment=""):
        """
        Report an abusive IP address to AbuseIPDB
        
        Args:
            ip_address (str): IP address to report
            categories (list): List of category IDs (see AbuseIPDB API docs)
            comment (str, optional): Comment to include with the report
            
        Returns:
            bool: True if report was successful, False otherwise
        """
        try:
            url = f"{self.BASE_URL}/report"
            
            params = {
                'ip': ip_address,
                'categories': ','.join(map(str, categories)),
                'comment': comment
            }
            
            response = requests.post(url, headers=self.headers, params=params)
            
            if response.status_code == 200:
                logger.info(f"Successfully reported IP to AbuseIPDB: {ip_address}")
                return True
            else:
                logger.error(f"Failed to report IP to AbuseIPDB: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error reporting IP to AbuseIPDB: {e}")
            return False
    
    def _process_check_results(self, check_results):
        """
        Process check results from AbuseIPDB
        
        Args:
            check_results (dict): Raw check results from AbuseIPDB
            
        Returns:
            dict: Processed check results
        """
        try:
            # Extract the relevant information from the check results
            data = check_results.get('data', {})
            
            if not data:
                logger.error("No data found in check results")
                return None
            
            # Get confidence score
            confidence_score = data.get('abuseConfidenceScore', 0)
            
            # Create result object
            result = {
                'ip': data.get('ipAddress', ''),
                'threat_score': confidence_score,
                'is_malicious': confidence_score >= self.confidence_score_min,
                'country': data.get('countryCode', 'unknown'),
                'isp': data.get('isp', 'unknown'),
                'domain': data.get('domain', ''),
                'total_reports': data.get('totalReports', 0),
                'num_distinct_users': data.get('numDistinctUsers', 0),
                'last_reported_at': data.get('lastReportedAt', ''),
                'categories': data.get('reports', []),
                'source': 'abuseipdb'
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing check results: {e}")
            return None
