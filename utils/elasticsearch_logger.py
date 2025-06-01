
import requests
import json
import logging
from datetime import datetime
from utils.logger import get_logger

logger = get_logger("elasticsearch_logger")

class ElasticsearchLogger:
    def __init__(self, config):
        self.es_url = config.get('url', 'http://localhost:9200')
        self.username = config.get('username', 'elastic')
        self.password = config.get('password', 'hello12')
        self.index_prefix = 'atb-live'
        
    def send_to_elasticsearch(self, threat_data):
        """Send threat data directly to Elasticsearch"""
        try:
            # Create index name with current date
            index_name = f"{self.index_prefix}-{datetime.now().strftime('%Y.%m.%d')}"
            url = f"{self.es_url}/{index_name}/_doc"
            
            # Add current timestamp if not present
            if '@timestamp' not in threat_data:
                threat_data['@timestamp'] = datetime.now().isoformat()
            
            # Send to Elasticsearch
            response = requests.post(
                url,
                auth=(self.username, self.password),
                json=threat_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Successfully sent threat data to Elasticsearch: {threat_data.get('ip', 'unknown')}")
                return True
            else:
                logger.error(f"Failed to send to Elasticsearch: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending to Elasticsearch: {e}")
            return False
    
    def create_index_template(self):
        """Create index template for proper field mapping"""
        try:
            template = {
                "index_patterns": [f"{self.index_prefix}-*"],
                "template": {
                    "mappings": {
                        "properties": {
                            "@timestamp": {"type": "date"},
                            "event_type": {"type": "keyword"},
                            "action": {"type": "keyword"},
                            "ip": {"type": "ip"},
                            "threat_score": {"type": "integer"},
                            "category": {"type": "keyword"},
                            "country": {"type": "keyword"},
                            "is_malicious": {"type": "boolean"},
                            "source": {"type": "keyword"}
                        }
                    }
                }
            }
            
            url = f"{self.es_url}/_index_template/{self.index_prefix}-template"
            response = requests.put(
                url,
                auth=(self.username, self.password),
                json=template,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code in [200, 201]:
                logger.info("Successfully created Elasticsearch index template")
                return True
            else:
                logger.warning(f"Failed to create index template: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating index template: {e}")
            return False