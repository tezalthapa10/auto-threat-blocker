# src/utils/config.py
import os
import yaml
import logging

def load_config(config_path):
    """
    Load configuration from YAML file
    
    Args:
        config_path (str): Path to configuration file
        
    Returns:
        dict: Configuration
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        return config
    except Exception as e:
        logging.error(f"Failed to load configuration from {config_path}: {e}")
        raise
