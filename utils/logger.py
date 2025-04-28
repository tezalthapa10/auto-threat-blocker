# src/utils/logger.py
import logging
import json
import os

# Ensure log directory exists
os.makedirs("logs", exist_ok=True)

def get_logger(name):
    """
    Get a logger instance with proper configuration
    
    Args:
        name (str): Logger name
        
    Returns:
        logging.Logger: Configured logger
    """
    logger = logging.getLogger(name)
    
    # Avoid adding handlers multiple times
    if not logger.handlers:
        # Set logging level
        logger.setLevel(logging.INFO)
        
        # Create formatters
        standard_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        json_formatter = logging.Formatter('%(message)s')
        
        # File handler for normal logs
        file_handler = logging.FileHandler(f"logs/{name}.log")
        file_handler.setFormatter(standard_formatter)
        logger.addHandler(file_handler)
        
        # File handler for JSON logs (used for Elasticsearch)
        json_handler = logging.FileHandler("logs/auto_blocker.json")
        json_handler.setFormatter(json_formatter)
        json_handler.setLevel(logging.INFO)
        logger.addHandler(json_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(standard_formatter)
        logger.addHandler(console_handler)
    
    return logger

# Create a helper function for structured logging
def log_event(logger, event_type, data):
    """
    Log a structured event
    
    Args:
        logger (logging.Logger): Logger instance
        event_type (str): Type of event
        data (dict): Event data
    """
    log_data = {
        "event_type": event_type,
        "timestamp": datetime.now().isoformat(),
        **data
    }
    logger.info(json.dumps(log_data))
