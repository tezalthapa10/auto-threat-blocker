import os
import hashlib
import logging
import json
import time
import re
from datetime import datetime

# Get logger
from utils.logger import get_logger
logger = get_logger("file_detector")

class FileDetector:
    def __init__(self, config):
        self.config = config
        self.directories = config.get('directories', [])
        self.extensions_to_scan = config.get('extensions_to_scan', ['.exe', '.sh', '.bat', '.ps1', '.php', '.js'])
        self.size_limit = config.get('size_limit', 100 * 1024 * 1024)  # Default 100MB
        
        # Ensure directories exist
        for directory in self.directories:
            if not os.path.exists(directory):
                logger.warning(f"Directory does not exist: {directory}")
    
    def scan_files(self):
        """Scan directories for suspicious files"""
        logger.info(f"Starting file scan in {len(self.directories)} directories")
        suspicious_files = []
        
        for directory in self.directories:
            if not os.path.exists(directory):
                logger.warning(f"Directory does not exist: {directory}")
                continue
                
            logger.info(f"Scanning directory: {directory}")
            
            try:
                for root, _, files in os.walk(directory):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        
                        try:
                            # Skip if not a regular file or not readable
                            if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
                                continue
                                
                            # Skip if too large
                            file_size = os.path.getsize(file_path)
                            if file_size > self.size_limit:
                                logger.warning(f"Skipping large file: {file_path} ({file_size} bytes)")
                                continue
                                
                            # Check file extension
                            _, ext = os.path.splitext(filename.lower())
                            if not self.extensions_to_scan or ext in self.extensions_to_scan:
                                logger.debug(f"Checking file: {file_path}")
                                
                                # Calculate file hash
                                file_hash = self._calculate_file_hash(file_path)
                                
                                # Basic suspicious pattern check (example)
                                is_suspicious = self._check_suspicious_patterns(file_path)
                                
                                if is_suspicious:
                                    logger.info(f"Found suspicious file: {file_path}")
                                    suspicious_files.append({
                                        'path': file_path,
                                        'hash': file_hash,
                                        'size': file_size,
                                        'extension': ext,
                                        'last_modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                                    })
                        except Exception as e:
                            logger.error(f"Error processing file {file_path}: {e}")
            except Exception as e:
                logger.error(f"Error scanning directory {directory}: {e}")
        
        logger.info(f"Completed file scan, found {len(suspicious_files)} suspicious files")
        return suspicious_files
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def _check_suspicious_patterns(self, file_path):
        """Check file for suspicious patterns (basic implementation)"""
        # This is a simple example - in a real implementation, you'd want more sophisticated checks
        try:
            # Check file extension first
            _, ext = os.path.splitext(file_path.lower())
            
            # Known suspicious extensions
            suspicious_exts = ['.exe', '.bat', '.vbs', '.ps1', '.sh']
            if ext in suspicious_exts:
                # For executable files, just flagging them might be enough in some environments
                return True
            
            # For text-based files, check for suspicious content
            if ext in ['.sh', '.py', '.php', '.js', '.txt']:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    
                    # Simple patterns that might indicate malicious scripts
                    suspicious_patterns = [
                        r'eval\s*\(base64_decode',  # PHP obfuscation
                        r'chmod\s+[0-7]*777',        # Suspicious permissions
                        r'rm\s+-rf\s+/',            # System deletion
                        r'wget\s+.+\s*\|\s*bash',   # Download and execute
                        r'curl\s+.+\s*\|\s*sh',     # Download and execute
                        r'while\s*true',            # Potential fork bomb
                        r'Invoke-Expression',       # PowerShell execution
                        r'New-Object\s+Net\.WebClient',  # PowerShell download
                    ]
                    
                    for pattern in suspicious_patterns:
                        if re.search(pattern, content):
                            logger.debug(f"Found suspicious pattern in {file_path}: {pattern}")
                            return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking file patterns in {file_path}: {e}")
            return False
