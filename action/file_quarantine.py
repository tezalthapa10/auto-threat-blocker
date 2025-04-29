import os
import shutil
import logging
import json
import hashlib
from datetime import datetime

# Get logger
from utils.logger import get_logger
logger = get_logger("file_quarantine")

class FileQuarantine:
    def __init__(self, config):
        self.config = config
        self.quarantine_dir = config.get('quarantine_dir', '/home/atb/auto-threat-blocker/quarantine')
        self.metadata_file = os.path.join(self.quarantine_dir, 'metadata.json')
        
        # Ensure quarantine directory exists
        self._ensure_quarantine_dir()
        
        # Load quarantined files metadata
        self.quarantined_files = self._load_metadata()
    
    def _ensure_quarantine_dir(self):
        """Ensure quarantine directory exists"""
        try:
            if not os.path.exists(self.quarantine_dir):
                os.makedirs(self.quarantine_dir, exist_ok=True)
                logger.info(f"Created quarantine directory: {self.quarantine_dir}")
        except Exception as e:
            logger.error(f"Failed to create quarantine directory: {e}")
            raise
    
    def quarantine_file(self, file_path, reason="Suspicious file"):
        """
        Move a file to quarantine
        
        Args:
            file_path (str): Path to the file to quarantine
            reason (str): Reason for quarantining
            
        Returns:
            dict: Quarantine metadata for the file, or None if failed
        """
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Check if file is already quarantined
            if file_hash in self.quarantined_files:
                logger.info(f"File is already quarantined: {file_path}")
                return self.quarantined_files[file_hash]
            
            # Create a unique filename for the quarantined file
            timestamp = int(datetime.now().timestamp())
            filename = os.path.basename(file_path)
            quarantine_filename = f"{timestamp}_{file_hash[:8]}_{filename}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Move the file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Create metadata
            metadata = {
                'hash': file_hash,
                'original_path': file_path,
                'quarantine_path': quarantine_path,
                'size': os.path.getsize(quarantine_path),
                'reason': reason,
                'quarantined_at': datetime.now().isoformat(),
                'filename': filename
            }
            
            # Update quarantined files metadata
            self.quarantined_files[file_hash] = metadata
            self._save_metadata()
            
            # Log in structured format
            log_data = {
                "action": "quarantine",
                "file_path": file_path,
                "hash": file_hash,
                "reason": reason,
                "timestamp": datetime.now().isoformat(),
                "is_malicious": True,
                "event_type": "file_quarantine"
            }
            logger.info(json.dumps(log_data))
            
            logger.info(f"Quarantined file: {file_path} -> {quarantine_path}")
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
            return None
    
    def restore_file(self, file_hash, restore_path=None):
        """
        Restore a file from quarantine
        
        Args:
            file_hash (str): Hash of the file to restore
            restore_path (str, optional): Path to restore the file to. If None, uses original path.
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if file_hash not in self.quarantined_files:
                logger.error(f"File not found in quarantine: {file_hash}")
                return False
            
            metadata = self.quarantined_files[file_hash]
            quarantine_path = metadata['quarantine_path']
            
            if not os.path.exists(quarantine_path):
                logger.error(f"Quarantined file not found: {quarantine_path}")
                return False
            
            # Determine restore path
            if not restore_path:
                restore_path = metadata['original_path']
            
            # Ensure the directory exists
            os.makedirs(os.path.dirname(restore_path), exist_ok=True)
            
            # Move the file back
            shutil.move(quarantine_path, restore_path)
            
            # Remove from quarantined files
            del self.quarantined_files[file_hash]
            self._save_metadata()
            
            # Log structured data
            log_data = {
                "action": "restore",
                "file_path": restore_path,
                "hash": file_hash,
                "timestamp": datetime.now().isoformat(),
                "event_type": "file_restore"
            }
            logger.info(json.dumps(log_data))
            
            logger.info(f"Restored file: {quarantine_path} -> {restore_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore file {file_hash}: {e}")
            return False
    
    def get_quarantined_files(self):
        """Get list of quarantined files"""
        return self.quarantined_files
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def _load_metadata(self):
        """Load quarantined files metadata"""
        try:
            if not os.path.exists(self.metadata_file):
                return {}
            
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            logger.error(f"Failed to load quarantine metadata: {e}")
            return {}
    
    def _save_metadata(self):
        """Save quarantined files metadata"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.quarantined_files, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save quarantine metadata: {e}")
