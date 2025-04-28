import os
import time
import logging
import hashlib
import requests

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class VirusTotalClient:
    def __init__(self, api_key):
        if not api_key:
            raise ValueError("API key must be provided.")
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'

    def _get_headers(self):
        return {
            'x-apikey': self.api_key
        }

    def scan_file(self, file_path):
        """Scan a file with VirusTotal."""
        try:
            file_hash = self._calculate_file_hash(file_path)

            # First check if the file has already been analyzed
            existing_report = self.get_file_report(file_hash)
            if existing_report:
                logger.info(f"File already analyzed. Returning existing report for {file_path}")
                return existing_report

            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(
                    f"{self.base_url}/files",
                    headers=self._get_headers(),
                    files=files
                )
            response.raise_for_status()
            analysis_id = response.json().get('data', {}).get('id')

            if not analysis_id:
                logger.error("Analysis ID not found in the response.")
                return None

            logger.info(f"File uploaded successfully. Analysis ID: {analysis_id}")
            return self._get_scan_results(analysis_id)

        except Exception as e:
            logger.error(f"Error scanning file with VirusTotal: {e}")
            return None

    def get_file_report(self, file_hash):
        """Get the VirusTotal report for a given file hash."""
        try:
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=self._get_headers()
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error getting file report from VirusTotal: {e}")
            return None

    def scan_ip(self, ip_address):
        """Scan an IP address with VirusTotal."""
        try:
            response = requests.get(
                f"{self.base_url}/ip_addresses/{ip_address}",
                headers=self._get_headers()
            )
            response.raise_for_status()
            ip_data = response.json()

            malicious_count, suspicious_count = self._process_ip_scan_results(ip_data)

            # Calculate threat score
            threat_score = malicious_count + (suspicious_count * 0.5)

            return {
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "threat_score": threat_score
            }

        except Exception as e:
            logger.error(f"Error scanning IP with VirusTotal: {e}")
            return None

    def _get_scan_results(self, analysis_id, timeout=300, interval=15):
        """Poll for scan results."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                response = requests.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers=self._get_headers()
                )
                response.raise_for_status()
                analysis_result = response.json()
                status = analysis_result.get('data', {}).get('attributes', {}).get('status')

                if status == 'completed':
                    logger.info(f"Analysis completed for ID: {analysis_id}")
                    return analysis_result
                else:
                    logger.info(f"Analysis pending... Retrying in {interval} seconds.")
                    time.sleep(interval)

            except Exception as e:
                logger.error(f"Error retrieving scan results: {e}")
                return None

        logger.warning(f"Timeout exceeded while waiting for scan results for ID: {analysis_id}")
        return None

    def _calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {e}")
            return None

    def _process_ip_scan_results(self, scan_results):
        """Helper to process IP scan results."""
        malicious_count = 0
        suspicious_count = 0

        try:
            if scan_results:
                last_analysis_stats = scan_results.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious_count = last_analysis_stats.get('malicious', 0)
                suspicious_count = last_analysis_stats.get('suspicious', 0)
        except Exception as e:
            logger.error(f"Error processing IP scan results: {e}")

        return malicious_count, suspicious_count
