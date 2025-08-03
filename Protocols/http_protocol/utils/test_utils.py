# tests/test_logger.py

import unittest
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, Mock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import HoneypotLogger

class TestHoneypotLogger(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.logger = HoneypotLogger(log_dir=self.test_dir)
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
    
    def test_logger_initialization(self):
        """Test logger creates necessary files and directories"""
        self.assertTrue(Path(self.test_dir).exists())
        
        # The log files should exist after initialization
        log_file = Path(self.test_dir, "honeypot.log")
        json_file = Path(self.test_dir, "intelligence.jsonl")
        
        self.assertTrue(log_file.exists(), f"Log file {log_file} does not exist")
        self.assertTrue(json_file.exists(), f"JSON file {json_file} does not exist")
        
    def test_log_request(self):
        """Test HTTP request logging"""
        headers = {"user-agent": "curl/7.68.0", "host": "example.com"}
        
        self.logger.log_request(
            correlation_id="test_001",
            ip="192.168.1.100",
            method="GET",
            path="/test",
            headers=headers,
            body=b"test body"
        )
        
        # Check JSON log was created
        json_log = Path(self.test_dir, "intelligence.jsonl")
        self.assertTrue(json_log.exists())
        
        # Read and verify JSON log content (read the last line)
        with open(json_log, 'r') as f:
            lines = f.readlines()
            log_entry = json.loads(lines[-1].strip())
        
        self.assertEqual(log_entry["correlation_id"], "test_001")
        self.assertEqual(log_entry["event_type"], "http_request")
        self.assertEqual(log_entry["source_ip"], "192.168.1.100")
        self.assertEqual(log_entry["method"], "GET")
        self.assertEqual(log_entry["path"], "/test")
        self.assertEqual(log_entry["body"], "test body")
    
    def test_log_response(self):
        """Test HTTP response logging"""
        headers = {"content-type": "text/html"}
        
        self.logger.log_response(
            correlation_id="test_002",
            status_code=200,
            headers=headers,
            response_time=0.123
        )
        
        # Read JSON log (read the last line)
        json_log = Path(self.test_dir, "intelligence.jsonl")
        with open(json_log, 'r') as f:
            lines = f.readlines()
            log_entry = json.loads(lines[-1].strip())
        
        self.assertEqual(log_entry["correlation_id"], "test_002")
        self.assertEqual(log_entry["event_type"], "http_response")
        self.assertEqual(log_entry["status_code"], 200)
        self.assertEqual(log_entry["response_time"], 0.123)
    
    def test_log_threat(self):
        """Test threat detection logging"""
        details = {"pattern": "sql_injection", "confidence": 0.95}
        
        self.logger.log_threat(
            correlation_id="test_003",
            threat_type="sql_injection",
            threat_score=85,
            details=details
        )
        
        # Read JSON log (read the last line)
        json_log = Path(self.test_dir, "intelligence.jsonl")
        with open(json_log, 'r') as f:
            lines = f.readlines()
            log_entry = json.loads(lines[-1].strip())
        
        self.assertEqual(log_entry["event_type"], "threat_detection")
        self.assertEqual(log_entry["threat_type"], "sql_injection")
        self.assertEqual(log_entry["threat_score"], 85)
        self.assertEqual(log_entry["details"], details)
    
    def test_log_credentials(self):
        """Test credential capture logging"""
        self.logger.log_credentials(
            correlation_id="test_004",
            source="phishing_page",
            username="admin",
            password="password123",
            ip="10.0.0.5"
        )
        
        # Read JSON log (read the last line)
        json_log = Path(self.test_dir, "intelligence.jsonl")
        with open(json_log, 'r') as f:
            lines = f.readlines()
            log_entry = json.loads(lines[-1].strip())
        
        self.assertEqual(log_entry["event_type"], "credentials_captured")
        self.assertEqual(log_entry["username"], "admin")
        self.assertEqual(log_entry["password"], "password123")
    
    def test_log_file_upload(self):
        """Test file upload logging"""
        self.logger.log_file_upload(
            correlation_id="test_005",
            filename="malware.exe",
            file_size=1024,
            file_hash="abc123def456",
            ip="172.16.0.10"
        )
        
        # Read JSON log (read the last line)
        json_log = Path(self.test_dir, "intelligence.jsonl")
        with open(json_log, 'r') as f:
            lines = f.readlines()
            log_entry = json.loads(lines[-1].strip())
        
        self.assertEqual(log_entry["event_type"], "file_upload")
        self.assertEqual(log_entry["filename"], "malware.exe")
        self.assertEqual(log_entry["file_size"], 1024)
    
    def test_log_tls_fingerprint(self):
        """Test TLS fingerprint logging"""
        self.logger.log_tls_fingerprint(
            correlation_id="test_006",
            ja3_hash="5eb6ec78b10a84983a410332ceda726f",
            ja3_string="771,4865-4866,0-11-10,29-23,0",
            ip="203.0.113.15"
        )
        
        # Read JSON log (read the last line)
        json_log = Path(self.test_dir, "intelligence.jsonl")
        with open(json_log, 'r') as f:
            lines = f.readlines()
            log_entry = json.loads(lines[-1].strip())
        
        self.assertEqual(log_entry["event_type"], "tls_fingerprint")
        self.assertEqual(log_entry["ja3_hash"], "5eb6ec78b10a84983a410332ceda726f")
    
    @patch('requests.get')
    def test_geo_info_success(self, mock_get):
        """Test successful geo IP lookup"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "country": "United States",
            "city": "New York",
            "org": "Example ISP"
        }
        mock_get.return_value = mock_response
        
        geo_info = self.logger._get_geo_info("203.0.113.1")
        self.assertEqual(geo_info, "United States, New York | Example ISP")
    
    @patch('requests.get')
    def test_geo_info_failure(self, mock_get):
        """Test failed geo IP lookup"""
        mock_get.side_effect = Exception("Network error")
        
        geo_info = self.logger._get_geo_info("203.0.113.1")
        self.assertEqual(geo_info, "Unknown")
    
    def test_local_ip_detection(self):
        """Test local IP detection"""
        self.assertEqual(self.logger._get_geo_info("127.0.0.1"), "Local")
        self.assertEqual(self.logger._get_geo_info("192.168.1.1"), "Local")
        self.assertEqual(self.logger._get_geo_info("::1"), "Local")
    
    def test_multiple_log_entries(self):
        """Test multiple log entries are properly formatted"""
        # Clear any existing content
        json_log = Path(self.test_dir, "intelligence.jsonl")
        if json_log.exists():
            json_log.unlink()
            json_log.touch()
        
        # Log multiple entries
        self.logger.log_request("test_001", "192.168.1.1", "GET", "/", {})
        self.logger.log_response("test_001", 200, {}, 0.1)
        self.logger.log_threat("test_002", "xss", 70, {"pattern": "script"})
        
        # Read all entries
        with open(json_log, 'r') as f:
            lines = f.readlines()
        
        self.assertEqual(len(lines), 3)
        
        # Verify each line is valid JSON
        for line in lines:
            data = json.loads(line.strip())
            self.assertIn("timestamp", data)
            self.assertIn("event_type", data)

if __name__ == "__main__":
    unittest.main()
