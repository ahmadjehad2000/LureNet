# utils/logger.py

import logging
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Optional
import requests

class HoneypotLogger:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup structured logger
        self.json_log_file = self.log_dir / "intelligence.jsonl"
        
        # Setup standard logger
        self.logger = self._setup_standard_logger()
        
        # Ensure log files exist
        log_file = self.log_dir / "honeypot.log"
        if not log_file.exists():
            log_file.touch()
        if not self.json_log_file.exists():
            self.json_log_file.touch()
        
    def _setup_standard_logger(self) -> logging.Logger:
        logger = logging.getLogger("honeypot")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        
        if not logger.handlers:
            formatter = logging.Formatter(
                fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            
            # File handler with rotation
            log_file = self.log_dir / "honeypot.log"
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            file_handler.setFormatter(formatter)
            
            # Console handler
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            
            logger.addHandler(file_handler)
            logger.addHandler(console_handler)
            
        return logger
    
    def log_request(self, correlation_id: str, ip: str, method: str, path: str, 
                   headers: Dict[str, str], body: bytes = b"", 
                   extra_info: Optional[str] = None):
        """Log HTTP request in both text and JSON format"""
        
        # Text logging
        user_agent = headers.get("user-agent", "Unknown")
        geo_info = self._get_geo_info(ip)
        
        message = f"[HTTP] {ip} ({geo_info}) {method} {path} UA=\"{user_agent}\""
        if extra_info:
            message += f" | {extra_info}"
            
        self.logger.info(message)
        
        # Structured JSON logging
        json_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "event_type": "http_request",
            "source_ip": ip,
            "method": method,
            "path": path,
            "headers": headers,
            "body_size": len(body),
            "body": body.decode('utf-8', errors='ignore')[:1000] if body else "",
            "geo_info": geo_info,
            "user_agent": user_agent
        }
        
        self._log_json(json_data)
    
    def log_response(self, correlation_id: str, status_code: int, 
                    headers: Dict[str, str], response_time: float):
        """Log HTTP response"""
        
        # Text logging
        self.logger.info(f"[RESPONSE] {correlation_id} | {status_code} | {response_time:.3f}s")
        
        # JSON logging
        json_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "event_type": "http_response",
            "status_code": status_code,
            "headers": headers,
            "response_time": response_time
        }
        
        self._log_json(json_data)
    
    def log_threat(self, correlation_id: str, threat_type: str, threat_score: int,
                  details: Dict[str, Any]):
        """Log threat intelligence"""
        
        # Text logging
        self.logger.warning(f"[THREAT] {correlation_id} | {threat_type} | Score: {threat_score}")
        
        # JSON logging
        json_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "event_type": "threat_detection",
            "threat_type": threat_type,
            "threat_score": threat_score,
            "details": details
        }
        
        self._log_json(json_data)
    
    def log_credentials(self, correlation_id: str, source: str, 
                       username: str, password: str, ip: str):
        """Log captured credentials"""
        
        # Text logging (sanitized)
        self.logger.warning(f"[CREDENTIALS] {correlation_id} | {source} | {ip} | {username}:***")
        
        # JSON logging (full data)
        json_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "event_type": "credentials_captured",
            "source": source,
            "username": username,
            "password": password,
            "source_ip": ip
        }
        
        self._log_json(json_data)
    
    def log_file_upload(self, correlation_id: str, filename: str, 
                       file_size: int, file_hash: str, ip: str):
        """Log file uploads"""
        
        self.logger.warning(f"[UPLOAD] {correlation_id} | {filename} | {file_size} bytes | {ip}")
        
        json_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "event_type": "file_upload",
            "filename": filename,
            "file_size": file_size,
            "file_hash": file_hash,
            "source_ip": ip
        }
        
        self._log_json(json_data)
    
    def log_tls_fingerprint(self, correlation_id: str, ja3_hash: str, 
                          ja3_string: str, ip: str):
        """Log TLS fingerprints"""
        
        self.logger.info(f"[TLS] {correlation_id} | JA3: {ja3_hash} | {ip}")
        
        json_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "event_type": "tls_fingerprint",
            "ja3_hash": ja3_hash,
            "ja3_string": ja3_string,
            "source_ip": ip
        }
        
        self._log_json(json_data)
    
    def _log_json(self, data: Dict[str, Any]):
        """Write JSON data to structured log file"""
        try:
            with open(self.json_log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(data, ensure_ascii=False) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write JSON log: {e}")
    
    def _get_geo_info(self, ip: str) -> str:
        """Get geographical information for IP"""
        try:
            if ip.startswith("127.") or ip == "::1" or ip.startswith("192.168."):
                return "Local"
            
            # Use free IP geolocation service
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=country,regionName,city,org,as,query",
                timeout=2
            )
            
            if resp.status_code == 200:
                data = resp.json()
                return f"{data.get('country', '')}, {data.get('city', '')} | {data.get('org', '')}"
        except Exception as e:
            self.logger.debug(f"GeoIP lookup failed for {ip}: {e}")
        
        return "Unknown"
    
    def info(self, message: str):
        """Standard info logging"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Standard warning logging"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Standard error logging"""
        self.logger.error(message)

# Global logger instance
honeypot_logger = HoneypotLogger()

def setup_logger() -> HoneypotLogger:
    """Get global logger instance"""
    return honeypot_logger
