import logging
import json
import time
from datetime import datetime, timezone

class HoneypotLogger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        import os
        os.makedirs(log_dir, exist_ok=True)
        
    def info(self, msg, *args): 
        formatted = msg % args if args else msg
        print(f"INFO: {formatted}")
        
    def warning(self, msg, *args): 
        formatted = msg % args if args else msg
        print(f"WARNING: {formatted}")
        
    def critical(self, msg, *args): 
        formatted = msg % args if args else msg
        print(f"CRITICAL: {formatted}")
        
    def error(self, msg, *args): 
        formatted = msg % args if args else msg
        print(f"ERROR: {formatted}")
    
    def log_threat(self, correlation_id, threat_type, threat_score, details):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
            "event_type": "threat_detection",
            "threat_type": threat_type,
            "threat_score": threat_score,
            "details": details
        }
        
        with open(f"{self.log_dir}/intelligence.jsonl", "a") as f:
            f.write(json.dumps(log_entry) + "\n")

def setup_logger(name=None):
    return HoneypotLogger()
