# core/__init__.py
"""Core modules"""

# core/config.py
class Config:
    def __init__(self):
        self.buffer_size = 10 * 1024 * 1024
        self.max_body_size = 100 * 1024 * 1024
        self.enable_c_acceleration = True

_config = Config()

def get_config():
    return _config

# core/intelligence.py  
class IntelligenceEngine:
    async def analyze_request(self, request, correlation_id):
        return {
            'threat_score': 50,
            'attack_type': 'probe',
            'correlation_id': correlation_id
        }

_intelligence_engine = IntelligenceEngine()

def get_intelligence_engine():
    return _intelligence_engine

# core/correlation.py
class CorrelationEngine:
    async def correlate_event(self, analysis_result):
        return {
            'session_id': 'test_session',
            'correlation_score': 0.8
        }

_correlation_engine = CorrelationEngine()

def get_correlation_engine():
    return _correlation_engine

# utils/__init__.py
"""Utility modules"""

# utils/logger.py
import logging

def setup_logger(name=__name__):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

# utils/helpers.py
import time
import hashlib
import uuid

class SecurityHelpers:
    @staticmethod
    def generate_correlation_id():
        timestamp = int(time.time() * 1000000)
        random_part = str(uuid.uuid4())[:8]
        return f"ATK_{timestamp:012x}_{random_part}"
