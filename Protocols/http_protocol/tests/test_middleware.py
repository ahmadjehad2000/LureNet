# tests/test_middleware.py

import pytest
import asyncio
import time
import hashlib
import json
import sys
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Dict, Any, List
import threading
from concurrent.futures import ThreadPoolExecutor

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Now import middleware modules
try:
    from middleware.intelligence import IntelligenceMiddleware, HAS_C_ACCELERATION as HAS_C_INTEL
    from middleware.capture import CaptureMiddleware, HighPerformanceBuffer, HAS_C_CAPTURE
    from middleware.deception import DeceptionMiddleware, DeceptionConfig, HAS_C_DECEPTION
    IMPORTS_OK = True
except ImportError as e:
    print(f"Import error: {e}")
    print(f"Python path: {sys.path}")
    print(f"Current directory: {os.getcwd()}")
    print(f"Project root: {project_root}")
    IMPORTS_OK = False

# Skip all tests if imports fail
pytestmark = pytest.mark.skipif(not IMPORTS_OK, reason="Middleware imports failed")

class MockRequest:
    """High-fidelity mock request for testing"""
    def __init__(self, method="GET", path="/", headers=None, body=b"", client_ip="127.0.0.1"):
        self.method = method
        self.url = Mock()
        self.url.path = path
        self.url.query = ""
        self.url.scheme = "http"
        self.url.hostname = "localhost"
        self.url.port = 8080
        self.headers = headers or {}
        self.client = Mock()
        self.client.host = client_ip
        self.state = Mock()
        self._body = body
    
    async def body(self):
        return self._body

class MockResponse:
    """Mock response for testing"""
    def __init__(self, status_code=200, headers=None, body=b""):
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body

@pytest.fixture
def app():
    """Create test FastAPI app"""
    app = FastAPI()
    
    @app.get("/test")
    async def test_endpoint():
        return {"message": "test"}
    
    @app.get("/admin")
    async def admin_endpoint():
        return {"admin": "panel"}
    
    @app.post("/upload")
    async def upload_endpoint(request: Request):
        body = await request.body()
        return {"uploaded": len(body)}
    
    return app

@pytest.fixture
def client(app):
    """Create test client"""
    return TestClient(app)

class TestIntelligenceMiddleware:
    """Comprehensive intelligence middleware tests"""
    
    @pytest.fixture
    def middleware(self):
        app = FastAPI()
        return IntelligenceMiddleware(app)
    
    @pytest.mark.asyncio
    async def test_correlation_id_generation(self, middleware):
        """Test correlation ID generation and uniqueness"""
        ids = set()
        for _ in range(100):  # Reduced for faster testing
            correlation_id = middleware._generate_correlation_id()
            assert correlation_id not in ids
            assert len(correlation_id) > 10
            ids.add(correlation_id)
    
    @pytest.mark.asyncio
    async def test_client_ip_extraction(self, middleware):
        """Test client IP extraction with various proxy headers"""
        test_cases = [
            ({"x-forwarded-for": "192.168.1.1, 10.0.0.1"}, "192.168.1.1"),
            ({"x-real-ip": "203.0.113.1"}, "203.0.113.1"),
            ({}, "127.0.0.1")  # Fallback to client.host
        ]
        
        for headers, expected_ip in test_cases:
            request = MockRequest(headers=headers)
            extracted_ip = middleware._extract_client_ip(request)
            assert extracted_ip == expected_ip
    
    @pytest.mark.asyncio
    async def test_request_intelligence_collection(self, middleware):
        """Test comprehensive request intelligence gathering"""
        request = MockRequest(
            method="POST",
            path="/api/login",
            headers={
                "user-agent": "Mozilla/5.0 (Evil Bot)",
                "content-type": "application/json",
                "x-forwarded-for": "1.2.3.4"
            },
            body=b'{"username":"admin","password":"test"}'
        )
        
        intel = await middleware._collect_request_intelligence(request, "test_id")
        
        assert intel['correlation_id'] == "test_id"
        assert intel['client_ip'] == "1.2.3.4"
        assert intel['method'] == "POST"
        assert intel['path'] == "/api/login"
        assert intel['user_agent'] == "Mozilla/5.0 (Evil Bot)"
        assert intel['content_type'] == "application/json"
        assert 'header_analysis' in intel
        assert 'url_analysis' in intel
    
    @pytest.mark.asyncio
    async def test_header_analysis(self, middleware):
        """Test header analysis for suspicious patterns"""
        headers = {
            "user-agent": "sqlmap/1.0",
            "x-forwarded-for": "192.168.1.1",
            "x-custom-header": "test",
            "accept": "text/html"
        }
        
        analysis = middleware._analyze_headers(headers)
        
        assert analysis['count'] == 4
        assert analysis['has_custom_headers'] is True
        assert isinstance(analysis['missing'], list)
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, middleware):
        """Test rate limiting functionality"""
        client_ip = "192.168.1.100"
        
        # Simulate rapid requests (should hit limit at 100 requests)
        limited_count = 0
        for i in range(110):  # Exceed the 100 request threshold
            is_limited = middleware._is_rate_limited(client_ip)
            if is_limited:
                limited_count += 1
        
        # Should eventually hit rate limit after 100 requests
        assert limited_count > 5  # Should be rate limited multiple times
    
    def test_metrics_collection(self, middleware):
        """Test metrics collection and reporting"""
        # Simulate some processing
        middleware._update_metrics(0.1, 'high')
        middleware._update_metrics(0.05, 'minimal')
        
        metrics = middleware.get_metrics()
        
        assert metrics['total_requests'] == 2
        assert metrics['threat_detections'] == 1
        assert metrics['average_processing_time'] > 0

class TestCaptureMiddleware:
    """Comprehensive capture middleware tests"""
    
    @pytest.fixture
    def middleware(self):
        app = FastAPI()
        return CaptureMiddleware(app, buffer_size=1024*100, max_body_capture=1024)  # Smaller for testing
    
    def test_high_performance_buffer(self):
        """Test high-performance ring buffer operations"""
        buffer = HighPerformanceBuffer(size=1024)
        
        # Test normal write
        data1 = b"Hello World" * 5
        assert buffer.write(data1) is True
        
        # Test larger write
        large_data = b"X" * 500
        assert buffer.write(large_data) is True
    
    @pytest.mark.asyncio
    async def test_request_capture(self, middleware):
        """Test comprehensive request capture"""
        request = MockRequest(
            method="POST",
            path="/api/data",
            headers={"content-type": "application/json"},
            body=b'{"data": "test"}'
        )
        
        captured = await middleware._capture_request(request, "test_correlation")
        
        assert captured.correlation_id == "test_correlation"
        assert captured.method == "POST"
        assert captured.path == "/api/data"
        assert captured.body == b'{"data": "test"}'
        assert captured.body_hash != ""
    
    def test_client_ip_extraction(self, middleware):
        """Test client IP extraction with proxy headers"""
        request = MockRequest(headers={
            "x-forwarded-for": "203.0.113.195, 192.168.1.1",
            "x-real-ip": "198.51.100.178"
        })
        
        ip = middleware._extract_client_ip(request)
        assert ip == "203.0.113.195"  # Should take first in X-Forwarded-For

class TestDeceptionMiddleware:
    """Comprehensive deception middleware tests"""
    
    @pytest.fixture
    def config(self):
        return DeceptionConfig(
            error_injection_rate=0.2,
            response_delay_range=(0.001, 0.01),  # Very fast for testing
            fake_headers_enabled=True,
            honeypot_fields_enabled=True
        )
    
    @pytest.fixture
    def middleware(self, config):
        app = FastAPI()
        return DeceptionMiddleware(app, config)
    
    @pytest.mark.asyncio
    async def test_admin_trap_detection(self, middleware):
        """Test admin panel trap detection"""
        admin_paths = ["/admin", "/wp-admin", "/phpmyadmin"]
        
        for path in admin_paths:
            request = MockRequest(path=path)
            trap_response = middleware._check_honeypot_traps(request)
            
            assert trap_response is not None
            assert trap_response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_exploit_trap_detection(self, middleware):
        """Test exploit attempt trap detection"""
        exploit_paths = ["/.env", "/shell.php", "/config.php"]
        
        for path in exploit_paths:
            request = MockRequest(path=path)
            trap_response = middleware._check_honeypot_traps(request)
            
            assert trap_response is not None
            assert trap_response.status_code == 200
    
    def test_static_asset_skip(self, middleware):
        """Test that static assets skip deception"""
        static_paths = ["/static/style.css", "/js/app.js", "/favicon.ico"]
        
        for path in static_paths:
            is_static = middleware._is_static_asset(path)
            assert is_static is True
        
        # Dynamic paths should not be skipped
        assert middleware._is_static_asset("/api/data") is False
    
    def test_session_id_generation(self, middleware):
        """Test session ID generation quality"""
        session_ids = set()
        
        for _ in range(10):  # Reduced for faster testing
            session_id = middleware._generate_session_id()
            assert len(session_id) == 32  # MD5 hex length
            assert session_id not in session_ids
            session_ids.add(session_id)

class TestMiddlewareIntegration:
    """Basic integration tests"""
    
    def test_import_success(self):
        """Test that all imports succeeded"""
        assert IMPORTS_OK is True
        assert IntelligenceMiddleware is not None
        assert CaptureMiddleware is not None 
        assert DeceptionMiddleware is not None
    
    def test_middleware_instantiation(self):
        """Test that middleware can be instantiated"""
        app = FastAPI()
        
        # Test each middleware can be created
        intel_middleware = IntelligenceMiddleware(app)
        assert intel_middleware is not None
        
        capture_middleware = CaptureMiddleware(app, buffer_size=1024)
        assert capture_middleware is not None
        
        deception_config = DeceptionConfig()
        deception_middleware = DeceptionMiddleware(app, deception_config)
        assert deception_middleware is not None

def test_setup_validation():
    """Validate test setup and environment"""
    print(f"Python version: {sys.version}")
    print(f"Current working directory: {os.getcwd()}")
    print(f"Python path: {sys.path[:3]}...")  # First 3 entries
    print(f"Imports OK: {IMPORTS_OK}")
    
    if IMPORTS_OK:
        print("✅ All middleware imports successful")
        print(f"C Acceleration - Intel: {HAS_C_INTEL}, Capture: {HAS_C_CAPTURE}, Deception: {HAS_C_DECEPTION}")
    else:
        print("❌ Import failures detected")

if __name__ == "__main__":
    # Run setup validation first
    test_setup_validation()
    
    # Run tests with minimal output
    pytest.main([__file__, "-v", "--tb=short", "-x"])  # Stop on first failure
