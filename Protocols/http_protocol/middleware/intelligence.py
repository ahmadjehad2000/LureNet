# middleware/intelligence.py

import time
import uuid
import asyncio
import struct
from typing import Dict, Any, Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import ctypes
from ctypes import CDLL, c_char_p, c_int, c_uint64, c_double, POINTER, Structure

from core.intelligence import get_intelligence_engine
from core.correlation import get_correlation_engine
from utils.logger import setup_logger
from utils.helpers import SecurityHelpers

# C library integration for high-performance operations
try:
    # Load C library for fast hashing and processing
    libfast = CDLL("./lib/libfast_intel.so")
    
    # Define C structures
    class RequestMetrics(Structure):
        _fields_ = [
            ("timestamp", c_uint64),
            ("request_size", c_int),
            ("header_count", c_int),
            ("processing_time", c_double),
            ("threat_score", c_double)
        ]
    
    # Define C function signatures
    libfast.fast_hash_request.argtypes = [c_char_p, c_int]
    libfast.fast_hash_request.restype = c_uint64
    
    libfast.calculate_request_fingerprint.argtypes = [POINTER(RequestMetrics)]
    libfast.calculate_request_fingerprint.restype = c_uint64
    
    HAS_C_ACCELERATION = True
except (OSError, AttributeError):
    HAS_C_ACCELERATION = False
    libfast = None

class IntelligenceMiddleware(BaseHTTPMiddleware):
    """
    High-performance intelligence collection middleware
    Integrates with C acceleration for critical path operations
    """
    
    def __init__(self, app, max_body_size: int = 10485760):  # 10MB
        super().__init__(app)
        self.logger = setup_logger()
        self.intelligence_engine = get_intelligence_engine()
        self.correlation_engine = get_correlation_engine()
        self.max_body_size = max_body_size
        
        # Performance counters
        self.request_count = 0
        self.total_processing_time = 0.0
        self.threat_detections = 0
        
        # Request rate limiting state
        self.rate_limit_state = {}
        self.rate_limit_window = 60  # seconds
        self.rate_limit_threshold = 100  # requests per window
        
        self.logger.info("Intelligence middleware initialized with C acceleration: %s", HAS_C_ACCELERATION)
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Main middleware dispatch with integrated intelligence collection
        """
        start_time = time.time()
        correlation_id = self._generate_correlation_id()
        
        # Inject correlation ID into request state
        request.state.correlation_id = correlation_id
        request.state.start_time = start_time
        
        try:
            # Pre-process request for intelligence
            request_intel = await self._collect_request_intelligence(request, correlation_id)
            
            # Rate limiting check
            if self._is_rate_limited(request_intel['client_ip']):
                return self._create_rate_limit_response()
            
            # Capture request body efficiently
            body_data = await self._capture_request_body(request)
            request_intel['body_data'] = body_data
            
            # Fast threat assessment using C acceleration if available
            if HAS_C_ACCELERATION:
                threat_score = self._fast_threat_assessment(request_intel)
                request_intel['fast_threat_score'] = threat_score
            
            # Store intelligence data in request state
            request.state.intelligence = request_intel
            
            # Process request through next middleware/handler
            response = await call_next(request)
            
            # Post-process response
            await self._process_response_intelligence(request, response, request_intel)
            
            # Update performance metrics
            self._update_metrics(time.time() - start_time, request_intel.get('threat_level', 'minimal'))
            
            return response
            
        except Exception as e:
            self.logger.error(f"Intelligence middleware error: {e}")
            # Continue processing even if intelligence fails
            return await call_next(request)
    
    async def _collect_request_intelligence(self, request: Request, correlation_id: str) -> Dict[str, Any]:
        """
        Collect comprehensive request intelligence data
        """
        client_ip = self._extract_client_ip(request)
        
        # Basic request metadata
        intel_data = {
            'correlation_id': correlation_id,
            'timestamp': time.time(),
            'client_ip': client_ip,
            'method': request.method,
            'path': str(request.url.path),
            'query_string': str(request.url.query) if request.url.query else "",
            'scheme': request.url.scheme,
            'headers': dict(request.headers),
            'user_agent': request.headers.get('user-agent', ''),
            'referer': request.headers.get('referer', ''),
            'content_type': request.headers.get('content-type', ''),
            'content_length': int(request.headers.get('content-length', 0)),
            'host': request.headers.get('host', ''),
            'x_forwarded_for': request.headers.get('x-forwarded-for', ''),
            'connection_info': {
                'remote_addr': client_ip,
                'server_name': request.url.hostname,
                'server_port': request.url.port
            }
        }
        
        # Enhanced header analysis
        intel_data['header_analysis'] = self._analyze_headers(request.headers)
        
        # URL analysis
        intel_data['url_analysis'] = self._analyze_url(request.url)
        
        # Geographic intelligence (if available)
        intel_data['geo_intel'] = await self._get_geo_intelligence(client_ip)
        
        return intel_data
    
    async def _capture_request_body(self, request: Request) -> Dict[str, Any]:
        """
        Efficiently capture and analyze request body
        """
        try:
            # Read body with size limit
            body = await request.body()
            
            if len(body) > self.max_body_size:
                self.logger.warning(f"Request body too large: {len(body)} bytes")
                body = body[:self.max_body_size]
            
            # Fast hash using C acceleration if available
            if HAS_C_ACCELERATION and body:
                body_hash = libfast.fast_hash_request(body, len(body))
            else:
                body_hash = hash(body)
            
            return {
                'size': len(body),
                'hash': body_hash,
                'preview': body[:500].decode('utf-8', errors='ignore') if body else "",
                'is_binary': self._is_binary_content(body),
                'content_preview': self._extract_content_preview(body)
            }
            
        except Exception as e:
            self.logger.error(f"Body capture error: {e}")
            return {'size': 0, 'hash': 0, 'preview': "", 'error': str(e)}
    
    def _fast_threat_assessment(self, request_intel: Dict[str, Any]) -> float:
        """
        Fast threat assessment using C acceleration
        """
        if not HAS_C_ACCELERATION:
            return 0.0
        
        try:
            # Create C structure for fast processing
            metrics = RequestMetrics()
            metrics.timestamp = int(request_intel['timestamp'])
            metrics.request_size = request_intel.get('body_data', {}).get('size', 0)
            metrics.header_count = len(request_intel['headers'])
            metrics.processing_time = 0.0  # Will be updated later
            metrics.threat_score = 0.0
            
            # Calculate fingerprint using C
            fingerprint = libfast.calculate_request_fingerprint(ctypes.byref(metrics))
            
            # Convert fingerprint to threat score (0.0 - 1.0)
            threat_score = (fingerprint % 1000) / 1000.0
            
            return threat_score
            
        except Exception as e:
            self.logger.error(f"C acceleration error: {e}")
            return 0.0
    
    async def _process_response_intelligence(self, request: Request, response: Response, 
                                           request_intel: Dict[str, Any]):
        """
        Process response and trigger comprehensive intelligence analysis
        """
        processing_time = time.time() - request.state.start_time
        
        # Add response metadata to intelligence
        response_intel = {
            'status_code': response.status_code,
            'response_headers': dict(response.headers),
            'processing_time': processing_time
        }
        
        # Combine request and response intelligence
        full_intel = {**request_intel, 'response': response_intel}
        
        # Background intelligence processing
        asyncio.create_task(self._background_intelligence_processing(request, full_intel))
    
    async def _background_intelligence_processing(self, request: Request, intel_data: Dict[str, Any]):
        """
        Background task for comprehensive intelligence analysis
        """
        try:
            # Run full threat analysis
            analysis_result = await self.intelligence_engine.analyze_request(
                request, intel_data['correlation_id']
            )
            
            # Session correlation
            correlation_result = await self.correlation_engine.correlate_event(analysis_result)
            
            # Log high-threat events immediately
            if analysis_result.get('threat_score', 0) > 70:
                self.logger.warning(
                    f"High threat detected: {intel_data['correlation_id']} - "
                    f"Score: {analysis_result['threat_score']}, "
                    f"Type: {analysis_result['attack_type']}, "
                    f"IP: {intel_data['client_ip']}"
                )
                self.threat_detections += 1
            
        except Exception as e:
            self.logger.error(f"Background intelligence processing error: {e}")
    
    def _generate_correlation_id(self) -> str:
        """Generate high-performance correlation ID"""
        if HAS_C_ACCELERATION:
            # Use C-accelerated random generation if available
            timestamp = int(time.time() * 1000000)  # microseconds
            random_part = hash(uuid.uuid4().bytes) & 0xFFFFFF  # 24-bit random
            return f"ATK_{timestamp:012x}_{random_part:06x}"
        else:
            return SecurityHelpers.generate_correlation_id()
    
    def _extract_client_ip(self, request: Request) -> str:
        """Extract real client IP considering proxies"""
        # Check X-Forwarded-For header first
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            # Take first IP in chain (original client)
            return forwarded_for.split(',')[0].strip()
        
        # Check other proxy headers
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip.strip()
        
        # Fallback to direct connection
        return request.client.host if request.client else "unknown"
    
    def _analyze_headers(self, headers) -> Dict[str, Any]:
        """Fast header analysis"""
        suspicious_headers = []
        missing_headers = []
        
        # Check for suspicious headers
        suspicious_patterns = [
            'x-originating-ip', 'x-remote-ip', 'x-cluster-client-ip',
            'x-forwarded', 'forwarded-for', 'x-real-ip'
        ]
        
        for pattern in suspicious_patterns:
            if any(pattern in header.lower() for header in headers.keys()):
                suspicious_headers.append(pattern)
        
        # Check for missing standard headers
        expected_headers = ['accept', 'accept-language', 'accept-encoding', 'user-agent']
        for expected in expected_headers:
            if not any(expected in header.lower() for header in headers.keys()):
                missing_headers.append(expected)
        
        return {
            'count': len(headers),
            'suspicious': suspicious_headers,
            'missing': missing_headers,
            'has_custom_headers': any(header.startswith('x-') for header in headers.keys()),
            'user_agent_length': len(headers.get('user-agent', '')),
            'is_bot_like': len(missing_headers) > 2
        }
    
    def _analyze_url(self, url) -> Dict[str, Any]:
        """Fast URL analysis"""
        path = str(url.path)
        query = str(url.query) if url.query else ""
        
        return {
            'path_length': len(path),
            'path_depth': len([p for p in path.split('/') if p]),
            'has_query': len(query) > 0,
            'query_param_count': len(query.split('&')) if query else 0,
            'has_suspicious_chars': any(char in path + query for char in ['..', '%', '<', '>', '"', "'"]),
            'has_encoded_chars': '%' in path or '%' in query,
            'is_admin_path': any(admin in path.lower() for admin in ['/admin', '/wp-admin', '/login', '/management'])
        }
    
    async def _get_geo_intelligence(self, ip: str) -> Dict[str, Any]:
        """Get geographic intelligence for IP"""
        # Placeholder for geo intelligence
        # In production, integrate with MaxMind GeoIP or similar
        return {
            'country': 'unknown',
            'region': 'unknown',
            'city': 'unknown',
            'is_tor': False,
            'is_vpn': False,
            'is_hosting': False
        }
    
    def _is_rate_limited(self, client_ip: str) -> bool:
        """Check if client IP is rate limited"""
        current_time = time.time()
        window_start = current_time - self.rate_limit_window
        
        # Clean old entries
        if client_ip in self.rate_limit_state:
            self.rate_limit_state[client_ip] = [
                timestamp for timestamp in self.rate_limit_state[client_ip]
                if timestamp > window_start
            ]
        else:
            self.rate_limit_state[client_ip] = []
        
        # Check threshold
        if len(self.rate_limit_state[client_ip]) >= self.rate_limit_threshold:
            return True
        
        # Add current request
        self.rate_limit_state[client_ip].append(current_time)
        return False
    
    def _create_rate_limit_response(self) -> Response:
        """Create rate limit exceeded response"""
        return Response(
            content="Rate limit exceeded",
            status_code=429,
            headers={"Retry-After": "60"}
        )
    
    def _is_binary_content(self, data: bytes) -> bool:
        """Check if content is binary"""
        if not data:
            return False
        
        # Check for null bytes (common in binary)
        return b'\x00' in data[:1024]
    
    def _extract_content_preview(self, data: bytes) -> str:
        """Extract safe content preview"""
        if not data:
            return ""
        
        try:
            # Try UTF-8 decode with error handling
            preview = data[:200].decode('utf-8', errors='replace')
            # Remove control characters except newlines and tabs
            return ''.join(char for char in preview if ord(char) >= 32 or char in '\n\t')
        except Exception:
            return f"<binary data: {len(data)} bytes>"
    
    def _update_metrics(self, processing_time: float, threat_level: str):
        """Update performance metrics"""
        self.request_count += 1
        self.total_processing_time += processing_time
        
        if threat_level in ['high', 'critical']:
            self.threat_detections += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get middleware performance metrics"""
        avg_processing_time = (
            self.total_processing_time / self.request_count 
            if self.request_count > 0 else 0.0
        )
        
        return {
            'total_requests': self.request_count,
            'total_processing_time': self.total_processing_time,
            'average_processing_time': avg_processing_time,
            'threat_detections': self.threat_detections,
            'threat_detection_rate': (
                self.threat_detections / self.request_count 
                if self.request_count > 0 else 0.0
            ),
            'c_acceleration_enabled': HAS_C_ACCELERATION,
            'active_rate_limited_ips': len(self.rate_limit_state)
        }
    
    def reset_metrics(self):
        """Reset performance metrics"""
        self.request_count = 0
        self.total_processing_time = 0.0
        self.threat_detections = 0
