# middleware/capture.py

import time
import hashlib
import struct
import asyncio
import mmap
import threading
from typing import Dict, Any, Optional, List, Tuple, Union, Union
from dataclasses import dataclass, field
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import CDLL, c_char_p, c_int, c_uint64, c_uint32, c_double, POINTER, Structure, c_void_p
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from utils.logger import setup_logger
from core.config import get_config
from utils.helpers import SecurityHelpers

# C library integration for high-performance packet capture
try:
    # Load optimized C library for packet processing
    libcapture = CDLL("./lib/libfast_capture.so")
    
    # C structures for efficient data passing
    class PacketHeader(Structure):
        _fields_ = [
            ("timestamp_sec", c_uint64),
            ("timestamp_usec", c_uint32),
            ("packet_len", c_uint32),
            ("capture_len", c_uint32),
            ("protocol", c_uint32),
            ("src_ip", c_uint32),
            ("dst_ip", c_uint32),
            ("src_port", c_uint32),
            ("dst_port", c_uint32),
            ("flags", c_uint32)
        ]
    
    class CaptureBuffer(Structure):
        _fields_ = [
            ("data", c_void_p),
            ("size", c_uint32),
            ("capacity", c_uint32),
            ("write_offset", c_uint32),
            ("read_offset", c_uint32)
        ]
    
    # Define C function signatures
    libcapture.create_capture_buffer.argtypes = [c_uint32]
    libcapture.create_capture_buffer.restype = POINTER(CaptureBuffer)
    
    libcapture.write_packet.argtypes = [POINTER(CaptureBuffer), c_char_p, c_uint32, POINTER(PacketHeader)]
    libcapture.write_packet.restype = c_int
    
    libcapture.fast_packet_hash.argtypes = [c_char_p, c_uint32]
    libcapture.fast_packet_hash.restype = c_uint64
    
    libcapture.analyze_payload.argtypes = [c_char_p, c_uint32]
    libcapture.analyze_payload.restype = c_uint32
    
    libcapture.extract_http_fields.argtypes = [c_char_p, c_uint32, c_char_p, c_uint32]
    libcapture.extract_http_fields.restype = c_int
    
    HAS_C_CAPTURE = True
except (OSError, AttributeError):
    HAS_C_CAPTURE = False
    libcapture = None

@dataclass
class CapturedRequest:
    """Structured capture data for efficient processing"""
    correlation_id: str
    timestamp: float
    client_ip: str
    method: str
    path: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    body_hash: str = ""
    protocol_version: str = "HTTP/1.1"
    tls_info: Optional[Dict[str, Any]] = None
    raw_packet: Optional[bytes] = None
    packet_hash: Optional[int] = None
    processing_flags: int = 0

@dataclass
class CapturedResponse:
    """Response capture data"""
    correlation_id: str
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body_preview: str = ""
    content_length: int = 0
    processing_time: float = 0.0
    encoding: str = "utf-8"

class HighPerformanceBuffer:
    """Lock-free ring buffer for high-throughput capture"""
    
    def __init__(self, size: int = 1048576):  # 1MB default
        self.size = size
        self.buffer = bytearray(size)
        self.write_pos = 0
        self.read_pos = 0
        self.wrapped = False
        self._lock = threading.RLock()
        
        # Memory-mapped buffer for ultra-fast writes
        try:
            self.mmap_buffer = mmap.mmap(-1, size)
            self.use_mmap = True
        except OSError:
            self.use_mmap = False
    
    def write(self, data: bytes) -> bool:
        """Thread-safe write with overflow protection"""
        data_len = len(data)
        
        with self._lock:
            # Check if we have space
            available = self._available_space()
            if data_len > available:
                # Advance read pointer to make space
                self._advance_read_pointer(data_len - available)
            
            # Write data, handling wrap-around
            if self.write_pos + data_len <= self.size:
                if self.use_mmap:
                    self.mmap_buffer[self.write_pos:self.write_pos + data_len] = data
                else:
                    self.buffer[self.write_pos:self.write_pos + data_len] = data
                self.write_pos += data_len
            else:
                # Split write across wrap boundary
                first_part = self.size - self.write_pos
                second_part = data_len - first_part
                
                if self.use_mmap:
                    self.mmap_buffer[self.write_pos:] = data[:first_part]
                    self.mmap_buffer[:second_part] = data[first_part:]
                else:
                    self.buffer[self.write_pos:] = data[:first_part]
                    self.buffer[:second_part] = data[first_part:]
                
                self.write_pos = second_part
                self.wrapped = True
        
        return True
    
    def _available_space(self) -> int:
        """Calculate available buffer space"""
        if not self.wrapped and self.write_pos >= self.read_pos:
            return self.size - (self.write_pos - self.read_pos)
        elif self.wrapped:
            return self.read_pos - self.write_pos
        else:
            return self.size - (self.write_pos - self.read_pos)
    
    def _advance_read_pointer(self, bytes_needed: int):
        """Advance read pointer to free space"""
        self.read_pos = (self.read_pos + bytes_needed) % self.size
        if self.read_pos < self.write_pos:
            self.wrapped = False

class CaptureMiddleware(BaseHTTPMiddleware):
    """
    High-performance traffic capture middleware with C acceleration
    Captures all HTTP traffic for forensic analysis and threat detection
    """
    
    def __init__(self, app, 
                 buffer_size: int = 10485760,  # 10MB buffer
                 max_body_capture: int = 1048576,  # 1MB max body
                 enable_raw_capture: bool = True,
                 pcap_output: Optional[str] = None):
        super().__init__(app)
        self.logger = setup_logger()
        self.config = get_config()
        
        # Configuration
        self.buffer_size = buffer_size
        self.max_body_capture = max_body_capture
        self.enable_raw_capture = enable_raw_capture
        self.pcap_output = pcap_output
        
        # High-performance buffers
        self.request_buffer = HighPerformanceBuffer(buffer_size)
        self.response_buffer = HighPerformanceBuffer(buffer_size)
        
        # C acceleration setup
        if HAS_C_CAPTURE:
            self.c_buffer = libcapture.create_capture_buffer(buffer_size)
            self.logger.info("C acceleration enabled for packet capture")
        else:
            self.c_buffer = None
            self.logger.info("C acceleration not available, using Python implementation")
        
        # Capture statistics
        self.stats = {
            'total_requests': 0,
            'total_responses': 0,
            'bytes_captured': 0,
            'packets_processed': 0,
            'capture_errors': 0,
            'buffer_overflows': 0,
            'processing_time': 0.0
        }
        
        # Background processing
        self.processing_queue = deque(maxlen=10000)
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="capture-worker")
        self.background_task = None
        
        # Start background processing
        self._start_background_processing()
        
        self.logger.info(f"Capture middleware initialized - Buffer: {buffer_size/1024/1024:.1f}MB, "
                        f"Max body: {max_body_capture/1024:.1f}KB, Raw capture: {enable_raw_capture}")
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Main dispatch with comprehensive traffic capture"""
        start_time = time.time()
        correlation_id = getattr(request.state, 'correlation_id', SecurityHelpers.generate_correlation_id())
        
        try:
            # Capture request
            captured_request = await self._capture_request(request, correlation_id)
            
            # Store in request state for other middleware
            request.state.captured_request = captured_request
            
            # Process through next middleware/handler
            response = await call_next(request)
            
            # Capture response
            captured_response = await self._capture_response(response, correlation_id, start_time)
            
            # Queue for background processing
            self._queue_for_processing(captured_request, captured_response)
            
            # Update statistics
            self._update_stats(captured_request, captured_response, time.time() - start_time)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Capture middleware error: {e}")
            self.stats['capture_errors'] += 1
            # Continue processing even on capture failure
            return await call_next(request)
    
    async def _capture_request(self, request: Request, correlation_id: str) -> CapturedRequest:
        """Comprehensive request capture with C acceleration"""
        timestamp = time.time()
        
        # Extract basic request data
        client_ip = self._extract_client_ip(request)
        method = request.method
        path = str(request.url.path)
        headers = dict(request.headers)
        
        # Capture body efficiently
        body = await self._capture_body(request)
        
        # Generate hashes
        if HAS_C_CAPTURE and body:
            # Use C acceleration for fast hashing
            packet_hash = libcapture.fast_packet_hash(body, len(body))
            body_hash = hashlib.sha256(body).hexdigest()
        else:
            packet_hash = hash(body) if body else 0
            body_hash = hashlib.sha256(body).hexdigest() if body else ""
        
        # Create structured capture
        captured = CapturedRequest(
            correlation_id=correlation_id,
            timestamp=timestamp,
            client_ip=client_ip,
            method=method,
            path=path,
            headers=headers,
            body=body,
            body_hash=body_hash,
            packet_hash=packet_hash
        )
        
        # Raw packet capture if enabled
        if self.enable_raw_capture:
            raw_packet = await self._create_raw_packet(request, body)
            captured.raw_packet = raw_packet
            
            # Write to C buffer if available
            if HAS_C_CAPTURE and self.c_buffer and raw_packet:
                packet_header = self._create_packet_header(captured, raw_packet)
                result = libcapture.write_packet(
                    self.c_buffer, 
                    raw_packet, 
                    len(raw_packet), 
                    ctypes.byref(packet_header)
                )
                if result == 0:
                    self.stats['buffer_overflows'] += 1
        
        # Write to high-performance buffer
        serialized = self._serialize_request(captured)
        self.request_buffer.write(serialized)
        
        return captured
    
    async def _capture_response(self, response: Response, correlation_id: str, start_time: float) -> CapturedResponse:
        """Capture response data with minimal performance impact"""
        processing_time = time.time() - start_time
        
        # Extract response headers
        headers = dict(response.headers)
        content_length = int(headers.get('content-length', 0))
        
        # Capture response body preview (limited for performance)
        body_preview = ""
        if hasattr(response, 'body') and response.body:
            preview_data = response.body[:500] if isinstance(response.body, bytes) else str(response.body)[:500]
            try:
                body_preview = preview_data.decode('utf-8', errors='ignore') if isinstance(preview_data, bytes) else preview_data
            except Exception:
                body_preview = f"<binary data: {len(preview_data)} bytes>"
        
        captured = CapturedResponse(
            correlation_id=correlation_id,
            status_code=response.status_code,
            headers=headers,
            body_preview=body_preview,
            content_length=content_length,
            processing_time=processing_time,
            encoding=headers.get('content-encoding', 'utf-8')
        )
        
        # Write to response buffer
        serialized = self._serialize_response(captured)
        self.response_buffer.write(serialized)
        
        return captured
    
    async def _capture_body(self, request: Request) -> bytes:
        """Efficiently capture request body with size limits"""
        try:
            body = await request.body()
            
            # Enforce size limit
            if len(body) > self.max_body_capture:
                self.logger.warning(f"Body truncated: {len(body)} -> {self.max_body_capture} bytes")
                body = body[:self.max_body_capture]
            
            return body
            
        except Exception as e:
            self.logger.error(f"Body capture error: {e}")
            return b""
    
    async def _create_raw_packet(self, request: Request, body: bytes) -> bytes:
        """Create raw packet representation for PCAP-style analysis"""
        try:
            # Construct pseudo-HTTP packet
            request_line = f"{request.method} {request.url.path}"
            if request.url.query:
                request_line += f"?{request.url.query}"
            request_line += f" HTTP/1.1\r\n"
            
            # Add headers
            header_lines = []
            for name, value in request.headers.items():
                header_lines.append(f"{name}: {value}\r\n")
            
            # Combine all parts
            raw_packet = request_line.encode('utf-8')
            raw_packet += "".join(header_lines).encode('utf-8')
            raw_packet += b"\r\n"  # Empty line before body
            raw_packet += body
            
            return raw_packet
            
        except Exception as e:
            self.logger.error(f"Raw packet creation error: {e}")
            return b""
    
    def _create_packet_header(self, captured: CapturedRequest, raw_packet: bytes) -> Any:
        """Create C packet header structure"""
        header = PacketHeader()
        
        timestamp_sec = int(captured.timestamp)
        timestamp_usec = int((captured.timestamp - timestamp_sec) * 1000000)
        
        header.timestamp_sec = timestamp_sec
        header.timestamp_usec = timestamp_usec
        header.packet_len = len(raw_packet)
        header.capture_len = min(len(raw_packet), 65535)  # Max capture size
        header.protocol = 6  # TCP
        
        # IP parsing (simplified)
        try:
            ip_parts = captured.client_ip.split('.')
            if len(ip_parts) == 4:
                header.src_ip = sum(int(part) << (8 * (3 - i)) for i, part in enumerate(ip_parts))
        except Exception:
            header.src_ip = 0
        
        header.dst_ip = 0x7f000001  # localhost
        header.src_port = 0  # Unknown
        header.dst_port = 80 if 'https' not in str(captured.headers.get('host', '')) else 443
        header.flags = 0x18  # PSH+ACK
        
        return header
    
    def _serialize_request(self, captured: CapturedRequest) -> bytes:
        """Serialize captured request for buffer storage"""
        try:
            # Create compact binary format
            data = {
                'id': captured.correlation_id,
                'ts': captured.timestamp,
                'ip': captured.client_ip,
                'method': captured.method,
                'path': captured.path,
                'headers': captured.headers,
                'body_hash': captured.body_hash,
                'body_size': len(captured.body),
                'packet_hash': captured.packet_hash or 0
            }
            
            # Simple binary serialization
            import json
            json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
            
            # Prefix with length for parsing
            length = struct.pack('!I', len(json_data))
            return length + json_data
            
        except Exception as e:
            self.logger.error(f"Request serialization error: {e}")
            return b""
    
    def _serialize_response(self, captured: CapturedResponse) -> bytes:
        """Serialize captured response for buffer storage"""
        try:
            data = {
                'id': captured.correlation_id,
                'status': captured.status_code,
                'headers': captured.headers,
                'body_preview': captured.body_preview,
                'content_length': captured.content_length,
                'processing_time': captured.processing_time
            }
            
            import json
            json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
            length = struct.pack('!I', len(json_data))
            return length + json_data
            
        except Exception as e:
            self.logger.error(f"Response serialization error: {e}")
            return b""
    
    def _extract_client_ip(self, request: Request) -> str:
        """Extract real client IP considering proxies and load balancers"""
        # Priority order for IP extraction
        ip_headers = [
            'x-forwarded-for',
            'x-real-ip', 
            'x-originating-ip',
            'x-cluster-client-ip',
            'forwarded'
        ]
        
        for header in ip_headers:
            value = request.headers.get(header)
            if value:
                # Handle comma-separated IPs (take first one)
                ip = value.split(',')[0].strip()
                if self._is_valid_ip(ip):
                    return ip
        
        # Fallback to direct connection
        return request.client.host if request.client else "unknown"
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP address validation"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False
    
    def _queue_for_processing(self, request: CapturedRequest, response: CapturedResponse):
        """Queue captured data for background processing"""
        try:
            self.processing_queue.append((request, response))
        except Exception as e:
            self.logger.error(f"Queue error: {e}")
    
    def _start_background_processing(self):
        """Start background processing task"""
        def background_worker():
            while True:
                try:
                    if self.processing_queue:
                        # Process batch of items
                        batch = []
                        for _ in range(min(100, len(self.processing_queue))):
                            if self.processing_queue:
                                batch.append(self.processing_queue.popleft())
                        
                        if batch:
                            self._process_capture_batch(batch)
                    
                    time.sleep(0.1)  # Brief pause to prevent CPU spinning
                    
                except Exception as e:
                    self.logger.error(f"Background processing error: {e}")
                    time.sleep(1)  # Longer pause on error
        
        # Start background thread
        background_thread = threading.Thread(target=background_worker, daemon=True)
        background_thread.start()
    
    def _process_capture_batch(self, batch: List[Tuple[CapturedRequest, CapturedResponse]]):
        """Process batch of captured traffic"""
        try:
            # Advanced analysis using C acceleration if available
            if HAS_C_CAPTURE:
                for request, response in batch:
                    if request.body:
                        # Analyze payload for threats
                        threat_flags = libcapture.analyze_payload(request.body, len(request.body))
                        request.processing_flags = threat_flags
            
            # Log high-value captures
            for request, response in batch:
                if self._is_high_value_capture(request, response):
                    self.logger.info(
                        f"High-value capture: {request.correlation_id} - "
                        f"{request.method} {request.path} -> {response.status_code} "
                        f"({len(request.body)} bytes, {response.processing_time:.3f}s)"
                    )
            
        except Exception as e:
            self.logger.error(f"Batch processing error: {e}")
    
    def _is_high_value_capture(self, request: CapturedRequest, response: CapturedResponse) -> bool:
        """Determine if capture is high-value for analysis"""
        # High-value indicators
        indicators = [
            len(request.body) > 10000,  # Large payloads
            response.status_code in [401, 403, 404, 500],  # Error responses
            'admin' in request.path.lower(),  # Admin paths
            'login' in request.path.lower(),  # Login attempts
            request.method in ['PUT', 'DELETE', 'PATCH'],  # Modification methods
            any(header.lower().startswith('x-') for header in request.headers),  # Custom headers
            response.processing_time > 2.0,  # Slow responses
            bool(request.processing_flags)  # C-detected threats
        ]
        
        return sum(indicators) >= 2
    
    def _update_stats(self, request: CapturedRequest, response: CapturedResponse, processing_time: float):
        """Update capture statistics"""
        self.stats['total_requests'] += 1
        self.stats['total_responses'] += 1
        self.stats['bytes_captured'] += len(request.body)
        self.stats['packets_processed'] += 1 if request.raw_packet else 0
        self.stats['processing_time'] += processing_time
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive capture statistics"""
        return {
            **self.stats,
            'buffer_usage': {
                'request_buffer_size': self.buffer_size,
                'response_buffer_size': self.buffer_size,
                'queue_length': len(self.processing_queue),
                'c_acceleration': HAS_C_CAPTURE
            },
            'performance': {
                'avg_processing_time': (
                    self.stats['processing_time'] / max(self.stats['total_requests'], 1)
                ),
                'capture_rate': self.stats['total_requests'] / max(time.time() - 0, 1),  # Requests per second
                'error_rate': self.stats['capture_errors'] / max(self.stats['total_requests'], 1)
            }
        }
    
    def export_captures(self, format: str = 'json', limit: int = 1000) -> bytes:
        """Export captured data in various formats"""
        # Implementation for exporting captures
        # This would read from buffers and format appropriately
        return b'{"message": "Export functionality not yet implemented"}'
    
    def flush_buffers(self):
        """Flush all capture buffers"""
        self.request_buffer = HighPerformanceBuffer(self.buffer_size)
        self.response_buffer = HighPerformanceBuffer(self.buffer_size)
        self.processing_queue.clear()
        self.logger.info("Capture buffers flushed")
    
    def __del__(self):
        """Cleanup resources"""
        if self.executor:
            self.executor.shutdown(wait=False)
