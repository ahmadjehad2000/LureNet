# middleware/deception.py

import time
import random
import hashlib
import struct
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import ctypes
from ctypes import CDLL, c_char_p, c_int, c_uint32, c_uint64, c_double, POINTER, Structure

from utils.logger import setup_logger
from core.config import get_config

# C library for high-speed deception operations
try:
    libdeception = CDLL("./lib/libfast_deception.so")
    
    class DeceptionProfile(Structure):
        _fields_ = [
            ("server_type", c_uint32),
            ("response_delay", c_uint32),
            ("error_rate", c_double),
            ("header_mask", c_uint64),
            ("behavior_flags", c_uint32)
        ]
    
    # C function signatures
    libdeception.generate_server_header.argtypes = [c_uint32, c_char_p, c_int]
    libdeception.generate_server_header.restype = c_int
    
    libdeception.calculate_delay.argtypes = [POINTER(DeceptionProfile), c_uint32]
    libdeception.calculate_delay.restype = c_double
    
    libdeception.should_inject_error.argtypes = [c_double, c_uint32]
    libdeception.should_inject_error.restype = c_int
    
    HAS_C_DECEPTION = True
except (OSError, AttributeError):
    HAS_C_DECEPTION = False
    libdeception = None

@dataclass
class DeceptionConfig:
    """Optimized deception configuration"""
    server_types: List[str] = None
    error_injection_rate: float = 0.15
    response_delay_range: Tuple[float, float] = (0.1, 2.0)
    fake_headers_enabled: bool = True
    honeypot_fields_enabled: bool = True
    admin_trap_paths: List[str] = None
    
    def __post_init__(self):
        if not self.server_types:
            self.server_types = ['nginx/1.18.0', 'Apache/2.4.41', 'IIS/10.0', 'lighttpd/1.4.55']
        if not self.admin_trap_paths:
            self.admin_trap_paths = ['/admin', '/wp-admin', '/phpmyadmin', '/administrator']

class DeceptionMiddleware(BaseHTTPMiddleware):
    """Ultra-fast deception middleware with C acceleration"""
    
    def __init__(self, app, config: Optional[DeceptionConfig] = None):
        super().__init__(app)
        self.logger = setup_logger()
        self.config = config or DeceptionConfig()
        
        # Pre-computed deception data for speed
        self._server_headers = self._precompute_server_headers()
        self._fake_cookies = self._precompute_fake_cookies()
        self._honeypot_responses = self._precompute_honeypot_responses()
        
        # C deception profile
        if HAS_C_DECEPTION:
            self.c_profile = DeceptionProfile()
            self.c_profile.server_type = hash(''.join(self.config.server_types)) & 0xFFFFFFFF
            self.c_profile.response_delay = int(sum(self.config.response_delay_range) * 500)
            self.c_profile.error_rate = self.config.error_injection_rate
            self.c_profile.header_mask = 0xFFFFFFFFFFFFFFFF
            self.c_profile.behavior_flags = 0x1 if self.config.fake_headers_enabled else 0x0
        
        # Performance counters
        self.deceptions_applied = 0
        self.traps_triggered = 0
        self.processing_time = 0.0
        
        self.logger.info(f"Deception engine loaded - C acceleration: {HAS_C_DECEPTION}")
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """High-speed deception dispatch"""
        start_time = time.perf_counter()
        
        # Fast path check - skip deception for static assets
        if self._is_static_asset(request.url.path):
            return await call_next(request)
        
        # Apply request-level deceptions
        await self._apply_request_deceptions(request)
        
        # Check for honeypot traps
        trap_response = self._check_honeypot_traps(request)
        if trap_response:
            self.traps_triggered += 1
            return trap_response
        
        # Process through application
        response = await call_next(request)
        
        # Apply response-level deceptions
        response = await self._apply_response_deceptions(request, response)
        
        # Update metrics
        self.processing_time += time.perf_counter() - start_time
        self.deceptions_applied += 1
        
        return response
    
    def _is_static_asset(self, path: str) -> bool:
        """Ultra-fast static asset detection"""
        return path.endswith(('.css', '.js', '.png', '.jpg', '.gif', '.ico', '.woff', '.woff2'))
    
    async def _apply_request_deceptions(self, request: Request):
        """Apply deceptions to incoming request"""
        # Inject fake request tracking
        if self.config.honeypot_fields_enabled:
            request.state.honeypot_id = self._generate_session_id()
            request.state.fake_csrf = self._generate_csrf_token()
    
    def _check_honeypot_traps(self, request: Request) -> Optional[Response]:
        """Lightning-fast honeypot trap detection"""
        path = request.url.path.lower()
        
        # Admin path traps
        for trap_path in self.config.admin_trap_paths:
            if path.startswith(trap_path):
                return self._create_admin_trap_response(request)
        
        # Common exploit paths
        exploit_patterns = ['.env', 'shell.php', 'config.php', 'backup.sql', 'wp-config.php']
        if any(pattern in path for pattern in exploit_patterns):
            return self._create_exploit_trap_response(request)
        
        # Bot detection traps
        if path in ['/robots.txt', '/sitemap.xml'] and 'bot' not in request.headers.get('user-agent', '').lower():
            return self._create_bot_trap_response(request)
        
        return None
    
    async def _apply_response_deceptions(self, request: Request, response: Response) -> Response:
        """Apply response-level deceptions with C acceleration"""
        
        # Fast server header injection
        if self.config.fake_headers_enabled:
            if HAS_C_DECEPTION:
                # Use C acceleration for header generation
                header_buffer = ctypes.create_string_buffer(256)
                header_len = libdeception.generate_server_header(
                    self.c_profile.server_type, header_buffer, 256
                )
                if header_len > 0:
                    server_header = header_buffer.value.decode('utf-8')
                else:
                    server_header = random.choice(self._server_headers)
            else:
                server_header = random.choice(self._server_headers)
            
            response.headers['server'] = server_header
            response.headers.update(random.choice(self._fake_cookies))
        
        # Error injection with C acceleration
        if HAS_C_DECEPTION:
            request_hash = hash(str(request.url)) & 0xFFFFFFFF
            should_inject = libdeception.should_inject_error(
                self.config.error_injection_rate, request_hash
            )
            if should_inject and response.status_code == 200:
                response.status_code = random.choice([500, 502, 503])
        elif random.random() < self.config.error_injection_rate and response.status_code == 200:
            response.status_code = random.choice([500, 502, 503])
        
        # Response delay with C calculation
        if HAS_C_DECEPTION:
            delay = libdeception.calculate_delay(
                ctypes.byref(self.c_profile), 
                hash(str(request.url)) & 0xFFFFFFFF
            )
            if delay > 0:
                import asyncio
                await asyncio.sleep(delay)
        else:
            delay = random.uniform(*self.config.response_delay_range)
            if delay > 0.05:  # Only delay if significant
                import asyncio
                await asyncio.sleep(delay)
        
        return response
    
    def _create_admin_trap_response(self, request: Request) -> Response:
        """Create convincing admin panel trap"""
        fake_login = random.choice(self._honeypot_responses['admin'])
        
        # Log the trap trigger
        self.logger.warning(f"Admin trap triggered: {request.client.host} -> {request.url.path}")
        
        return Response(
            content=fake_login,
            status_code=200,
            headers={
                'content-type': 'text/html; charset=utf-8',
                'server': random.choice(self._server_headers),
                'set-cookie': f'PHPSESSID={self._generate_session_id()}; path=/',
                'x-powered-by': 'PHP/7.4.3'
            }
        )
    
    def _create_exploit_trap_response(self, request: Request) -> Response:
        """Create exploit attempt trap"""
        # Log the exploit attempt
        self.logger.critical(f"Exploit trap: {request.client.host} -> {request.url.path}")
        
        # Return fake vulnerable response
        fake_content = random.choice(self._honeypot_responses['exploit'])
        
        return Response(
            content=fake_content,
            status_code=200,
            headers={'content-type': 'text/plain', 'server': 'Apache/2.4.41'}
        )
    
    def _create_bot_trap_response(self, request: Request) -> Response:
        """Create bot detection trap"""
        if request.url.path == '/robots.txt':
            # Fake robots.txt with honeypot paths
            content = "User-agent: *\nDisallow: /admin/\nDisallow: /secret/\nDisallow: /hidden/"
        else:
            # Fake sitemap with trap URLs
            content = '<?xml version="1.0"?><urlset><url><loc>http://example.com/admin/</loc></url></urlset>'
        
        return Response(content=content, status_code=200, headers={'content-type': 'text/plain'})
    
    def _precompute_server_headers(self) -> List[str]:
        """Pre-compute server headers for performance"""
        return self.config.server_types + [
            'Microsoft-IIS/8.5', 'nginx/1.16.1', 'Apache/2.4.29',
            'cloudflare', 'AmazonS3', 'Tengine/2.3.2'
        ]
    
    def _precompute_fake_cookies(self) -> List[Dict[str, str]]:
        """Pre-compute fake cookie sets"""
        return [
            {'x-cache': 'HIT', 'x-cache-hits': '1'},
            {'x-served-by': 'cache-lax1427-LAX'},
            {'x-timer': 'S1234567890.123456,VS0,VE12'},
            {'cf-ray': f'{random.randint(100000000000, 999999999999)}-LAX'},
            {'x-amz-cf-id': self._generate_session_id()[:20]},
        ]
    
    def _precompute_honeypot_responses(self) -> Dict[str, List[str]]:
        """Pre-compute honeypot response templates"""
        return {
            'admin': [
                '<html><head><title>Admin Login</title></head><body><form><input name="username"><input name="password" type="password"><button>Login</button></form></body></html>',
                '<!DOCTYPE html><html><body><h1>Administration Panel</h1><p>Please log in to continue.</p></body></html>',
                '<form method="post"><input placeholder="Username" name="user"><input placeholder="Password" type="password" name="pass"><input type="submit" value="Sign In"></form>'
            ],
            'exploit': [
                'root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin',
                'DB_HOST=localhost\nDB_USER=admin\nDB_PASS=password123\nDB_NAME=production',
                '<?php phpinfo(); ?>',
                'MySQL Error: Access denied for user "admin"@"localhost"'
            ]
        }
    
    def _generate_session_id(self) -> str:
        """Generate realistic session ID"""
        return hashlib.md5(f"{time.time()}{random.randint(1000, 9999)}".encode()).hexdigest()
    
    def _generate_csrf_token(self) -> str:
        """Generate fake CSRF token"""
        return hashlib.sha256(f"{time.time()}{random.randint(10000, 99999)}".encode()).hexdigest()[:32]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get deception statistics"""
        return {
            'deceptions_applied': self.deceptions_applied,
            'traps_triggered': self.traps_triggered,
            'avg_processing_time': (
                self.processing_time / max(self.deceptions_applied, 1)
            ),
            'c_acceleration': HAS_C_DECEPTION,
            'config': {
                'error_rate': self.config.error_injection_rate,
                'fake_headers': self.config.fake_headers_enabled,
                'honeypot_fields': self.config.honeypot_fields_enabled,
                'server_types_count': len(self.config.server_types)
            }
        }
    
    def update_config(self, new_config: DeceptionConfig):
        """Hot-reload deception configuration"""
        self.config = new_config
        self._server_headers = self._precompute_server_headers()
        self._fake_cookies = self._precompute_fake_cookies()
        self._honeypot_responses = self._precompute_honeypot_responses()
        self.logger.info("Deception configuration updated")
