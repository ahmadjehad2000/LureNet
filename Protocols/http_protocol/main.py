# main.py
"""
Lurenet HTTP Honeypot - Main Application
Advanced modular honeypot platform with threat intelligence and deception capabilities
"""

import asyncio
import signal
import sys
import os
import time
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional
import uvicorn
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import click

# Core imports
from middleware.intelligence import IntelligenceMiddleware
from middleware.capture import CaptureMiddleware
from middleware.deception import DeceptionMiddleware, DeceptionConfig
from core.intelligence import get_intelligence_engine
from core.response_engine import ResponseEngine
from core.correlation import SessionTracker
from config.config_loader import ProfileManager, get_profile_manager
from utils.logger import setup_logger
from utils.helpers import SecurityHelpers

class HoneypotApplication:
    """Main honeypot application orchestrator"""
    
    def __init__(self, config_dir: str = "config", port: int = 8080, host: str = "0.0.0.0"):
        self.config_dir = Path(config_dir)
        self.host = host
        self.port = port
        self.logger = setup_logger()
        
        # Core components
        self.app: Optional[FastAPI] = None
        self.profile_manager: Optional[ProfileManager] = None
        self.response_engine: Optional[ResponseEngine] = None
        self.session_tracker: Optional[SessionTracker] = None
        
        # Middleware instances
        self.intelligence_middleware: Optional[IntelligenceMiddleware] = None
        self.capture_middleware: Optional[CaptureMiddleware] = None
        self.deception_middleware: Optional[DeceptionMiddleware] = None
        
        # Application state
        self.start_time = time.time()
        self.is_running = False
        self.stats = {
            'total_requests': 0,
            'threat_detections': 0,
            'honeypot_hits': 0,
            'sessions_tracked': 0
        }
        
        self.logger.info("🍯 Lurenet HTTP Honeypot initializing...")
    
    def initialize_components(self):
        """Initialize all honeypot components"""
        try:
            # Core components
            self.profile_manager = get_profile_manager()
            self.response_engine = ResponseEngine(str(self.config_dir / "profiles"))
            self.session_tracker = SessionTracker(correlation_window=3600)
            
            # Validate configuration
            self._validate_configuration()
            
            self.logger.info("✅ Core components initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Component initialization failed: {e}")
            raise
    
    def create_application(self) -> FastAPI:
        """Create and configure FastAPI application with middleware stack"""
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            """Application lifespan manager"""
            # Startup
            self.logger.info("🚀 Honeypot starting up...")
            self.is_running = True
            
            # Initialize background tasks
            asyncio.create_task(self._background_statistics_updater())
            asyncio.create_task(self._periodic_threat_summary())
            
            yield
            
            # Shutdown
            self.logger.info("🛑 Honeypot shutting down...")
            self.is_running = False
            await self._cleanup_resources()
        
        # Create FastAPI app
        app = FastAPI(
            title="Lurenet HTTP Honeypot",
            description="Advanced modular honeypot platform for malware research",
            version="1.0.0",
            docs_url=None,  # Disable docs in production
            redoc_url=None,
            lifespan=lifespan
        )
        
        # Configure CORS (restrictive for security)
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000"],  # Only allow specific origins
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["*"],
        )
        
        # Add middleware stack (order matters!)
        self._add_middleware_stack(app)
        
        # Add route handlers
        self._register_routes(app)
        
        # Add exception handlers
        self._add_exception_handlers(app)
        
        self.app = app
        return app
    
    def _add_middleware_stack(self, app: FastAPI):
        """Add middleware in correct order (last added = first executed)"""
        
        # 1. Deception middleware (outermost - first to process requests)
        deception_config = DeceptionConfig(
            error_injection_rate=0.05,
            response_delay_range=(0.1, 0.8),
            fake_headers_enabled=True,
            honeypot_fields_enabled=True
        )
        self.deception_middleware = DeceptionMiddleware(app, deception_config)
        app.add_middleware(DeceptionMiddleware, config=deception_config)
        
        # 2. Capture middleware (captures all traffic)
        self.capture_middleware = CaptureMiddleware(
            app,
            buffer_size=50*1024*1024,  # 50MB buffer
            max_body_capture=10*1024*1024,  # 10MB max body
            enable_raw_capture=True
        )
        app.add_middleware(
            CaptureMiddleware,
            buffer_size=50*1024*1024,
            max_body_capture=10*1024*1024,
            enable_raw_capture=True
        )
        
        # 3. Intelligence middleware (innermost - analyzes everything)
        self.intelligence_middleware = IntelligenceMiddleware(
            app,
            max_body_size=10*1024*1024
        )
        app.add_middleware(IntelligenceMiddleware, max_body_size=10*1024*1024)
        
        self.logger.info("🔧 Middleware stack configured")
    
    def _register_routes(self, app: FastAPI):
        """Register all route handlers"""
        
        @app.middleware("http")
        async def main_request_handler(request: Request, call_next):
            """Main request processing middleware"""
            try:
                # Get correlation ID from state (set by intelligence middleware)
                correlation_id = getattr(request.state, 'correlation_id', SecurityHelpers.generate_correlation_id())
                
                # Get threat analysis data
                threat_data = getattr(request.state, 'intelligence', {})
                
                # Generate response using response engine
                response = await self.response_engine.generate_response(request, threat_data)
                
                # Update statistics
                self.stats['total_requests'] += 1
                if threat_data.get('threat_score', 0) > 50:
                    self.stats['threat_detections'] += 1
                
                # Check if this is a honeypot hit
                if self._is_honeypot_hit(request, threat_data):
                    self.stats['honeypot_hits'] += 1
                    self.logger.warning(f"🍯 Honeypot hit: {correlation_id} - {request.client.host} -> {request.url.path}")
                
                # Return the generated response
                if isinstance(response, tuple):
                    content, status_code, headers = response
                    if isinstance(content, (HTMLResponse, JSONResponse, PlainTextResponse)):
                        return content
                    elif isinstance(content, str):
                        return HTMLResponse(content=content, status_code=status_code, headers=headers)
                    else:
                        return Response(content=str(content), status_code=status_code, headers=headers)
                else:
                    return response
                    
            except Exception as e:
                self.logger.error(f"Request processing error: {e}")
                return HTMLResponse(
                    content="<h1>500 Internal Server Error</h1>",
                    status_code=500
                )
        
        # Catch-all route for unhandled paths
        @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        async def catch_all(request: Request, path: str):
            """Catch-all handler - should rarely be reached due to middleware"""
            return HTMLResponse(
                content="<h1>404 Not Found</h1><p>The requested resource was not found.</p>",
                status_code=404
            )
        
        # Health check endpoint (for monitoring)
        @app.get("/_health")
        async def health_check():
            """Health check endpoint"""
            uptime = time.time() - self.start_time
            return JSONResponse({
                "status": "healthy",
                "uptime_seconds": int(uptime),
                "version": "1.0.0",
                "components": {
                    "intelligence": self.intelligence_middleware is not None,
                    "capture": self.capture_middleware is not None,
                    "deception": self.deception_middleware is not None
                }
            })
        
        # Statistics endpoint (protected)
        @app.get("/_stats")
        async def statistics(request: Request):
            """Get honeypot statistics (protected endpoint)"""
            # Simple authentication check
            auth_header = request.headers.get("authorization")
            if auth_header != "Bearer honeypot-admin-token":
                raise HTTPException(status_code=401, detail="Unauthorized")
            
            uptime = time.time() - self.start_time
            stats = {
                **self.stats,
                "uptime_seconds": int(uptime),
                "requests_per_second": self.stats['total_requests'] / max(uptime, 1),
                "threat_detection_rate": (
                    self.stats['threat_detections'] / max(self.stats['total_requests'], 1)
                ),
                "middleware_stats": {
                    "intelligence": self.intelligence_middleware.get_metrics() if self.intelligence_middleware else {},
                    "capture": self.capture_middleware.get_stats() if self.capture_middleware else {},
                    "deception": self.deception_middleware.get_stats() if self.deception_middleware else {}
                }
            }
            return JSONResponse(stats)
        
        self.logger.info("🛣️  Routes registered")
    
    def _add_exception_handlers(self, app: FastAPI):
        """Add custom exception handlers"""
        
        @app.exception_handler(404)
        async def not_found_handler(request: Request, exc):
            """Custom 404 handler"""
            profile = self.response_engine.get_profile()
            content = profile.get_error_page('404', 
                path=request.url.path, 
                host=request.headers.get('host', 'localhost'),
                port='80'
            )
            return HTMLResponse(content=content, status_code=404)
        
        @app.exception_handler(500)
        async def internal_error_handler(request: Request, exc):
            """Custom 500 handler"""
            profile = self.response_engine.get_profile()
            content = profile.get_error_page('500',
                path=request.url.path,
                host=request.headers.get('host', 'localhost'),
                port='80'
            )
            return HTMLResponse(content=content, status_code=500)
        
        self.logger.info("🚨 Exception handlers configured")
    
    def _validate_configuration(self):
        """Validate honeypot configuration"""
        required_dirs = [
            self.config_dir,
            self.config_dir / "profiles",
            Path("logs"),
            Path("data")
        ]
        
        for directory in required_dirs:
            if not directory.exists():
                directory.mkdir(parents=True, exist_ok=True)
                self.logger.warning(f"Created missing directory: {directory}")
        
        # Check profile files
        profile_files = list((self.config_dir / "profiles").glob("*.yaml"))
        if not profile_files:
            self.logger.error("No server profiles found! Please ensure profile files exist.")
            raise FileNotFoundError("No server profiles configured")
        
        self.logger.info(f"✅ Configuration validated - {len(profile_files)} profiles loaded")
    
    def _is_honeypot_hit(self, request: Request, threat_data: Dict[str, Any]) -> bool:
        """Determine if request is a honeypot hit"""
        indicators = [
            threat_data.get('threat_score', 0) > 60,
            any(admin in request.url.path.lower() for admin in ['/admin', '/wp-admin', '/phpmyadmin']),
            any(exploit in request.url.path.lower() for exploit in ['.env', 'shell.php', 'config.php']),
            threat_data.get('attack_type') in ['sql_injection', 'xss', 'command_injection'],
            len(threat_data.get('tool_analysis', {}).get('detected_tools', [])) > 0
        ]
        
        return sum(indicators) >= 2
    
    async def _background_statistics_updater(self):
        """Background task to update statistics"""
        while self.is_running:
            try:
                # Update session statistics
                if self.session_tracker:
                    session_stats = self.session_tracker.get_session_stats()
                    self.stats['sessions_tracked'] = session_stats.get('active_sessions', 0)
                
                await asyncio.sleep(60)  # Update every minute
                
            except Exception as e:
                self.logger.error(f"Statistics updater error: {e}")
                await asyncio.sleep(5)
    
    async def _periodic_threat_summary(self):
        """Periodic threat intelligence summary"""
        while self.is_running:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                
                # Log summary
                uptime = time.time() - self.start_time
                self.logger.info(
                    f"📊 Threat Summary - Uptime: {uptime/3600:.1f}h, "
                    f"Requests: {self.stats['total_requests']}, "
                    f"Threats: {self.stats['threat_detections']}, "
                    f"Honeypot Hits: {self.stats['honeypot_hits']}"
                )
                
            except Exception as e:
                self.logger.error(f"Threat summary error: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_resources(self):
        """Cleanup resources on shutdown"""
        try:
            if self.capture_middleware:
                self.capture_middleware.flush_buffers()
            
            # Log final statistics
            uptime = time.time() - self.start_time
            self.logger.info(
                f"📈 Final Stats - Uptime: {uptime/3600:.1f}h, "
                f"Requests: {self.stats['total_requests']}, "
                f"Threats: {self.stats['threat_detections']}, "
                f"Honeypot Hits: {self.stats['honeypot_hits']}"
            )
            
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")
    
    def run(self, debug: bool = False):
        """Run the honeypot application"""
        try:
            self.initialize_components()
            app = self.create_application()
            
            # Setup signal handlers for graceful shutdown
            def signal_handler(sig, frame):
                self.logger.info(f"🛑 Received signal {sig}, shutting down...")
                self.is_running = False
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            
            self.logger.info(f"🚀 Starting Lurenet HTTP Honeypot on {self.host}:{self.port}")
            self.logger.info("🍯 Honeypot is now active and ready to capture threats!")
            
            # Run the server
            uvicorn.run(
                app,
                host=self.host,
                port=self.port,
                log_level="warning" if not debug else "debug",
                access_log=False,  # We handle our own logging
                server_header=False,  # Don't reveal server type
                date_header=False,
                loop="asyncio"
            )
            
        except Exception as e:
            self.logger.error(f"❌ Honeypot startup failed: {e}")
            raise

# CLI Interface
@click.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=8080, help='Port to bind to')
@click.option('--config-dir', default='config', help='Configuration directory')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.option('--profile', default=None, help='Specific server profile to use')
def main(host: str, port: int, config_dir: str, debug: bool, profile: Optional[str]):
    """
    Lurenet HTTP Honeypot - Advanced modular honeypot platform
    
    Examples:
        python main.py --host 0.0.0.0 --port 80 --profile apache
        python main.py --debug --port 8080
    """
    try:
        # Create and run honeypot
        honeypot = HoneypotApplication(
            config_dir=config_dir,
            host=host,
            port=port
        )
        
        # Set specific profile if requested
        if profile:
            honeypot.initialize_components()
            if not honeypot.response_engine.set_profile(profile):
                click.echo(f"❌ Profile '{profile}' not found!", err=True)
                available = honeypot.profile_manager.list_profiles()
                click.echo(f"Available profiles: {', '.join(available)}")
                return
            click.echo(f"✅ Using server profile: {profile}")
        
        # Run the honeypot
        honeypot.run(debug=debug)
        
    except KeyboardInterrupt:
        click.echo("\n🛑 Honeypot stopped by user")
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        if debug:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
