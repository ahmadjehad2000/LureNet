# core/response_engine.py

import time
import random
import asyncio
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse
from fastapi.templating import Jinja2Templates

from config.config_loader import ProfileManager, ServerProfile
from utils.helpers import TimingHelpers, DataHelpers

class ResponseEngine:
    """
    Core response generation engine for realistic server emulation
    """
    
    def __init__(self, profiles_dir: str = "config/profiles"):
        self.profile_manager = ProfileManager(profiles_dir)
        self.templates = Jinja2Templates(directory="templates")
        self.current_profile = None
        
    def set_profile(self, profile_name: str) -> bool:
        """Set active server profile"""
        profile = self.profile_manager.get_profile(profile_name)
        if profile:
            self.current_profile = profile
            return True
        return False
    
    def get_profile(self) -> ServerProfile:
        """Get current profile or random if none set"""
        if self.current_profile is None:
            self.current_profile = self.profile_manager.get_random_profile()
        return self.current_profile
    
    async def generate_response(self, request: Request, threat_data: Dict[str, Any]) -> Tuple[Any, int, Dict[str, str]]:
        """
        Generate appropriate response based on request and threat analysis
        Returns: (response_content, status_code, headers)
        """
        profile = self.get_profile()
        path = str(request.url.path)
        method = request.method
        
        # Get base headers for this server type
        headers = profile.get_headers()
        
        # Add security headers if configured
        security_headers = profile.get_security_headers()
        headers.update(security_headers)
        
        # Check if this is a vulnerable path
        vuln_info = profile.is_vulnerable_path(path)
        if vuln_info:
            return await self._handle_vulnerable_path(request, vuln_info, threat_data, headers)
        
        # Check for specific attack patterns
        attack_type = threat_data.get('attack_type', 'unknown')
        if attack_type != 'unknown':
            return await self._handle_attack_response(request, attack_type, threat_data, headers)
        
        # Handle common paths
        if path == "/":
            return await self._handle_root(request, headers)
        elif path == "/robots.txt":
            return await self._handle_robots(headers)
        elif path.startswith("/static/"):
            return await self._handle_static_file(path, headers)
        elif path == "/favicon.ico":
            return await self._handle_favicon(headers)
        
        # Default 404 response
        return await self._handle_404(request, path, headers)
    
    async def _handle_vulnerable_path(self, request: Request, vuln_info: Dict[str, Any], 
                                    threat_data: Dict[str, Any], headers: Dict[str, str]) -> Tuple[Any, int, Dict[str, str]]:
        """Handle requests to vulnerable paths"""
        profile = self.get_profile()
        response_type = vuln_info.get('response_type', 'login_form')
        
        # Add realistic delay
        delay = profile.get_response_time('base')
        await asyncio.sleep(delay)
        
        if response_type == 'login_form':
            return await self._generate_login_form(request, vuln_info, headers)
        elif response_type == 'directory_listing':
            return await self._generate_directory_listing(request, vuln_info, headers)
        elif response_type == 'php_error':
            return await self._generate_php_error(request, headers)
        elif response_type == 'aspnet_login':
            return await self._generate_aspnet_login(request, headers)
        elif response_type == 'json_error':
            return await self._generate_json_error(request, headers)
        elif response_type == 'shell_interface':
            return await self._generate_shell_interface(request, headers)
        else:
            # Default to 403 forbidden
            return await self._handle_403(request, headers)
    
    async def _handle_attack_response(self, request: Request, attack_type: str, 
                                    threat_data: Dict[str, Any], headers: Dict[str, str]) -> Tuple[Any, int, Dict[str, str]]:
        """Generate responses for detected attacks"""
        profile = self.get_profile()
        
        if attack_type == 'sql_injection':
            # Simulate database error
            delay = profile.get_response_time('500')
            await asyncio.sleep(delay)
            return await self._generate_sql_error(request, headers)
            
        elif attack_type == 'xss':
            # Reflect the XSS attempt (safely)
            return await self._generate_xss_reflection(request, headers)
            
        elif attack_type == 'path_traversal':
            # Return 403 or fake file content
            if random.random() < 0.3:
                return await self._generate_fake_file_content(request, headers)
            else:
                return await self._handle_403(request, headers)
                
        elif attack_type == 'command_injection':
            # Simulate command output or error
            return await self._generate_command_output(request, headers)
            
        # Default response for unknown attacks
        return await self._handle_404(request, str(request.url.path), headers)
    
    async def _generate_login_form(self, request: Request, vuln_info: Dict[str, Any], 
                                 headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Generate realistic login form"""
        profile = self.get_profile()
        
        if 'wp-admin' in str(request.url.path):
            # WordPress style login
            content = self._get_wordpress_login()
        elif 'admin' in str(request.url.path):
            # Generic admin login
            content = self._get_generic_admin_login()
        else:
            # Basic login form
            content = self._get_basic_login_form()
        
        # Add session cookie
        session_config = profile.get_session_config()
        cookie_name = session_config.get('cookie_name', 'SESSIONID')
        session_id = DataHelpers.generate_session_id()
        
        response = HTMLResponse(content=content, status_code=200, headers=headers)
        response.set_cookie(cookie_name, session_id, httponly=True)
        
        return response, 200, headers
    
    async def _generate_directory_listing(self, request: Request, vuln_info: Dict[str, Any], 
                                        headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Generate fake directory listing"""
        path = str(request.url.path)
        
        # Generate fake files and directories
        fake_entries = [
            {"name": "..", "type": "dir", "size": "-", "modified": "2025-01-15 10:30"},
            {"name": "config.php.bak", "type": "file", "size": "2.1K", "modified": "2025-01-10 14:22"},
            {"name": "uploads", "type": "dir", "size": "-", "modified": "2025-01-12 09:15"},
            {"name": "readme.txt", "type": "file", "size": "1.3K", "modified": "2024-12-20 16:45"},
        ]
        
        content = self._build_directory_listing_html(path, fake_entries)
        return HTMLResponse(content=content, status_code=200, headers=headers), 200, headers
    
    async def _generate_php_error(self, request: Request, headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Generate realistic PHP error"""
        errors = [
            "Fatal error: Uncaught Error: Call to undefined function mysql_connect() in /var/www/html/config.php:15",
            "Warning: include(../includes/db.php): failed to open stream: No such file or directory in /var/www/html/index.php:8",
            "Parse error: syntax error, unexpected '}' in /var/www/html/admin.php on line 42"
        ]
        
        error = random.choice(errors)
        content = f"""
        <br />
        <b>{error}</b><br />
        Stack trace:
        #0 /var/www/html/index.php(15): include()
        #1 {{main}}
        """
        
        return HTMLResponse(content=content, status_code=500, headers=headers), 500, headers
    
    async def _generate_aspnet_login(self, request: Request, headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Generate ASP.NET style login"""
        content = """
        <!DOCTYPE html>
        <html>
        <head><title>Login</title></head>
        <body>
        <form method="post" action="/login.aspx" id="aspnetForm">
        <div>
        <input type="hidden" name="__VIEWSTATE" value="/wEWBQIBAgIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4A" />
        </div>
        <table>
        <tr><td>Username:</td><td><input type="text" name="txtUsername" /></td></tr>
        <tr><td>Password:</td><td><input type="password" name="txtPassword" /></td></tr>
        <tr><td colspan="2"><input type="submit" name="btnLogin" value="Login" /></td></tr>
        </table>
        </form>
        </body>
        </html>
        """
        
        return HTMLResponse(content=content, status_code=200, headers=headers), 200, headers
    
    async def _generate_json_error(self, request: Request, headers: Dict[str, str]) -> Tuple[JSONResponse, int, Dict[str, str]]:
        """Generate JSON API error"""
        error_responses = [
            {"error": "Authentication required", "code": 401},
            {"error": "Invalid API key", "code": 403},
            {"error": "Rate limit exceeded", "code": 429},
            {"error": "Internal server error", "code": 500}
        ]
        
        error = random.choice(error_responses)
        headers["Content-Type"] = "application/json"
        
        return JSONResponse(content=error, status_code=error["code"], headers=headers), error["code"], headers
    
    async def _generate_shell_interface(self, request: Request, headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Generate fake web shell interface"""
        content = """
        <html><head><title>Shell</title></head><body>
        <form method="post">
        <input type="text" name="cmd" placeholder="Enter command..." style="width:500px;" />
        <input type="submit" value="Execute" />
        </form>
        <pre>
        Linux server 4.15.0-142-generic #146-Ubuntu SMP x86_64 GNU/Linux
        uid=33(www-data) gid=33(www-data) groups=33(www-data)
        </pre>
        </body></html>
        """
        
        return HTMLResponse(content=content, status_code=200, headers=headers), 200, headers
    
    async def _handle_root(self, request: Request, headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Handle root path requests"""
        profile = self.get_profile()
        
        # Check for random errors
        if profile.should_show_error('500'):
            return await self._handle_500(request, headers)
        elif profile.should_show_error('503'):
            return await self._handle_503(request, headers)
        
        # Serve default page
        content = """
        <!DOCTYPE html>
        <html><head><title>Welcome</title></head>
        <body><h1>It works!</h1><p>This is the default web page for this server.</p></body></html>
        """
        
        delay = profile.get_response_time('base')
        await asyncio.sleep(delay)
        
        return HTMLResponse(content=content, status_code=200, headers=headers), 200, headers
    
    async def _handle_robots(self, headers: Dict[str, str]) -> Tuple[PlainTextResponse, int, Dict[str, str]]:
        """Handle robots.txt"""
        content = """User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /backup/
Disallow: /config/
Allow: /
"""
        headers["Content-Type"] = "text/plain"
        return PlainTextResponse(content=content, status_code=200, headers=headers), 200, headers
    
    async def _handle_static_file(self, path: str, headers: Dict[str, str]) -> Tuple[Any, int, Dict[str, str]]:
        """Handle static file requests"""
        # Most static files don't exist in honeypot
        return await self._handle_404(None, path, headers)
    
    async def _handle_favicon(self, headers: Dict[str, str]) -> Tuple[PlainTextResponse, int, Dict[str, str]]:
        """Handle favicon requests"""
        return PlainTextResponse(content="", status_code=204, headers=headers), 204, headers
    
    async def _handle_404(self, request: Optional[Request], path: str, headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Generate 404 error page"""
        profile = self.get_profile()
        
        # Add realistic delay for 404s
        delay = profile.get_response_time('404')
        await asyncio.sleep(delay)
        
        # Get server-specific 404 page
        host = headers.get('Host', 'localhost')
        port = '80'  # Default port
        
        content = profile.get_error_page('404', path=path, host=host, port=port)
        
        return HTMLResponse(content=content, status_code=404, headers=headers), 404, headers
    
    async def _handle_403(self, request: Request, headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Generate 403 forbidden page"""
        profile = self.get_profile()
        
        delay = profile.get_response_time('403')
        await asyncio.sleep(delay)
        
        path = str(request.url.path)
        host = headers.get('Host', 'localhost')
        
        content = profile.get_error_page('403', path=path, host=host, port='80')
        
        return HTMLResponse(content=content, status_code=403, headers=headers), 403, headers
    
    async def _handle_500(self, request: Request, headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Generate 500 internal server error"""
        profile = self.get_profile()
        
        delay = profile.get_response_time('500')
        await asyncio.sleep(delay)
        
        path = str(request.url.path) if request else "/"
        host = headers.get('Host', 'localhost')
        
        content = profile.get_error_page('500', path=path, host=host, port='80')
        
        return HTMLResponse(content=content, status_code=500, headers=headers), 500, headers
    
    async def _handle_503(self, request: Request, headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Generate 503 service unavailable"""
        profile = self.get_profile()
        
        delay = profile.get_response_time('503')
        await asyncio.sleep(delay)
        
        content = "<h1>503 Service Temporarily Unavailable</h1><p>The server is temporarily overloaded or under maintenance.</p>"
        
        return HTMLResponse(content=content, status_code=503, headers=headers), 503, headers
    
    # Helper methods for generating content
    def _get_wordpress_login(self) -> str:
        """Generate WordPress login form"""
        return """<!DOCTYPE html>
<html><head><title>WordPress › Login</title></head>
<body class="login">
<div id="login">
<h1><a href="https://wordpress.org/">WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-admin/" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" required></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input" required></p>
<p class="submit"><input type="submit" name="wp-submit" value="Log In"></p>
</form>
</div></body></html>"""
    
    def _get_generic_admin_login(self) -> str:
        """Generate generic admin login"""
        return """<!DOCTYPE html>
<html><head><title>Admin Login</title></head>
<body><div style="width:300px;margin:100px auto;padding:20px;border:1px solid #ccc;">
<h2>Administrator Login</h2>
<form method="post">
<p>Username:<br><input type="text" name="username" style="width:100%;"></p>
<p>Password:<br><input type="password" name="password" style="width:100%;"></p>
<p><input type="submit" value="Login" style="width:100%;"></p>
</form>
</div></body></html>"""
    
    def _get_basic_login_form(self) -> str:
        """Generate basic login form"""
        return """<!DOCTYPE html>
<html><head><title>Login Required</title></head>
<body><h1>Authentication Required</h1>
<form method="post"><table>
<tr><td>Username:</td><td><input type="text" name="user"></td></tr>
<tr><td>Password:</td><td><input type="password" name="pass"></td></tr>
<tr><td colspan="2"><input type="submit" value="Login"></td></tr>
</table></form></body></html>"""
    
    def _build_directory_listing_html(self, path: str, entries: list) -> str:
        """Build directory listing HTML"""
        html = f"""<!DOCTYPE html>
<html><head><title>Index of {path}</title></head>
<body><h1>Index of {path}</h1><hr><pre>"""
        
        for entry in entries:
            html += f'<a href="{entry["name"]}">{entry["name"]}</a>{" " * (50 - len(entry["name"]))}{entry["modified"]} {entry["size"]}\n'
        
        html += "</pre><hr></body></html>"
        return html
    
    async def _generate_sql_error(self, request: Request, headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Generate SQL database error"""
        errors = [
            "MySQL Error: You have an error in your SQL syntax near '1=1' at line 1",
            "Database connection failed: Access denied for user 'web'@'localhost'",
            "SQL Error: Table 'users' doesn't exist in database"
        ]
        
        error = random.choice(errors)
        content = f"<h1>Database Error</h1><p>{error}</p>"
        
        return HTMLResponse(content=content, status_code=500, headers=headers), 500, headers
    
    async def _generate_xss_reflection(self, request: Request, headers: Dict[str, str]) -> Tuple[HTMLResponse, int, Dict[str, str]]:
        """Safely reflect XSS attempt (escaped)"""
        query = str(request.url.query)
        escaped_query = query.replace('<', '&lt;').replace('>', '&gt;')
        
        content = f"<h1>Search Results</h1><p>You searched for: {escaped_query}</p><p>No results found.</p>"
        
        return HTMLResponse(content=content, status_code=200, headers=headers), 200, headers
    
    async def _generate_fake_file_content(self, request: Request, headers: Dict[str, str]) -> Tuple[PlainTextResponse, int, Dict[str, str]]:
        """Generate fake sensitive file content"""
        fake_files = {
            'passwd': "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
            'shadow': "root:$6$randomhash:18000:0:99999:7:::\nwww-data:*:18000:0:99999:7:::\n",
            'config': "<?php\n$db_host = 'localhost';\n$db_user = 'admin';\n$db_pass = 'secretpass123';\n?>"
        }
        
        path = str(request.url.path).lower()
        if 'passwd' in path:
            content = fake_files['passwd']
        elif 'shadow' in path:
            content = fake_files['shadow'] 
        elif 'config' in path:
            content = fake_files['config']
        else:
            content = "# Configuration file\nuser=admin\npassword=defaultpass\n"
        
        headers["Content-Type"] = "text/plain"
        return PlainTextResponse(content=content, status_code=200, headers=headers), 200, headers
    
    async def _generate_command_output(self, request: Request, headers: Dict[str, str]) -> Tuple[PlainTextResponse, int, Dict[str, str]]:
        """Generate fake command execution output"""
        outputs = [
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            "Linux webserver 4.15.0-142-generic #146-Ubuntu SMP x86_64 GNU/Linux",
            "/bin/sh: command not found",
            "Permission denied"
        ]
        
        output = random.choice(outputs)
        headers["Content-Type"] = "text/plain"
        
        return PlainTextResponse(content=output, status_code=200, headers=headers), 200, headers
