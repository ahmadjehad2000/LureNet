# utils/helpers.py

import hashlib
import re
import time
import uuid
import base64
import random
import string
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
import magic
import yara

class SecurityHelpers:
    """Security-related helper functions"""
    
    @staticmethod
    def generate_correlation_id() -> str:
        """Generate unique correlation ID for tracking"""
        timestamp = int(time.time())
        random_part = uuid.uuid4().hex[:8]
        return f"ATK_{timestamp}_{random_part}"
    
    @staticmethod
    def hash_file(file_path: Union[str, Path]) -> Dict[str, str]:
        """Generate multiple hashes for a file"""
        hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)
        
        return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
    
    @staticmethod
    def hash_data(data: bytes) -> Dict[str, str]:
        """Generate multiple hashes for data"""
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()
        }
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe storage"""
        # Remove dangerous characters
        safe_chars = re.sub(r'[^\w\-_\.]', '_', filename)
        # Limit length
        return safe_chars[:255]
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP address is private/local"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False
    
    @staticmethod
    def encode_safe(data: str) -> str:
        """Base64 encode data safely"""
        return base64.b64encode(data.encode('utf-8')).decode('ascii')
    
    @staticmethod
    def decode_safe(data: str) -> str:
        """Base64 decode data safely"""
        try:
            return base64.b64decode(data).decode('utf-8')
        except Exception:
            return data

class AttackDetection:
    """Attack pattern detection helpers"""
    
    SQL_INJECTION_PATTERNS = [
        r"('|(\\'))+.*(or|union|select|insert|delete|update|drop|create|alter|exec)",
        r"(union|select|insert|delete|update|drop|create|alter)\s+.*\s+(from|into|table)",
        r"'.*(\s)*(or|and)\s*'.*'",
        r"(exec|execute)\s*(\(|\s)*(xp_|sp_)",
        r"(;|--|/\*|\*/|\|\|)",
        r"(char|ascii|substr|concat|length)\s*\(",
        r"0x[0-9a-f]+",
        r"(waitfor|delay)\s+('|\")?[0-9]"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript\s*:",
        r"on(click|load|error|focus|blur|change|submit)\s*=",
        r"<(iframe|object|embed|applet)",
        r"document\.(cookie|location|write)",
        r"window\.(location|open)",
        r"eval\s*\(",
        r"expression\s*\(",
        r"vbscript\s*:",
        r"data\s*:\s*text/html"
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"(;|\||&|`|\$\(|\${)",
        r"(cat|ls|pwd|id|whoami|uname|ps|netstat)\s",
        r"(wget|curl|nc|telnet|ssh)\s",
        r"(rm|mv|cp|chmod|chown)\s",
        r"(/bin/|/usr/bin/|/sbin/)",
        r"(cmd|powershell|bash|sh)\s",
        r"(echo|printf)\s.*[|>]"
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"\.\.%2f",
        r"\.\.%5c",
        r"%252e%252e%252f",
        r"..%252f",
        r"..%255c"
    ]
    
    @classmethod
    def detect_sql_injection(cls, text: str) -> Dict[str, Any]:
        """Detect SQL injection patterns"""
        text = text.lower()
        matches = []
        
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern)
        
        return {
            "detected": len(matches) > 0,
            "confidence": min(len(matches) * 0.3, 1.0),
            "patterns": matches
        }
    
    @classmethod
    def detect_xss(cls, text: str) -> Dict[str, Any]:
        """Detect XSS patterns"""
        matches = []
        
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern)
        
        return {
            "detected": len(matches) > 0,
            "confidence": min(len(matches) * 0.25, 1.0),
            "patterns": matches
        }
    
    @classmethod
    def detect_command_injection(cls, text: str) -> Dict[str, Any]:
        """Detect command injection patterns"""
        matches = []
        
        for pattern in cls.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern)
        
        return {
            "detected": len(matches) > 0,
            "confidence": min(len(matches) * 0.4, 1.0),
            "patterns": matches
        }
    
    @classmethod
    def detect_path_traversal(cls, text: str) -> Dict[str, Any]:
        """Detect path traversal patterns"""
        matches = []
        
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append(pattern)
        
        return {
            "detected": len(matches) > 0,
            "confidence": min(len(matches) * 0.5, 1.0),
            "patterns": matches
        }

class URLAnalysis:
    """URL and HTTP request analysis helpers"""
    
    @staticmethod
    def parse_url_components(url: str) -> Dict[str, Any]:
        """Parse URL into components"""
        parsed = urlparse(url)
        
        return {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "params": parsed.params,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "query_params": parse_qs(parsed.query),
            "path_segments": [seg for seg in parsed.path.split('/') if seg]
        }
    
    @staticmethod
    def extract_suspicious_parameters(query_params: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Extract potentially malicious query parameters"""
        suspicious = []
        
        for param, values in query_params.items():
            for value in values:
                decoded_value = unquote(value)
                
                # Check for various attack patterns
                sql_result = AttackDetection.detect_sql_injection(decoded_value)
                xss_result = AttackDetection.detect_xss(decoded_value)
                cmd_result = AttackDetection.detect_command_injection(decoded_value)
                path_result = AttackDetection.detect_path_traversal(decoded_value)
                
                if any([sql_result["detected"], xss_result["detected"], 
                       cmd_result["detected"], path_result["detected"]]):
                    suspicious.append({
                        "parameter": param,
                        "value": value,
                        "decoded_value": decoded_value,
                        "sql_injection": sql_result,
                        "xss": xss_result,
                        "command_injection": cmd_result,
                        "path_traversal": path_result
                    })
        
        return suspicious
    
    @staticmethod
    def analyze_user_agent(user_agent: str) -> Dict[str, Any]:
        """Analyze User-Agent string for tools and anomalies"""
        ua_lower = user_agent.lower()
        
        # Known attack tools
        attack_tools = {
            "sqlmap": "sqlmap",
            "nmap": "nmap",
            "nikto": "nikto",
            "dirb": "dirb",
            "gobuster": "gobuster",
            "wfuzz": "wfuzz",
            "burp": "burp",
            "zap": "zap",
            "w3af": "w3af",
            "masscan": "masscan"
        }
        
        detected_tools = []
        for tool_name, pattern in attack_tools.items():
            if pattern in ua_lower:
                detected_tools.append(tool_name)
        
        # Suspicious characteristics
        suspicious_patterns = [
            "bot", "crawler", "spider", "scan", "test", "check",
            "python", "curl", "wget", "libwww", "lwp"
        ]
        
        suspicious_chars = any(pattern in ua_lower for pattern in suspicious_patterns)
        
        return {
            "user_agent": user_agent,
            "detected_tools": detected_tools,
            "is_suspicious": len(detected_tools) > 0 or suspicious_chars,
            "is_bot": any(bot in ua_lower for bot in ["bot", "crawler", "spider"]),
            "length": len(user_agent),
            "is_empty": len(user_agent.strip()) == 0
        }

class FileAnalysis:
    """File analysis and malware detection helpers"""
    
    @staticmethod
    def detect_file_type(file_path: Union[str, Path]) -> Dict[str, str]:
        """Detect file type using magic numbers"""
        try:
            mime_type = magic.from_file(str(file_path), mime=True)
            file_type = magic.from_file(str(file_path))
            
            return {
                "mime_type": mime_type,
                "file_type": file_type,
                "extension": Path(file_path).suffix.lower()
            }
        except Exception as e:
            return {
                "mime_type": "unknown",
                "file_type": f"error: {str(e)}",
                "extension": Path(file_path).suffix.lower()
            }
    
    @staticmethod
    def is_executable(file_path: Union[str, Path]) -> bool:
        """Check if file is executable"""
        try:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(4)
            
            # Check for common executable signatures
            pe_signature = b'\x4d\x5a'  # MZ (PE/DOS)
            elf_signature = b'\x7f\x45\x4c\x46'  # ELF
            mach_o_32 = b'\xfe\xed\xfa\xce'  # Mach-O 32-bit
            mach_o_64 = b'\xfe\xed\xfa\xcf'  # Mach-O 64-bit
            
            return (magic_bytes.startswith(pe_signature) or 
                   magic_bytes.startswith(elf_signature) or
                   magic_bytes.startswith(mach_o_32) or
                   magic_bytes.startswith(mach_o_64))
        except Exception:
            return False
    
    @staticmethod
    def extract_strings(file_path: Union[str, Path], min_length: int = 4) -> List[str]:
        """Extract printable strings from file"""
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            current_string = ""
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""
            
            # Don't forget the last string
            if len(current_string) >= min_length:
                strings.append(current_string)
                
        except Exception:
            pass
        
        return strings[:100]  # Limit to first 100 strings

class TimingHelpers:
    """Timing and rate limiting helpers"""
    
    @staticmethod
    def realistic_delay(server_type: str = "apache") -> float:
        """Generate realistic server response delays"""
        base_delays = {
            "apache": (0.05, 0.3),
            "nginx": (0.02, 0.15),
            "iis": (0.1, 0.5)
        }
        
        min_delay, max_delay = base_delays.get(server_type, (0.05, 0.3))
        return random.uniform(min_delay, max_delay)
    
    @staticmethod
    def error_delay(error_type: str = "404") -> float:
        """Generate realistic error response delays"""
        error_delays = {
            "404": (0.8, 1.5),
            "403": (0.3, 0.8),
            "500": (1.0, 2.0),
            "503": (0.1, 0.3)
        }
        
        min_delay, max_delay = error_delays.get(error_type, (0.5, 1.0))
        return random.uniform(min_delay, max_delay)

class DataHelpers:
    """Data processing and formatting helpers"""
    
    @staticmethod
    def generate_session_id() -> str:
        """Generate realistic session ID"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
    
    @staticmethod
    def generate_csrf_token() -> str:
        """Generate CSRF token"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=40))
    
    @staticmethod
    def truncate_data(data: str, max_length: int = 1000) -> str:
        """Safely truncate data for logging"""
        if len(data) <= max_length:
            return data
        return data[:max_length] + "...[truncated]"
    
    @staticmethod
    def format_bytes(size: int) -> str:
        """Format byte size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""
    
    @staticmethod
    def normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
        """Normalize HTTP headers for analysis"""
        normalized = {}
        for key, value in headers.items():
            normalized[key.lower().replace('_', '-')] = value.strip()
        return normalized
