# config/config_loader.py

import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
import random

class ServerProfile:
    """Server profile configuration handler"""
    
    def __init__(self, profile_path: str):
        self.profile_path = Path(profile_path)
        self.config = self._load_profile()
        
    def _load_profile(self) -> Dict[str, Any]:
        """Load server profile from YAML file"""
        try:
            with open(self.profile_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f"Failed to load profile {self.profile_path}: {e}")
    
    @property
    def name(self) -> str:
        return self.config.get('name', 'unknown')
    
    @property
    def description(self) -> str:
        return self.config.get('description', '')
    
    def get_headers(self, randomize: bool = False) -> Dict[str, str]:
        """Get HTTP headers for this server profile"""
        headers = self.config.get('headers', {}).copy()
        
        if randomize:
            # Add some variation to make fingerprinting harder
            if 'server' in headers:
                # Occasionally omit server header
                if random.random() < 0.05:
                    del headers['server']
        
        return headers
    
    def get_response_time(self, response_type: str = 'base') -> float:
        """Get realistic response time for this server"""
        timing = self.config.get('timing', {})
        
        if response_type == 'base':
            time_config = timing.get('base_response_time', {'min': 0.1, 'max': 0.5})
        else:
            # Error response timing
            error_timing = timing.get('error_responses', {})
            time_config = error_timing.get(response_type, {'min': 0.5, 'max': 1.0})
        
        return random.uniform(time_config['min'], time_config['max'])
    
    def get_error_page(self, error_code: str, **template_vars) -> str:
        """Generate error page for this server"""
        error_pages = self.config.get('error_pages', {})
        error_config = error_pages.get(str(error_code))
        
        if not error_config:
            return f"<h1>{error_code} Error</h1>"
        
        template = error_config.get('template', f'<h1>{error_code} Error</h1>')
        
        # Simple template substitution
        for key, value in template_vars.items():
            template = template.replace(f'{{{{{key}}}}}', str(value))
        
        return template
    
    def get_vulnerable_paths(self) -> List[Dict[str, Any]]:
        """Get list of vulnerable paths this server should respond to"""
        return self.config.get('vulnerable_paths', [])
    
    def is_vulnerable_path(self, path: str) -> Optional[Dict[str, Any]]:
        """Check if path is a known vulnerable endpoint"""
        for vuln_path in self.get_vulnerable_paths():
            if path.startswith(vuln_path['path']):
                return vuln_path
        return None
    
    def should_show_error(self, error_code: str) -> bool:
        """Determine if server should return error based on probability"""
        behavior = self.config.get('behavior', {})
        error_prob = behavior.get('error_probability', {})
        threshold = error_prob.get(str(error_code), 0.0)
        
        return random.random() < threshold
    
    def get_session_config(self) -> Dict[str, Any]:
        """Get session configuration"""
        return self.config.get('behavior', {}).get('sessions', {})
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers (if any)"""
        sec_headers = self.config.get('security_headers', {})
        return {k: v for k, v in sec_headers.items() if v is not None}
    
    def get_ssl_config(self) -> Dict[str, Any]:
        """Get SSL/TLS configuration"""
        return self.config.get('ssl', {})
    
    def simulate_load_behavior(self) -> bool:
        """Simulate server under load"""
        anti_fp = self.config.get('anti_fingerprinting', {})
        return anti_fp.get('fake_load_behavior', False) and random.random() < 0.1

class ProfileManager:
    """Manages multiple server profiles"""
    
    def __init__(self, profiles_dir: str = "config/profiles"):
        self.profiles_dir = Path(profiles_dir)
        self.profiles = {}
        self._load_all_profiles()
    
    def _load_all_profiles(self):
        """Load all profile files from directory"""
        if not self.profiles_dir.exists():
            raise ValueError(f"Profiles directory {self.profiles_dir} not found")
        
        for profile_file in self.profiles_dir.glob("*.yaml"):
            try:
                profile = ServerProfile(profile_file)
                self.profiles[profile.name] = profile
            except Exception as e:
                print(f"Warning: Failed to load profile {profile_file}: {e}")
    
    def get_profile(self, profile_name: str) -> Optional[ServerProfile]:
        """Get specific server profile"""
        return self.profiles.get(profile_name)
    
    def get_random_profile(self) -> ServerProfile:
        """Get random server profile"""
        if not self.profiles:
            raise ValueError("No profiles loaded")
        return random.choice(list(self.profiles.values()))
    
    def list_profiles(self) -> List[str]:
        """List all available profile names"""
        return list(self.profiles.keys())
    
    def get_profile_for_request(self, request_path: str) -> ServerProfile:
        """Select appropriate profile based on request characteristics"""
        # For now, return random profile
        # Later can add logic to select based on request patterns
        return self.get_random_profile()

# Global profile manager instance
profile_manager = None

def get_profile_manager() -> ProfileManager:
    """Get global profile manager instance"""
    global profile_manager
    if profile_manager is None:
        profile_manager = ProfileManager()
    return profile_manager
