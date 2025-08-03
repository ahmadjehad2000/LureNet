# middleware/__init__.py

"""
Middleware Package
High-performance middleware components for traffic analysis, capture, and deception
"""

from .intelligence import IntelligenceMiddleware, HAS_C_ACCELERATION as HAS_C_INTEL
from .capture import CaptureMiddleware, HighPerformanceBuffer, HAS_C_CAPTURE  
from .deception import DeceptionMiddleware, DeceptionConfig, HAS_C_DECEPTION

__version__ = "1.0.0"
__author__ = "NHoneypot Security Team"

__all__ = [
    # Intelligence middleware
    'IntelligenceMiddleware',
    'HAS_C_INTEL',
    
    # Capture middleware  
    'CaptureMiddleware',
    'HighPerformanceBuffer',
    'HAS_C_CAPTURE',
    
    # Deception middleware
    'DeceptionMiddleware', 
    'DeceptionConfig',
    'HAS_C_DECEPTION'
]

# Module-level configuration
MIDDLEWARE_CONFIG = {
    'enable_c_acceleration': any([HAS_C_INTEL, HAS_C_CAPTURE, HAS_C_DECEPTION]),
    'default_buffer_size': 10 * 1024 * 1024,  # 10MB
    'max_request_size': 100 * 1024 * 1024,    # 100MB
    'correlation_id_prefix': 'ATK_'
}

def get_middleware_info():
    """Get middleware package information"""
    return {
        'version': __version__,
        'c_acceleration': {
            'intelligence': HAS_C_INTEL,
            'capture': HAS_C_CAPTURE, 
            'deception': HAS_C_DECEPTION
        },
        'config': MIDDLEWARE_CONFIG
    }
