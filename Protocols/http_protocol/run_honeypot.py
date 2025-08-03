# run_honeypot.py
"""
Lurenet Honeypot Runner & Configuration Validator
Comprehensive startup script with environment validation
"""

import os
import sys
import yaml
import json
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import socket
import psutil
import platform

class HoneypotEnvironmentValidator:
    """Validates honeypot environment and configuration"""
    
    def __init__(self, base_dir: Path = None):
        self.base_dir = base_dir or Path.cwd()
        self.errors = []
        self.warnings = []
        self.info = []
        
    def validate_all(self) -> bool:
        """Run all validation checks"""
        print("🔍 Validating Honeypot Environment...")
        
        # Core validations
        self.validate_python_environment()
        self.validate_directory_structure()
        self.validate_configuration_files()
        self.validate_dependencies()
        self.validate_permissions()
        self.validate_network_requirements()
        self.validate_system_resources()
        
        # Print results
        self.print_validation_results()
        
        return len(self.errors) == 0
    
    def validate_python_environment(self):
        """Validate Python version and environment"""
        try:
            version = sys.version_info
            if version.major != 3 or version.minor < 8:
                self.errors.append(f"Python 3.8+ required, found {version.major}.{version.minor}")
            else:
                self.info.append(f"✅ Python {version.major}.{version.minor}.{version.micro}")
            
            # Check virtual environment
            if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
                self.info.append("✅ Running in virtual environment")
            else:
                self.warnings.append("⚠️  Not running in virtual environment (recommended)")
                
        except Exception as e:
            self.errors.append(f"Python environment check failed: {e}")
    
    def validate_directory_structure(self):
        """Validate required directory structure"""
        required_dirs = [
            "config",
            "config/profiles", 
            "middleware",
            "core",
            "utils",
            "analysis",
            "routes",
            "intelligence",
            "logs",
            "data",
            "templates",
            "static",
            "decoys",
            "certs",
            "tests"
        ]
        
        missing_dirs = []
        for dir_name in required_dirs:
            dir_path = self.base_dir / dir_name
            if not dir_path.exists():
                missing_dirs.append(dir_name)
        
        if missing_dirs:
            self.errors.append(f"Missing directories: {', '.join(missing_dirs)}")
        else:
            self.info.append(f"✅ Directory structure validated ({len(required_dirs)} dirs)")
    
    def validate_configuration_files(self):
        """Validate configuration files"""
        config_files = {
            "config/profiles/apache.yaml": "Apache server profile",
            "config/profiles/nginx.yaml": "Nginx server profile", 
            "config/vulnerabilities.yaml": "Vulnerability definitions",
            "config/intelligence.yaml": "Intelligence configuration"
        }
        
        missing_configs = []
        valid_configs = 0
        
        for config_file, description in config_files.items():
            file_path = self.base_dir / config_file
            
            if not file_path.exists():
                missing_configs.append(f"{config_file} ({description})")
                continue
            
            # Validate YAML syntax
            try:
                with open(file_path, 'r') as f:
                    yaml.safe_load(f)
                valid_configs += 1
            except yaml.YAMLError as e:
                self.errors.append(f"Invalid YAML in {config_file}: {e}")
            except Exception as e:
                self.errors.append(f"Error reading {config_file}: {e}")
        
        if missing_configs:
            self.errors.append(f"Missing config files: {', '.join(missing_configs)}")
        
        if valid_configs > 0:
            self.info.append(f"✅ Configuration files validated ({valid_configs} files)")
    
    def validate_dependencies(self):
        """Validate Python dependencies"""
        required_packages = [
            'fastapi',
            'uvicorn',
            'pyyaml',
            'click',
            'python-multipart',
            'starlette'
        ]
        
        optional_packages = [
            'magic',  # File type detection
            'yara-python',  # YARA rules
            'maxminddb',  # GeoIP
            'psutil'  # System monitoring
        ]
        
        missing_required = []
        missing_optional = []
        
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing_required.append(package)
        
        for package in optional_packages:
            try:
                if package == 'yara-python':
                    __import__('yara')
                elif package == 'python-magic':
                    __import__('magic')
                else:
                    __import__(package.replace('-', '_'))
            except ImportError:
                missing_optional.append(package)
        
        if missing_required:
            self.errors.append(f"Missing required packages: {', '.join(missing_required)}")
        else:
            self.info.append(f"✅ Required dependencies satisfied ({len(required_packages)} packages)")
        
        if missing_optional:
            self.warnings.append(f"⚠️  Missing optional packages: {', '.join(missing_optional)}")
    
    def validate_permissions(self):
        """Validate file and directory permissions"""
        # Check write permissions for logs and data
        write_dirs = ["logs", "data", "data"]
        
        permission_issues = []
        
        for dir_name in write_dirs:
            dir_path = self.base_dir / dir_name
            if dir_path.exists():
                if not os.access(dir_path, os.W_OK):
                    permission_issues.append(f"{dir_name} (not writable)")
            else:
                # Try to create directory
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                except PermissionError:
                    permission_issues.append(f"{dir_name} (cannot create)")
        
        if permission_issues:
            self.errors.append(f"Permission issues: {', '.join(permission_issues)}")
        else:
            self.info.append("✅ File permissions validated")
    
    def validate_network_requirements(self):
        """Validate network requirements"""
        # Check if we can bind to common ports
        ports_to_check = [8080, 8443, 80, 443]
        available_ports = []
        used_ports = []
        
        for port in ports_to_check:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', port))
                    available_ports.append(port)
            except OSError:
                used_ports.append(port)
        
        if available_ports:
            self.info.append(f"✅ Available ports: {', '.join(map(str, available_ports))}")
        
        if used_ports:
            if 80 in used_ports or 443 in used_ports:
                self.warnings.append(f"⚠️  Privileged ports in use: {', '.join(map(str, [p for p in used_ports if p in [80, 443]]))}")
            if 8080 in used_ports:
                self.warnings.append("⚠️  Default port 8080 is in use")
    
    def validate_system_resources(self):
        """Validate system resources"""
        try:
            # Memory check
            memory = psutil.virtual_memory()
            available_gb = memory.available / (1024**3)
            
            if available_gb < 0.5:
                self.warnings.append(f"⚠️  Low memory: {available_gb:.1f}GB available")
            else:
                self.info.append(f"✅ Memory: {available_gb:.1f}GB available")
            
            # Disk space check
            disk = psutil.disk_usage(str(self.base_dir))
            available_gb = disk.free / (1024**3)
            
            if available_gb < 1.0:
                self.warnings.append(f"⚠️  Low disk space: {available_gb:.1f}GB available")
            else:
                self.info.append(f"✅ Disk space: {available_gb:.1f}GB available")
            
            # CPU check
            cpu_count = psutil.cpu_count()
            self.info.append(f"✅ CPU cores: {cpu_count}")
            
        except Exception as e:
            self.warnings.append(f"⚠️  Could not check system resources: {e}")
    
    def print_validation_results(self):
        """Print validation results"""
        print("\n" + "="*60)
        print("🔍 VALIDATION RESULTS")
        print("="*60)
        
        if self.info:
            print("\n✅ SUCCESS:")
            for msg in self.info:
                print(f"  {msg}")
        
        if self.warnings:
            print("\n⚠️  WARNINGS:")
            for msg in self.warnings:
                print(f"  {msg}")
        
        if self.errors:
            print("\n❌ ERRORS:")
            for msg in self.errors:
                print(f"  {msg}")
        else:
            print("\n🎉 All validations passed!")
        
        print("\n" + "="*60)
    
    def create_missing_directories(self):
        """Create missing directories"""
        dirs_to_create = [
            "logs", "data", "data/uploads", "static/css", "static/js",
            "templates", "decoys/phishing", "decoys/malware", "certs"
        ]
        
        created = []
        for dir_name in dirs_to_create:
            dir_path = self.base_dir / dir_name
            if not dir_path.exists():
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                    created.append(dir_name)
                except Exception as e:
                    print(f"❌ Failed to create {dir_name}: {e}")
        
        if created:
            print(f"📁 Created directories: {', '.join(created)}")
    
    def install_dependencies(self, install_optional: bool = False):
        """Install missing dependencies"""
        required_packages = [
            'fastapi>=0.100.0',
            'uvicorn[standard]>=0.20.0', 
            'pyyaml>=6.0',
            'click>=8.0.0',
            'python-multipart>=0.0.6',
            'starlette>=0.27.0'
        ]
        
        optional_packages = [
            'python-magic>=0.4.24',
            'yara-python>=4.2.0',
            'maxminddb>=2.2.0',
            'psutil>=5.8.0'
        ]
        
        packages_to_install = required_packages
        if install_optional:
            packages_to_install.extend(optional_packages)
        
        print(f"📦 Installing {len(packages_to_install)} packages...")
        
        try:
            cmd = [sys.executable, '-m', 'pip', 'install'] + packages_to_install
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print("✅ Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            print(f"Error output: {e.stderr}")
            return False

class HoneypotQuickStart:
    """Quick start configuration generator"""
    
    def __init__(self, base_dir: Path = None):
        self.base_dir = base_dir or Path.cwd()
    
    def create_minimal_config(self):
        """Create minimal working configuration"""
        print("🔧 Creating minimal configuration...")
        
        # Create Apache profile
        apache_profile = {
            'name': 'apache_2_4_ubuntu',
            'description': 'Apache 2.4.41 on Ubuntu 20.04',
            'headers': {
                'server': 'Apache/2.4.41 (Ubuntu)',
                'x_powered_by': 'PHP/7.4.3'
            },
            'timing': {
                'base_response_time': {'min': 0.05, 'max': 0.3},
                'error_responses': {
                    '404': {'min': 0.8, 'max': 1.5},
                    '500': {'min': 1.0, 'max': 2.0}
                }
            },
            'error_pages': {
                '404': {
                    'title': '404 Not Found',
                    'template': '''<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body>
<h1>Not Found</h1>
<p>The requested URL {{path}} was not found on this server.</p>
<hr><address>Apache/2.4.41 (Ubuntu) Server at {{host}} Port {{port}}</address>
</body></html>'''
                }
            },
            'vulnerable_paths': [
                {
                    'path': '/wp-admin/',
                    'description': 'WordPress admin panel',
                    'threat_score': 40,
                    'response_type': 'login_form'
                },
                {
                    'path': '/admin/',
                    'description': 'Generic admin panel',
                    'threat_score': 45,
                    'response_type': 'login_form'
                },
                {
                    'path': '/phpmyadmin/',
                    'description': 'PHPMyAdmin interface',
                    'threat_score': 60,
                    'response_type': 'login_form'
                }
            ],
            'behavior': {
                'error_probability': {'500': 0.02, '503': 0.01}
            }
        }
        
        # Save Apache profile
        profiles_dir = self.base_dir / "config" / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        
        with open(profiles_dir / "apache.yaml", 'w') as f:
            yaml.dump(apache_profile, f, default_flow_style=False)
        
        # Create basic vulnerabilities config
        vulnerabilities_config = {
            'cve_simulations': {
                'CVE-2021-41773': {
                    'description': 'Apache HTTP Server Path Traversal',
                    'paths': ['/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'],
                    'threat_score': 95,
                    'response_type': 'path_traversal'
                }
            },
            'attack_patterns': {
                'sql_injection': {
                    'patterns': ["' OR 1=1--", "UNION SELECT", "'; DROP TABLE"],
                    'threat_score': 80,
                    'response_delay': 2.5
                },
                'xss': {
                    'patterns': ["<script>alert(", "javascript:", "onerror="],
                    'threat_score': 60,
                    'response_type': 'reflected_xss'
                }
            },
            'tool_signatures': {
                'sqlmap': {
                    'user_agents': ['sqlmap/', 'User-Agent: sqlmap'],
                    'threat_score': 85
                },
                'nmap': {
                    'user_agents': ['Nmap Scripting Engine'],
                    'patterns': ['OPTIONS *', 'GET / HTTP/1.0'],
                    'threat_score': 40
                }
            }
        }
        
        with open(self.base_dir / "config" / "vulnerabilities.yaml", 'w') as f:
            yaml.dump(vulnerabilities_config, f, default_flow_style=False)
        
        # Create intelligence config
        intelligence_config = {
            'threat_scoring': {
                'weights': {
                    'vulnerability_score': 0.4,
                    'tool_detection': 0.3,
                    'persistence_attempts': 0.2,
                    'data_exfiltration': 0.1
                },
                'thresholds': {
                    'low': 30,
                    'medium': 60,
                    'high': 85,
                    'critical': 95
                }
            },
            'attack_types': {
                'reconnaissance': {
                    'indicators': ['robots.txt', 'sitemap.xml', '/.well-known/'],
                    'score': 20
                },
                'vulnerability_scanning': {
                    'indicators': ['nikto', 'dirb', 'gobuster'],
                    'score': 40
                },
                'exploitation': {
                    'indicators': ['shell.php', 'cmd.php', 'eval('],
                    'score': 90
                }
            }
        }
        
        with open(self.base_dir / "config" / "intelligence.yaml", 'w') as f:
            yaml.dump(intelligence_config, f, default_flow_style=False)
        
        print("✅ Minimal configuration created")
    
    def create_startup_script(self):
        """Create startup script"""
        startup_script = '''#!/bin/bash
# Lurenet Honeypot Startup Script

echo "🍯 Starting Lurenet HTTP Honeypot..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt 2>/dev/null || echo "⚠️  No requirements.txt found"

# Run validation
echo "🔍 Validating environment..."
python run_honeypot.py --validate

# Start honeypot
echo "🚀 Starting honeypot..."
python main.py --host 0.0.0.0 --port 8080 "$@"
'''
        
        script_path = self.base_dir / "start_honeypot.sh"
        with open(script_path, 'w') as f:
            f.write(startup_script)
        
        # Make executable
        os.chmod(script_path, 0o755)
        
        print("✅ Startup script created: start_honeypot.sh")
    
    def create_requirements_file(self):
        """Create requirements.txt file"""
        requirements = [
            "fastapi>=0.100.0",
            "uvicorn[standard]>=0.20.0",
            "pyyaml>=6.0",
            "click>=8.0.0",
            "python-multipart>=0.0.6",
            "starlette>=0.27.0",
            "# Optional dependencies",
            "python-magic>=0.4.24",
            "psutil>=5.8.0"
        ]
        
        with open(self.base_dir / "requirements.txt", 'w') as f:
            f.write('\n'.join(requirements))
        
        print("✅ Requirements file created: requirements.txt")

def main():
    """Main runner function"""
    parser = argparse.ArgumentParser(description="Lurenet Honeypot Runner & Validator")
    parser.add_argument('--validate', action='store_true', help='Validate environment only')
    parser.add_argument('--setup', action='store_true', help='Setup minimal configuration')
    parser.add_argument('--install-deps', action='store_true', help='Install dependencies')
    parser.add_argument('--install-optional', action='store_true', help='Install optional dependencies')
    parser.add_argument('--create-dirs', action='store_true', help='Create missing directories')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to')
    parser.add_argument('--profile', help='Server profile to use')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    base_dir = Path.cwd()
    validator = HoneypotEnvironmentValidator(base_dir)
    
    print("🍯 Lurenet HTTP Honeypot Runner")
    print("="*50)
    
    # Handle different modes
    if args.setup:
        print("🔧 Setting up honeypot environment...")
        
        # Create directories
        validator.create_missing_directories()
        
        # Create minimal config
        quick_start = HoneypotQuickStart(base_dir)
        quick_start.create_minimal_config()
        quick_start.create_startup_script()
        quick_start.create_requirements_file()
        
        print("\n✅ Setup complete! Next steps:")
        print("  1. Install dependencies: python run_honeypot.py --install-deps")
        print("  2. Validate environment: python run_honeypot.py --validate")
        print("  3. Start honeypot: python main.py")
        print("  4. Or use startup script: ./start_honeypot.sh")
        return
    
    if args.create_dirs:
        validator.create_missing_directories()
        return
    
    if args.install_deps:
        success = validator.install_dependencies(install_optional=args.install_optional)
        if not success:
            sys.exit(1)
        return
    
    if args.validate:
        is_valid = validator.validate_all()
        if not is_valid:
            print("\n❌ Validation failed! Fix errors before starting honeypot.")
            sys.exit(1)
        else:
            print("\n✅ Environment validation successful!")
        return
    
    # Default: validate and run
    print("🔍 Running pre-flight validation...")
    is_valid = validator.validate_all()
    
    if not is_valid:
        print("\n❌ Validation failed!")
        print("💡 Run with --setup to create minimal configuration")
        print("💡 Run with --install-deps to install dependencies")
        sys.exit(1)
    
    # Import and run honeypot
    try:
        print("\n🚀 Starting honeypot...")
        
        # Add current directory to Python path
        sys.path.insert(0, str(base_dir))
        
        from main import HoneypotApplication
        
        honeypot = HoneypotApplication(
            config_dir=str(base_dir / "config"),
            host=args.host,
            port=args.port
        )
        
        # Set specific profile if requested
        if args.profile:
            honeypot.initialize_components()
            if not honeypot.response_engine.set_profile(args.profile):
                print(f"❌ Profile '{args.profile}' not found!")
                available = honeypot.profile_manager.list_profiles()
                print(f"Available profiles: {', '.join(available)}")
                sys.exit(1)
            print(f"✅ Using server profile: {args.profile}")
        
        # Run the honeypot
        honeypot.run(debug=args.debug)
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure all required files are present")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Honeypot stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
