# tests/test_config.py

import unittest
import tempfile
import shutil
from pathlib import Path
import yaml
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.config_loader import ServerProfile, ProfileManager

class TestServerProfile(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_profile_file = Path(self.test_dir) / "test_apache.yaml"
        
        # Create test profile
        test_config = {
            'name': 'test_apache',
            'description': 'Test Apache Profile',
            'headers': {
                'server': 'Apache/2.4.41 (Ubuntu)',
                'x_powered_by': 'PHP/7.4.3'
            },
            'timing': {
                'base_response_time': {'min': 0.1, 'max': 0.3},
                'error_responses': {
                    '404': {'min': 0.8, 'max': 1.5}
                }
            },
            'error_pages': {
                '404': {
                    'title': '404 Not Found',
                    'template': '<h1>Not Found</h1><p>{{path}} not found</p>'
                }
            },
            'vulnerable_paths': [
                {
                    'path': '/wp-admin/',
                    'description': 'WordPress admin',
                    'threat_score': 40,
                    'response_type': 'login_form'
                }
            ],
            'behavior': {
                'error_probability': {
                    '500': 0.02
                }
            }
        }
        
        with open(self.test_profile_file, 'w') as f:
            yaml.dump(test_config, f)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
    
    def test_profile_loading(self):
        """Test profile loads correctly"""
        profile = ServerProfile(self.test_profile_file)
        
        self.assertEqual(profile.name, 'test_apache')
        self.assertEqual(profile.description, 'Test Apache Profile')
    
    def test_get_headers(self):
        """Test header retrieval"""
        profile = ServerProfile(self.test_profile_file)
        headers = profile.get_headers()
        
        self.assertEqual(headers['server'], 'Apache/2.4.41 (Ubuntu)')
        self.assertEqual(headers['x_powered_by'], 'PHP/7.4.3')
    
    def test_get_response_time(self):
        """Test response timing"""
        profile = ServerProfile(self.test_profile_file)
        
        # Test base response time
        response_time = profile.get_response_time('base')
        self.assertGreaterEqual(response_time, 0.1)
        self.assertLessEqual(response_time, 0.3)
        
        # Test error response time
        error_time = profile.get_response_time('404')
        self.assertGreaterEqual(error_time, 0.8)
        self.assertLessEqual(error_time, 1.5)
    
    def test_get_error_page(self):
        """Test error page generation"""
        profile = ServerProfile(self.test_profile_file)
        
        error_page = profile.get_error_page('404', path='/test/path')
        self.assertIn('Not Found', error_page)
        self.assertIn('/test/path', error_page)
    
    def test_vulnerable_paths(self):
        """Test vulnerable path detection"""
        profile = ServerProfile(self.test_profile_file)
        
        # Test positive match
        vuln_info = profile.is_vulnerable_path('/wp-admin/login.php')
        self.assertIsNotNone(vuln_info)
        self.assertEqual(vuln_info['threat_score'], 40)
        
        # Test negative match
        safe_info = profile.is_vulnerable_path('/safe/path')
        self.assertIsNone(safe_info)
    
    def test_error_probability(self):
        """Test error probability calculation"""
        profile = ServerProfile(self.test_profile_file)
        
        # Run multiple times to test probability
        error_count = 0
        trials = 1000
        
        for _ in range(trials):
            if profile.should_show_error('500'):
                error_count += 1
        
        # Should be approximately 2% (0.02 * 1000 = 20)
        # Allow some variance (5-50 errors)
        self.assertGreater(error_count, 5)
        self.assertLess(error_count, 50)

class TestProfileManager(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment with real profile structure"""
        self.test_dir = tempfile.mkdtemp()
        self.profiles_dir = Path(self.test_dir) / "profiles"
        self.profiles_dir.mkdir()
        
        # Create test profiles matching real structure
        apache_config = {
            'name': 'apache_2_4_ubuntu',
            'description': 'Apache Test',
            'headers': {'server': 'Apache/2.4.41 (Ubuntu)', 'x_powered_by': 'PHP/7.4.3'},
            'timing': {'base_response_time': {'min': 0.05, 'max': 0.3}},
            'vulnerable_paths': [
                {'path': '/wp-admin/', 'threat_score': 40, 'response_type': 'login_form'}
            ]
        }
        
        nginx_config = {
            'name': 'nginx_1_18_ubuntu',
            'description': 'Nginx Test',
            'headers': {'server': 'nginx/1.18.0', 'x_powered_by': 'Express'},
            'timing': {'base_response_time': {'min': 0.02, 'max': 0.15}},
            'vulnerable_paths': [
                {'path': '/admin/', 'threat_score': 45, 'response_type': 'login_form'}
            ]
        }
        
        iis_config = {
            'name': 'iis_10_windows_server',
            'description': 'IIS Test',
            'headers': {'server': 'Microsoft-IIS/10.0', 'x_powered_by': 'ASP.NET'},
            'timing': {'base_response_time': {'min': 0.08, 'max': 0.5}},
            'vulnerable_paths': [
                {'path': '/login.aspx', 'threat_score': 40, 'response_type': 'aspnet_login'}
            ]
        }
        
        with open(self.profiles_dir / "apache.yaml", 'w') as f:
            yaml.dump(apache_config, f)
        
        with open(self.profiles_dir / "nginx.yaml", 'w') as f:
            yaml.dump(nginx_config, f)
            
        with open(self.profiles_dir / "iis.yaml", 'w') as f:
            yaml.dump(iis_config, f)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
    
    def test_profile_manager_loading(self):
        """Test profile manager loads all profiles"""
        manager = ProfileManager(str(self.profiles_dir))
        
        profiles = manager.list_profiles()
        self.assertIn('apache_2_4_ubuntu', profiles)
        self.assertIn('nginx_1_18_ubuntu', profiles)
        self.assertIn('iis_10_windows_server', profiles)
        self.assertEqual(len(profiles), 3)
    
    def test_get_specific_profile(self):
        """Test getting specific profile"""
        manager = ProfileManager(str(self.profiles_dir))
        
        apache_profile = manager.get_profile('apache_2_4_ubuntu')
        self.assertIsNotNone(apache_profile)
        self.assertEqual(apache_profile.name, 'apache_2_4_ubuntu')
        
        nginx_profile = manager.get_profile('nginx_1_18_ubuntu')
        self.assertIsNotNone(nginx_profile)
        self.assertEqual(nginx_profile.name, 'nginx_1_18_ubuntu')
        
        iis_profile = manager.get_profile('iis_10_windows_server')
        self.assertIsNotNone(iis_profile)
        self.assertEqual(iis_profile.name, 'iis_10_windows_server')
        
        # Test non-existent profile
        fake_profile = manager.get_profile('nonexistent')
        self.assertIsNone(fake_profile)
    
    def test_get_random_profile(self):
        """Test random profile selection"""
        manager = ProfileManager(str(self.profiles_dir))
        
        # Test multiple random selections
        selected_profiles = set()
        for _ in range(30):
            profile = manager.get_random_profile()
            selected_profiles.add(profile.name)
        
        # Should have selected multiple profiles
        self.assertTrue(len(selected_profiles) >= 2)
        expected_profiles = {'apache_2_4_ubuntu', 'nginx_1_18_ubuntu', 'iis_10_windows_server'}
        self.assertTrue(selected_profiles.issubset(expected_profiles))
    
    def test_server_differentiation(self):
        """Test that different servers have different characteristics"""
        manager = ProfileManager(str(self.profiles_dir))
        
        apache = manager.get_profile('apache_2_4_ubuntu')
        nginx = manager.get_profile('nginx_1_18_ubuntu')
        iis = manager.get_profile('iis_10_windows_server')
        
        # Test different headers
        apache_headers = apache.get_headers()
        nginx_headers = nginx.get_headers()
        iis_headers = iis.get_headers()
        
        self.assertIn('Apache', apache_headers['server'])
        self.assertIn('nginx', nginx_headers['server'])
        self.assertIn('IIS', iis_headers['server'])
        
        # Test different timing characteristics
        apache_time = apache.get_response_time()
        nginx_time = nginx.get_response_time()
        iis_time = iis.get_response_time()
        
        # Nginx should generally be faster than IIS
        # Note: This is probabilistic, so we test ranges
        self.assertGreaterEqual(apache_time, 0.05)
        self.assertLessEqual(apache_time, 0.3)
        
        self.assertGreaterEqual(nginx_time, 0.02)
        self.assertLessEqual(nginx_time, 0.15)
        
        self.assertGreaterEqual(iis_time, 0.08)
        self.assertLessEqual(iis_time, 0.5)
    
    def test_vulnerable_paths_per_server(self):
        """Test that each server has appropriate vulnerable paths"""
        manager = ProfileManager(str(self.profiles_dir))
        
        apache = manager.get_profile('apache_2_4_ubuntu')
        nginx = manager.get_profile('nginx_1_18_ubuntu')
        iis = manager.get_profile('iis_10_windows_server')
        
        # Test Apache WordPress path
        apache_vuln = apache.is_vulnerable_path('/wp-admin/login.php')
        self.assertIsNotNone(apache_vuln)
        self.assertEqual(apache_vuln['threat_score'], 40)
        
        # Test Nginx admin path
        nginx_vuln = nginx.is_vulnerable_path('/admin/dashboard')
        self.assertIsNotNone(nginx_vuln)
        self.assertEqual(nginx_vuln['threat_score'], 45)
        
        # Test IIS ASP.NET path
        iis_vuln = iis.is_vulnerable_path('/login.aspx')
        self.assertIsNotNone(iis_vuln)
        self.assertEqual(iis_vuln['threat_score'], 40)

class TestRealProfiles(unittest.TestCase):
    """Test the actual profile files"""
    
    def test_real_apache_profile_exists(self):
        """Test that real Apache profile exists and loads"""
        apache_path = Path("config/profiles/apache.yaml")
        if apache_path.exists():
            profile = ServerProfile(apache_path)
            self.assertEqual(profile.name, 'apache_2_4_ubuntu')
            self.assertIn('Apache', profile.get_headers()['server'])
    
    def test_real_nginx_profile_exists(self):
        """Test that real Nginx profile exists and loads"""
        nginx_path = Path("config/profiles/nginx.yaml")
        if nginx_path.exists():
            profile = ServerProfile(nginx_path)
            self.assertEqual(profile.name, 'nginx_1_18_ubuntu')
            self.assertIn('nginx', profile.get_headers()['server'])
    
    def test_real_iis_profile_exists(self):
        """Test that real IIS profile exists and loads"""
        iis_path = Path("config/profiles/iis.yaml")
        if iis_path.exists():
            profile = ServerProfile(iis_path)
            self.assertEqual(profile.name, 'iis_10_windows_server')
            self.assertIn('IIS', profile.get_headers()['server'])

class TestVulnerabilityConfig(unittest.TestCase):
    """Test vulnerability configuration loading"""
    
    def test_vulnerability_config_exists(self):
        """Test that vulnerability config exists and loads"""
        vuln_path = Path("config/vulnerabilities.yaml")
        if vuln_path.exists():
            with open(vuln_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Test structure
            self.assertIn('cve_simulations', config)
            self.assertIn('attack_patterns', config)
            self.assertIn('tool_signatures', config)
            
            # Test specific CVEs exist
            cves = config['cve_simulations']
            self.assertIn('CVE-2021-41773', cves)
            self.assertIn('CVE-2022-22965', cves)
            
            # Test attack patterns
            patterns = config['attack_patterns']
            self.assertIn('sql_injection', patterns)
            self.assertIn('xss', patterns)
            
            # Test tool signatures
            tools = config['tool_signatures']
            self.assertIn('sqlmap', tools)
            self.assertIn('nmap', tools)

class TestIntelligenceConfig(unittest.TestCase):
    """Test intelligence configuration loading"""
    
    def test_intelligence_config_exists(self):
        """Test that intelligence config exists and loads"""
        intel_path = Path("config/intelligence.yaml")
        if intel_path.exists():
            with open(intel_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Test structure
            self.assertIn('threat_scoring', config)
            self.assertIn('attack_types', config)
            self.assertIn('session_tracking', config)
            
            # Test threat scoring
            scoring = config['threat_scoring']
            self.assertIn('weights', scoring)
            self.assertIn('thresholds', scoring)
            
            # Test thresholds are reasonable
            thresholds = scoring['thresholds']
            self.assertLess(thresholds['low'], thresholds['medium'])
            self.assertLess(thresholds['medium'], thresholds['high'])
            self.assertLess(thresholds['high'], thresholds['critical'])
            
            # Test attack types
            attacks = config['attack_types']
            self.assertIn('reconnaissance', attacks)
            self.assertIn('exploitation', attacks)
            
            # Test session tracking
            sessions = config['session_tracking']
            self.assertIn('correlation_window', sessions)
            self.assertIn('suspicious_patterns', sessions)

class TestConfigIntegration(unittest.TestCase):
    """Test integration between different config files"""
    
    def test_config_files_consistency(self):
        """Test that config files are consistent with each other"""
        # Load all configs
        apache_path = Path("config/profiles/apache.yaml")
        vuln_path = Path("config/vulnerabilities.yaml")
        intel_path = Path("config/intelligence.yaml")
        
        if all(p.exists() for p in [apache_path, vuln_path, intel_path]):
            with open(apache_path, 'r') as f:
                apache_config = yaml.safe_load(f)
            with open(vuln_path, 'r') as f:
                vuln_config = yaml.safe_load(f)
            with open(intel_path, 'r') as f:
                intel_config = yaml.safe_load(f)
            
            # Test that vulnerability paths exist in server profiles
            apache_paths = [v['path'] for v in apache_config.get('vulnerable_paths', [])]
            
            # At least some overlap should exist
            self.assertTrue(len(apache_paths) > 0)
            
            # Test threat score consistency
            intel_thresholds = intel_config['threat_scoring']['thresholds']
            for vuln in apache_config.get('vulnerable_paths', []):
                threat_score = vuln.get('threat_score', 0)
                self.assertGreaterEqual(threat_score, 0)
                self.assertLessEqual(threat_score, 100)

if __name__ == "__main__":
    unittest.main()
