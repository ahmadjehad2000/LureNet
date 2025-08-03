# tests/test_core_clean.py

import unittest
import asyncio
import tempfile
import shutil
import time
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path
import yaml
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.response_engine import ResponseEngine
from core.intelligence import ThreatAnalyzer
from core.correlation import SessionTracker, AttackEvent

class AsyncTestMixin:
    """Mixin for async test support"""
    def run_async(self, coro):
        return asyncio.run(coro)

class TestResponseEngine(unittest.TestCase, AsyncTestMixin):
    """Test response engine core functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test profile once for all tests"""
        cls.test_dir = tempfile.mkdtemp()
        profiles_dir = Path(cls.test_dir) / "profiles"
        profiles_dir.mkdir()
        
        # Minimal test profile
        profile = {
            'name': 'test_server',
            'headers': {'server': 'TestServer/1.0'},
            'timing': {'base_response_time': {'min': 0.001, 'max': 0.002}},
            'error_pages': {'404': {'template': '<h1>404 Not Found</h1>'}},
            'vulnerable_paths': [
                {'path': '/admin/', 'threat_score': 50, 'response_type': 'login_form'}
            ],
            'behavior': {'error_probability': {'500': 0.0}}
        }
        
        with open(profiles_dir / "test.yaml", 'w') as f:
            yaml.dump(profile, f)
        
        cls.engine = ResponseEngine(str(profiles_dir))
    
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_dir)
    
    def test_initialization(self):
        """Test engine initializes correctly"""
        self.assertIsNotNone(self.engine.profile_manager)
        self.assertTrue(self.engine.set_profile('test_server'))
    
    def test_root_response(self):
        """Test root path response"""
        mock_request = Mock()
        mock_request.url.path = "/"
        mock_request.method = "GET"
        
        async def test():
            response, status, headers = await self.engine.generate_response(
                mock_request, {'attack_type': 'unknown'}
            )
            self.assertEqual(status, 200)
            self.assertIn('server', headers)
            return True
        
        self.assertTrue(self.run_async(test()))
    
    def test_vulnerable_path_response(self):
        """Test vulnerable path handling"""
        mock_request = Mock()
        mock_request.url.path = "/admin/"
        mock_request.method = "GET"
        
        async def test():
            response, status, headers = await self.engine.generate_response(
                mock_request, {'attack_type': 'admin_probe'}
            )
            self.assertEqual(status, 200)
            return True
        
        self.assertTrue(self.run_async(test()))

class TestThreatAnalyzer(unittest.TestCase, AsyncTestMixin):
    """Test threat analysis core functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Set up configs once for all tests"""
        cls.test_dir = tempfile.mkdtemp()
        
        # Create minimal configs
        vuln_config = {
            'tool_signatures': {
                'sqlmap': {'user_agents': ['sqlmap/'], 'threat_score': 85}
            },
            'cve_simulations': {
                'CVE-2021-41773': {'paths': ['/etc/passwd'], 'threat_score': 95}
            }
        }
        
        intel_config = {
            'threat_scoring': {
                'weights': {'vulnerability_score': 0.5, 'tool_detection': 0.5},
                'thresholds': {'low': 30, 'medium': 60, 'high': 85, 'critical': 95}
            }
        }
        
        with open(Path(cls.test_dir) / "vulnerabilities.yaml", 'w') as f:
            yaml.dump(vuln_config, f)
        
        with open(Path(cls.test_dir) / "intelligence.yaml", 'w') as f:
            yaml.dump(intel_config, f)
    
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_dir)
    
    def setUp(self):
        """Create analyzer with mocked ProfileManager"""
        with patch('core.intelligence.ProfileManager'):
            self.analyzer = ThreatAnalyzer(str(self.test_dir))
    
    def test_initialization(self):
        """Test analyzer initializes with configs"""
        self.assertIn('tool_signatures', self.analyzer.vuln_config)
        self.assertIn('threat_scoring', self.analyzer.intel_config)
    
    def test_normal_request_analysis(self):
        """Test analysis of normal request"""
        mock_request = Mock()
        mock_request.method = "GET"
        mock_request.url.path = "/"
        mock_request.url.query = ""
        mock_request.headers = {'user-agent': 'Mozilla/5.0'}
        mock_request.client.host = "192.168.1.100"
        mock_request.body = AsyncMock(return_value=b"")
        
        async def test():
            result = await self.analyzer.analyze_request(mock_request, "TEST_001")
            self.assertEqual(result['correlation_id'], "TEST_001")
            self.assertIn('threat_score', result)
            self.assertIn('attack_type', result)
            return True
        
        self.assertTrue(self.run_async(test()))
    
    def test_threat_classification(self):
        """Test threat level classification"""
        test_cases = [
            (10, 'minimal'),  # Below 30
            (35, 'low'),      # 30-59
            (65, 'medium'),   # 60-84
            (90, 'high')      # 85-94
        ]
        
        for score, expected_level in test_cases:
            with self.subTest(score=score):
                self.assertEqual(
                    self.analyzer._classify_threat_level(score), 
                    expected_level
                )

class TestSessionTracker(unittest.TestCase, AsyncTestMixin):
    """Test session correlation core functionality"""
    
    def setUp(self):
        """Create tracker with disabled cleanup"""
        with patch.object(SessionTracker, '_start_cleanup_task'):
            self.tracker = SessionTracker(correlation_window=300)
    
    def test_initialization(self):
        """Test tracker initializes correctly"""
        self.assertEqual(self.tracker.correlation_window, 300)
        self.assertEqual(len(self.tracker.active_sessions), 0)
    
    def test_attack_event_creation(self):
        """Test creating attack event from analysis"""
        analysis_data = {
            'correlation_id': 'TEST_001',
            'timestamp': time.time(),
            'threat_score': 75,
            'threat_level': 'high',
            'attack_type': 'sql_injection',
            'confidence': 0.9,
            'request_data': {
                'client_ip': '192.168.1.100',
                'method': 'POST',
                'path': '/login.php',
                'user_agent': 'sqlmap/1.6.12',
                'body_size': 256
            },
            'tool_analysis': {'detected_tools': [{'tool': 'sqlmap'}]},
            'vulnerability_analysis': {'detected_cves': [{'cve_id': 'CVE-2021-41773'}]},
            'processing_time': 0.05
        }
        
        event = self.tracker._create_attack_event(analysis_data)
        
        self.assertEqual(event.correlation_id, 'TEST_001')
        self.assertEqual(event.source_ip, '192.168.1.100')
        self.assertEqual(event.attack_type, 'sql_injection')
        self.assertEqual(event.threat_score, 75)
    
    def test_session_creation(self):
        """Test session creation and correlation"""
        analysis_data = {
            'correlation_id': 'TEST_001',
            'timestamp': time.time(),
            'threat_score': 60,
            'threat_level': 'medium',
            'attack_type': 'reconnaissance',
            'confidence': 0.7,
            'request_data': {
                'client_ip': '192.168.1.100',
                'method': 'GET',
                'path': '/robots.txt',
                'user_agent': 'Mozilla/5.0',
                'body_size': 0
            },
            'tool_analysis': {'detected_tools': []},
            'vulnerability_analysis': {'detected_cves': []},
            'processing_time': 0.02
        }
        
        async def test():
            result = await self.tracker.correlate_event(analysis_data)
            
            # Should create new session
            self.assertEqual(len(self.tracker.active_sessions), 1)
            self.assertTrue(result['correlation_metadata']['is_new_session'])
            self.assertEqual(result['session']['event_count'], 1)
            return True
        
        self.assertTrue(self.run_async(test()))
    
    def test_session_statistics(self):
        """Test session statistics"""
        stats = self.tracker.get_session_stats()
        
        expected_keys = ['active_sessions', 'active_campaigns', 'total_events']
        for key in expected_keys:
            with self.subTest(key=key):
                self.assertIn(key, stats)
                self.assertIsInstance(stats[key], int)

class TestCoreIntegration(unittest.TestCase, AsyncTestMixin):
    """Test integration between core modules"""
    
    @classmethod
    def setUpClass(cls):
        """Set up minimal test environment"""
        cls.test_dir = tempfile.mkdtemp()
        
        # Create profiles directory
        profiles_dir = Path(cls.test_dir) / "profiles"
        profiles_dir.mkdir()
        
        # Minimal configs
        profile = {
            'name': 'test_server',
            'headers': {'server': 'TestServer/1.0'},
            'timing': {'base_response_time': {'min': 0.001, 'max': 0.002}},
            'vulnerable_paths': [{'path': '/admin/', 'threat_score': 50, 'response_type': 'login_form'}],
            'behavior': {'error_probability': {'500': 0.0}}
        }
        
        vuln_config = {'tool_signatures': {'test_tool': {'user_agents': ['test'], 'threat_score': 70}}}
        intel_config = {
            'threat_scoring': {
                'weights': {'vulnerability_score': 0.5, 'tool_detection': 0.5},
                'thresholds': {'low': 30, 'medium': 60, 'high': 85, 'critical': 95}
            }
        }
        
        with open(profiles_dir / "test.yaml", 'w') as f:
            yaml.dump(profile, f)
        with open(Path(cls.test_dir) / "vulnerabilities.yaml", 'w') as f:
            yaml.dump(vuln_config, f)
        with open(Path(cls.test_dir) / "intelligence.yaml", 'w') as f:
            yaml.dump(intel_config, f)
    
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_dir)
    
    def setUp(self):
        """Initialize modules for integration test"""
        self.response_engine = ResponseEngine(str(Path(self.test_dir) / "profiles"))
        
        with patch('core.intelligence.ProfileManager'):
            self.threat_analyzer = ThreatAnalyzer(str(self.test_dir))
        
        with patch.object(SessionTracker, '_start_cleanup_task'):
            self.session_tracker = SessionTracker()
    
    def test_request_pipeline(self):
        """Test complete request processing pipeline"""
        # Create mock request
        mock_request = Mock()
        mock_request.method = "GET"
        mock_request.url.path = "/admin/"
        mock_request.url.query = ""
        mock_request.headers = {'user-agent': 'test_scanner/1.0'}
        mock_request.client.host = "192.168.1.100"
        mock_request.body = AsyncMock(return_value=b"")
        
        async def test():
            # Step 1: Threat analysis
            analysis_result = await self.threat_analyzer.analyze_request(mock_request, "INTEGRATION_001")
            self.assertIn('threat_score', analysis_result)
            
            # Step 2: Session correlation
            correlation_result = await self.session_tracker.correlate_event(analysis_result)
            self.assertIn('session', correlation_result)
            
            # Step 3: Response generation
            response, status, headers = await self.response_engine.generate_response(mock_request, analysis_result)
            self.assertIsInstance(status, int)
            self.assertIsInstance(headers, dict)
            
            return True
        
        self.assertTrue(self.run_async(test()))

if __name__ == "__main__":
    # Run tests with minimal output
    unittest.main(verbosity=1, buffer=True)
