# core/intelligence.py

import time
import asyncio
import yaml
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from fastapi import Request
from urllib.parse import unquote, parse_qs

from utils.helpers import AttackDetection, URLAnalysis, SecurityHelpers
from utils.logger import HoneypotLogger
from config.config_loader import ProfileManager

class ThreatAnalyzer:
    """Core threat analysis and classification engine"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.logger = HoneypotLogger()
        self.profile_manager = ProfileManager()
        
        # Load configuration files
        self.vuln_config = self._load_vulnerabilities_config()
        self.intel_config = self._load_intelligence_config()
        
        # Threat scoring weights
        self.scoring_weights = self.intel_config.get('threat_scoring', {}).get('weights', {
            'vulnerability_score': 0.4,
            'tool_detection': 0.3, 
            'persistence_attempts': 0.2,
            'data_exfiltration': 0.1
        })
        
        # Threat thresholds
        self.threat_thresholds = self.intel_config.get('threat_scoring', {}).get('thresholds', {
            'low': 30, 'medium': 60, 'high': 85, 'critical': 95
        })
    
    def _load_vulnerabilities_config(self) -> Dict[str, Any]:
        """Load vulnerability simulation config"""
        try:
            vuln_file = self.config_dir / "vulnerabilities.yaml"
            with open(vuln_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load vulnerabilities config: {e}")
            return {}
    
    def _load_intelligence_config(self) -> Dict[str, Any]:
        """Load intelligence analysis config"""
        try:
            intel_file = self.config_dir / "intelligence.yaml"
            with open(intel_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load intelligence config: {e}")
            return {}
    
    async def analyze_request(self, request: Request, correlation_id: str) -> Dict[str, Any]:
        """
        Comprehensive request analysis for threat intelligence
        Returns threat analysis data
        """
        start_time = time.time()
        
        # Extract request components
        request_data = await self._extract_request_data(request)
        
        # Perform analysis
        url_analysis = self._analyze_url(request_data)
        header_analysis = self._analyze_headers(request_data)
        payload_analysis = await self._analyze_payload(request)
        attack_analysis = self._detect_attack_patterns(request_data, payload_analysis)
        tool_analysis = self._detect_attack_tools(request_data)
        vulnerability_analysis = self._analyze_vulnerabilities(request_data)
        
        # Calculate threat score
        threat_score = self._calculate_threat_score(
            attack_analysis, tool_analysis, vulnerability_analysis, url_analysis
        )
        
        # Classify threat level
        threat_level = self._classify_threat_level(threat_score)
        
        # Build comprehensive analysis result
        analysis_result = {
            'correlation_id': correlation_id,
            'timestamp': time.time(),
            'processing_time': time.time() - start_time,
            'request_data': request_data,
            'url_analysis': url_analysis,
            'header_analysis': header_analysis,
            'payload_analysis': payload_analysis,
            'attack_analysis': attack_analysis,
            'tool_analysis': tool_analysis,
            'vulnerability_analysis': vulnerability_analysis,
            'threat_score': threat_score,
            'threat_level': threat_level,
            'attack_type': self._determine_primary_attack_type(attack_analysis),
            'confidence': self._calculate_confidence(attack_analysis, tool_analysis),
            'recommendations': self._generate_recommendations(threat_level, attack_analysis)
        }
        
        # Log threat intelligence
        await self._log_threat_intelligence(analysis_result)
        
        return analysis_result
    
    async def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract all relevant data from request"""
        try:
            body = await request.body()
        except Exception:
            body = b""
        
        return {
            'method': request.method,
            'url': str(request.url),
            'path': request.url.path,
            'query': str(request.url.query) if request.url.query else "",
            'headers': dict(request.headers),
            'client_ip': request.client.host,
            'body': body,
            'body_size': len(body),
            'user_agent': request.headers.get('user-agent', ''),
            'referer': request.headers.get('referer', ''),
            'content_type': request.headers.get('content-type', ''),
            'content_length': request.headers.get('content-length', '0')
        }
    
    def _analyze_url(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze URL components for threats"""
        url = request_data['url']
        path = request_data['path']
        query = request_data['query']
        
        # Parse URL components
        url_components = URLAnalysis.parse_url_components(url)
        
        # Detect suspicious parameters
        suspicious_params = []
        if query:
            try:
                query_params = parse_qs(query)
                suspicious_params = URLAnalysis.extract_suspicious_parameters(query_params)
            except Exception:
                pass
        
        # Analyze path characteristics
        path_analysis = {
            'depth': len([p for p in path.split('/') if p]),
            'has_traversal': '..' in path or '%2e%2e' in path.lower(),
            'has_encoded_chars': '%' in path,
            'suspicious_extensions': any(ext in path.lower() for ext in ['.php', '.asp', '.jsp', '.cgi']),
            'admin_paths': any(admin in path.lower() for admin in ['admin', 'login', 'wp-admin', 'management']),
            'backup_patterns': any(backup in path.lower() for backup in ['.bak', '.backup', '.old', '.orig'])
        }
        
        return {
            'components': url_components,
            'suspicious_parameters': suspicious_params,
            'path_analysis': path_analysis,
            'encoded_path': unquote(path),
            'param_count': len(url_components.get('query_params', {})),
            'suspicion_score': self._calculate_url_suspicion_score(path_analysis, suspicious_params)
        }
    
    def _analyze_headers(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP headers for anomalies and tools"""
        headers = request_data['headers']
        user_agent = request_data['user_agent']
        
        # Analyze User-Agent
        ua_analysis = URLAnalysis.analyze_user_agent(user_agent)
        
        # Check for suspicious headers
        suspicious_headers = []
        header_anomalies = []
        
        # Common attack tool headers
        tool_headers = [
            'x-originating-ip', 'x-remote-ip', 'x-forwarded-for',
            'x-real-ip', 'x-cluster-client-ip', 'x-forwarded',
            'forwarded-for', 'forwarded'
        ]
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            
            # Check for tool-specific headers
            if header_lower in tool_headers:
                suspicious_headers.append({
                    'name': header_name,
                    'value': header_value,
                    'reason': 'potential_ip_spoofing'
                })
            
            # Check for unusual header values
            if len(header_value) > 1000:
                header_anomalies.append({
                    'name': header_name,
                    'issue': 'unusually_long_value',
                    'length': len(header_value)
                })
        
        # Missing common headers (could indicate automation)
        expected_headers = ['accept', 'accept-language', 'accept-encoding']
        missing_headers = [h for h in expected_headers if h not in [k.lower() for k in headers.keys()]]
        
        return {
            'user_agent_analysis': ua_analysis,
            'suspicious_headers': suspicious_headers,
            'header_anomalies': header_anomalies,
            'missing_headers': missing_headers,
            'header_count': len(headers),
            'is_suspicious': ua_analysis['is_suspicious'] or len(suspicious_headers) > 0
        }
    
    async def _analyze_payload(self, request: Request) -> Dict[str, Any]:
        """Analyze request payload/body"""
        try:
            body = await request.body()
            if not body:
                return {'has_payload': False, 'size': 0}
            
            body_str = body.decode('utf-8', errors='ignore')
            
            # Analyze payload content
            payload_analysis = {
                'has_payload': True,
                'size': len(body),
                'content_preview': body_str[:500] if len(body_str) > 500 else body_str,
                'is_json': False,
                'is_xml': False,
                'is_form_data': False,
                'suspicious_patterns': []
            }
            
            # Detect content type
            content_type = request.headers.get('content-type', '').lower()
            if 'json' in content_type:
                payload_analysis['is_json'] = True
            elif 'xml' in content_type:
                payload_analysis['is_xml'] = True
            elif 'form' in content_type:
                payload_analysis['is_form_data'] = True
            
            # Check for suspicious patterns in payload
            suspicious_patterns = self._detect_payload_patterns(body_str)
            payload_analysis['suspicious_patterns'] = suspicious_patterns
            
            return payload_analysis
            
        except Exception as e:
            return {'has_payload': False, 'size': 0, 'error': str(e)}
    
    def _detect_attack_patterns(self, request_data: Dict[str, Any], payload_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Detect various attack patterns"""
        url = request_data['url']
        path = request_data['path']
        query = request_data['query']
        headers = request_data['headers']
        
        # Combine all text for analysis
        combined_text = f"{url} {query}"
        if payload_analysis.get('has_payload'):
            combined_text += f" {payload_analysis.get('content_preview', '')}"
        
        # Run pattern detection
        sql_result = AttackDetection.detect_sql_injection(combined_text)
        xss_result = AttackDetection.detect_xss(combined_text) 
        cmd_result = AttackDetection.detect_command_injection(combined_text)
        path_traversal_result = AttackDetection.detect_path_traversal(combined_text)
        
        # Check for additional attack types
        additional_attacks = self._detect_additional_attacks(request_data, payload_analysis)
        
        return {
            'sql_injection': sql_result,
            'xss': xss_result,
            'command_injection': cmd_result,
            'path_traversal': path_traversal_result,
            'additional_attacks': additional_attacks,
            'total_detections': sum([
                sql_result['detected'], xss_result['detected'],
                cmd_result['detected'], path_traversal_result['detected']
            ]) + len(additional_attacks),
            'max_confidence': max([
                sql_result['confidence'], xss_result['confidence'],
                cmd_result['confidence'], path_traversal_result['confidence']
            ])
        }
    
    def _detect_attack_tools(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect attack tools and scanners"""
        user_agent = request_data['user_agent']
        headers = request_data['headers']
        path = request_data['path']
        
        detected_tools = []
        tool_confidence = 0.0
        
        # Check user agent for known tools
        tool_signatures = self.vuln_config.get('tool_signatures', {})
        
        for tool_name, signature_data in tool_signatures.items():
            # Check user agent patterns
            ua_patterns = signature_data.get('user_agents', [])
            for pattern in ua_patterns:
                if pattern.lower() in user_agent.lower():
                    detected_tools.append({
                        'tool': tool_name,
                        'confidence': 0.9,
                        'evidence': f"User-Agent: {pattern}",
                        'threat_score': signature_data.get('threat_score', 50)
                    })
                    tool_confidence = max(tool_confidence, 0.9)
            
            # Check for tool-specific headers
            tool_headers = signature_data.get('headers', [])
            for header_name in tool_headers:
                if header_name.lower() in [h.lower() for h in headers.keys()]:
                    detected_tools.append({
                        'tool': tool_name,
                        'confidence': 0.8,
                        'evidence': f"Header: {header_name}",
                        'threat_score': signature_data.get('threat_score', 50)
                    })
                    tool_confidence = max(tool_confidence, 0.8)
            
            # Check for tool-specific patterns
            tool_patterns = signature_data.get('patterns', [])
            for pattern in tool_patterns:
                if pattern.lower() in path.lower():
                    detected_tools.append({
                        'tool': tool_name,
                        'confidence': 0.7,
                        'evidence': f"Path pattern: {pattern}",
                        'threat_score': signature_data.get('threat_score', 50)
                    })
                    tool_confidence = max(tool_confidence, 0.7)
        
        return {
            'detected_tools': detected_tools,
            'tool_count': len(detected_tools),
            'max_confidence': tool_confidence,
            'is_automated': len(detected_tools) > 0 or self._detect_automation_patterns(request_data)
        }
    
    def _analyze_vulnerabilities(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze for specific vulnerability targeting"""
        path = request_data['path']
        query = request_data['query']
        
        detected_cves = []
        vuln_score = 0
        
        # Check for CVE-specific patterns
        cve_simulations = self.vuln_config.get('cve_simulations', {})
        
        for cve_id, cve_data in cve_simulations.items():
            cve_paths = cve_data.get('paths', [])
            for cve_path in cve_paths:
                if cve_path.lower() in path.lower() or cve_path.lower() in query.lower():
                    detected_cves.append({
                        'cve_id': cve_id,
                        'description': cve_data.get('description', ''),
                        'threat_score': cve_data.get('threat_score', 70),
                        'matched_path': cve_path
                    })
                    vuln_score = max(vuln_score, cve_data.get('threat_score', 70))
        
        # Check for honeypot traps
        honeypot_hits = self._check_honeypot_traps(request_data)
        
        return {
            'detected_cves': detected_cves,
            'cve_count': len(detected_cves),
            'honeypot_hits': honeypot_hits,
            'vulnerability_score': vuln_score,
            'targeting_specific_vulns': len(detected_cves) > 0
        }
    
    def _calculate_threat_score(self, attack_analysis: Dict[str, Any], tool_analysis: Dict[str, Any], 
                              vulnerability_analysis: Dict[str, Any], url_analysis: Dict[str, Any]) -> float:
        """Calculate overall threat score using weighted factors"""
        
        # Base scores from different analysis components
        vulnerability_score = vulnerability_analysis.get('vulnerability_score', 0)
        tool_detection_score = (tool_analysis.get('max_confidence', 0) * 100)
        attack_pattern_score = (attack_analysis.get('max_confidence', 0) * 100)
        url_suspicion_score = url_analysis.get('suspicion_score', 0)
        
        # Apply weights
        weighted_score = (
            vulnerability_score * self.scoring_weights.get('vulnerability_score', 0.4) +
            tool_detection_score * self.scoring_weights.get('tool_detection', 0.3) +
            attack_pattern_score * 0.2 +  # Pattern detection weight
            url_suspicion_score * 0.1      # URL suspicion weight
        )
        
        # Boost score for multiple attack types
        if attack_analysis.get('total_detections', 0) > 1:
            weighted_score *= 1.2
        
        # Boost score for known CVE targeting
        if vulnerability_analysis.get('cve_count', 0) > 0:
            weighted_score *= 1.3
        
        return min(weighted_score, 100.0)  # Cap at 100
    
    def _classify_threat_level(self, threat_score: float) -> str:
        """Classify threat level based on score"""
        if threat_score >= self.threat_thresholds['critical']:
            return 'critical'
        elif threat_score >= self.threat_thresholds['high']:
            return 'high'
        elif threat_score >= self.threat_thresholds['medium']:
            return 'medium'
        elif threat_score >= self.threat_thresholds['low']:
            return 'low'
        else:
            return 'minimal'
    
    def _determine_primary_attack_type(self, attack_analysis: Dict[str, Any]) -> str:
        """Determine the primary attack type"""
        # Check which attack type has highest confidence
        attack_types = {
            'sql_injection': attack_analysis.get('sql_injection', {}).get('confidence', 0),
            'xss': attack_analysis.get('xss', {}).get('confidence', 0),
            'command_injection': attack_analysis.get('command_injection', {}).get('confidence', 0),
            'path_traversal': attack_analysis.get('path_traversal', {}).get('confidence', 0)
        }
        
        # Add additional attack types
        additional = attack_analysis.get('additional_attacks', [])
        for attack in additional:
            attack_types[attack['type']] = attack.get('confidence', 0)
        
        if not attack_types or max(attack_types.values()) == 0:
            return 'reconnaissance'
        
        return max(attack_types, key=attack_types.get)
    
    def _calculate_confidence(self, attack_analysis: Dict[str, Any], tool_analysis: Dict[str, Any]) -> float:
        """Calculate overall confidence in threat assessment"""
        attack_confidence = attack_analysis.get('max_confidence', 0)
        tool_confidence = tool_analysis.get('max_confidence', 0)
        
        # Combine confidences
        combined_confidence = max(attack_confidence, tool_confidence)
        
        # Boost confidence if multiple indicators
        if attack_analysis.get('total_detections', 0) > 1:
            combined_confidence = min(combined_confidence + 0.1, 1.0)
        
        if tool_analysis.get('tool_count', 0) > 0:
            combined_confidence = min(combined_confidence + 0.1, 1.0)
        
        return combined_confidence
    
    def _generate_recommendations(self, threat_level: str, attack_analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on threat analysis"""
        recommendations = []
        
        if threat_level in ['high', 'critical']:
            recommendations.append("Immediate investigation required")
            recommendations.append("Consider blocking source IP")
            
        if attack_analysis.get('sql_injection', {}).get('detected'):
            recommendations.append("SQL injection attempt detected - review database security")
            
        if attack_analysis.get('command_injection', {}).get('detected'):
            recommendations.append("Command injection detected - review input validation")
            
        if attack_analysis.get('xss', {}).get('detected'):
            recommendations.append("XSS attempt detected - review output encoding")
            
        if attack_analysis.get('path_traversal', {}).get('detected'):
            recommendations.append("Path traversal detected - review file access controls")
        
        return recommendations
    
    async def _log_threat_intelligence(self, analysis_result: Dict[str, Any]):
        """Log comprehensive threat intelligence"""
        correlation_id = analysis_result['correlation_id']
        threat_score = analysis_result['threat_score']
        threat_level = analysis_result['threat_level']
        attack_type = analysis_result['attack_type']
        
        # Log to structured logger
        self.logger.log_threat(
            correlation_id=correlation_id,
            threat_type=attack_type,
            threat_score=int(threat_score),
            details={
                'threat_level': threat_level,
                'confidence': analysis_result['confidence'],
                'detected_tools': [t['tool'] for t in analysis_result['tool_analysis']['detected_tools']],
                'attack_patterns': analysis_result['attack_analysis']['total_detections'],
                'processing_time': analysis_result['processing_time']
            }
        )
    
    # Helper methods
    def _calculate_url_suspicion_score(self, path_analysis: Dict[str, Any], suspicious_params: List[Dict[str, Any]]) -> float:
        """Calculate suspicion score for URL"""
        score = 0
        
        if path_analysis['has_traversal']:
            score += 30
        if path_analysis['admin_paths']:
            score += 20
        if path_analysis['backup_patterns']:
            score += 25
        if len(suspicious_params) > 0:
            score += 30
        if path_analysis['depth'] > 5:
            score += 10
        
        return min(score, 100)
    
    def _detect_payload_patterns(self, payload: str) -> List[Dict[str, Any]]:
        """Detect suspicious patterns in payload"""
        patterns = []
        
        # SQL injection patterns
        sql_patterns = ["'", "union select", "drop table", "insert into"]
        for pattern in sql_patterns:
            if pattern.lower() in payload.lower():
                patterns.append({'type': 'sql_injection', 'pattern': pattern})
        
        # Command injection patterns  
        cmd_patterns = ["system(", "exec(", "shell_exec(", "passthru("]
        for pattern in cmd_patterns:
            if pattern.lower() in payload.lower():
                patterns.append({'type': 'command_injection', 'pattern': pattern})
        
        return patterns
    
    def _detect_additional_attacks(self, request_data: Dict[str, Any], payload_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect additional attack types beyond common patterns"""
        attacks = []
        path = request_data['path']
        
        # File upload attacks
        if request_data['method'] == 'POST' and 'upload' in path.lower():
            attacks.append({'type': 'file_upload', 'confidence': 0.6})
        
        # Brute force indicators
        if 'login' in path.lower() and request_data['method'] == 'POST':
            attacks.append({'type': 'credential_brute_force', 'confidence': 0.5})
        
        # Directory traversal
        if '../' in path or '..\\' in path:
            attacks.append({'type': 'directory_traversal', 'confidence': 0.8})
        
        return attacks
    
    def _detect_automation_patterns(self, request_data: Dict[str, Any]) -> bool:
        """Detect if request appears to be automated"""
        headers = request_data['headers']
        user_agent = request_data['user_agent']
        
        # Missing common browser headers
        browser_headers = ['accept-language', 'accept-encoding', 'cache-control']
        missing_count = sum(1 for h in browser_headers if h not in [k.lower() for k in headers.keys()])
        
        # Simple user agents
        simple_ua_patterns = ['curl', 'wget', 'python', 'bot', 'crawler']
        is_simple_ua = any(pattern in user_agent.lower() for pattern in simple_ua_patterns)
        
        return missing_count >= 2 or is_simple_ua
    
    def _check_honeypot_traps(self, request_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if request hits honeypot traps"""
        path = request_data['path']
        hits = []
        
        honeypot_traps = self.vuln_config.get('honeypot_traps', {})
        
        # Check fake admin panels
        fake_admins = honeypot_traps.get('fake_admin_panels', [])
        for admin_trap in fake_admins:
            if admin_trap.get('path', '').lower() in path.lower():
                hits.append({
                    'type': 'fake_admin_panel',
                    'path': admin_trap['path'],
                    'score': 40
                })
        
        # Check fake files
        fake_files = honeypot_traps.get('fake_databases', []) + honeypot_traps.get('fake_configs', [])
        for file_trap in fake_files:
            if file_trap.get('path', '').lower() in path.lower():
                hits.append({
                    'type': 'fake_sensitive_file',
                    'path': file_trap['path'],
                    'score': 60
                })
        
        return hits


# Singleton intelligence engine
intelligence_engine = None

def get_intelligence_engine() -> ThreatAnalyzer:
    """Get global intelligence engine instance"""
    global intelligence_engine
    if intelligence_engine is None:
        intelligence_engine = ThreatAnalyzer()
    return intelligence_engine
