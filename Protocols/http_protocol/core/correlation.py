# core/correlation.py

import time
from typing import Dict, Any
from utils.logger import setup_logger

class SessionTracker:
    """Simple session correlation engine"""
    
    def __init__(self, correlation_window: int = 3600):
        self.correlation_window = correlation_window
        self.sessions = {}
        self.logger = setup_logger()
        
    async def correlate_event(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate event with existing sessions"""
        try:
            source_ip = analysis_result.get('request_data', {}).get('client_ip', 'unknown')
            correlation_id = analysis_result.get('correlation_id', 'unknown')
            
            # Simple session ID based on IP
            session_id = f"SES_{hash(source_ip) & 0xFFFFFFFF:08x}"
            
            # Get or create session
            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    'session_id': session_id,
                    'source_ip': source_ip,
                    'start_time': time.time(),
                    'event_count': 0,
                    'total_threat_score': 0
                }
            
            session = self.sessions[session_id]
            session['event_count'] += 1
            session['total_threat_score'] += analysis_result.get('threat_score', 0)
            session['last_activity'] = time.time()
            
            # Log session info
            self.logger.info(f"Session correlation: {session_id} - {session['event_count']} events, threat score: {session['total_threat_score']}")
            
            return {
                'session': session,
                'correlation_metadata': {
                    'session_id': session_id,
                    'is_new_session': session['event_count'] == 1,
                    'correlation_score': min(session['event_count'] / 10.0, 1.0)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Correlation error: {e}")
            return {
                'session': {'session_id': 'error', 'event_count': 0},
                'correlation_metadata': {'error': str(e)}
            }
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        return {
            'active_sessions': len(self.sessions),
            'active_campaigns': 0,
            'total_events': sum(s.get('event_count', 0) for s in self.sessions.values())
        }

# Global instance
_correlation_engine = None

def get_correlation_engine() -> SessionTracker:
    """Get global correlation engine instance"""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = SessionTracker()
    return _correlation_engine
