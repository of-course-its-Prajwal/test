# anomaly_detector.py — ML-based Anomaly Detection Module
from collections import deque
from datetime import datetime, timedelta
import statistics

class AnomalyDetector:
    """Detects unusual file change patterns using statistical analysis"""
    
    def __init__(self, window_size=60, threshold=2.5):
        """
        window_size: Time window in seconds to analyze
        threshold: Standard deviations from mean to trigger alert
        """
        self.window_size = window_size
        self.threshold = threshold
        self.event_timestamps = deque(maxlen=1000)
        self.baseline_rate = 0
        self.baseline_samples = []
        self.learning_phase = True
        self.learning_count = 0
        self.learning_threshold = 50  # Events to learn normal behavior
        
    def record_event(self, event_type="change"):
        """Record a file system event"""
        now = datetime.now()
        self.event_timestamps.append(now)
        
        # Calculate current rate (events per minute)
        current_rate = self._calculate_rate()
        
        # Learning phase: build baseline
        if self.learning_phase:
            self.baseline_samples.append(current_rate)
            self.learning_count += 1
            
            if self.learning_count >= self.learning_threshold:
                self.learning_phase = False
                self.baseline_rate = statistics.mean(self.baseline_samples)
                
            return False, current_rate, "Learning"
        
        # Detection phase: check for anomalies
        is_anomaly = self._is_anomalous(current_rate)
        status = "ANOMALY DETECTED!" if is_anomaly else "Normal"
        
        return is_anomaly, current_rate, status
    
    def _calculate_rate(self):
        """Calculate events per minute in the time window"""
        if len(self.event_timestamps) < 2:
            return 0
        
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_size)
        
        # Count events in time window
        recent_events = [t for t in self.event_timestamps if t >= cutoff]
        
        if not recent_events:
            return 0
        
        # Convert to events per minute
        time_span = (now - recent_events[0]).total_seconds() / 60
        if time_span == 0:
            return 0
            
        return len(recent_events) / time_span
    
    def _is_anomalous(self, current_rate):
        """Check if current rate is anomalous"""
        if len(self.baseline_samples) < 10:
            return False
        
        mean = statistics.mean(self.baseline_samples)
        
        try:
            stdev = statistics.stdev(self.baseline_samples)
        except:
            stdev = 0
        
        if stdev == 0:
            # If no variation, only flag if rate is much higher
            return current_rate > mean * 3
        
        # Z-score based detection
        z_score = abs((current_rate - mean) / stdev)
        
        return z_score > self.threshold
    
    def get_statistics(self):
        """Get current statistics"""
        current_rate = self._calculate_rate()
        
        stats = {
            "current_rate": round(current_rate, 2),
            "baseline_rate": round(self.baseline_rate, 2),
            "total_events": len(self.event_timestamps),
            "learning_phase": self.learning_phase,
            "learning_progress": f"{self.learning_count}/{self.learning_threshold}"
        }
        
        if len(self.baseline_samples) >= 2:
            try:
                stats["stdev"] = round(statistics.stdev(self.baseline_samples), 2)
            except:
                stats["stdev"] = 0
        
        return stats
    
    def reset(self):
        """Reset the detector"""
        self.event_timestamps.clear()
        self.baseline_samples.clear()
        self.learning_phase = True
        self.learning_count = 0
        self.baseline_rate = 0