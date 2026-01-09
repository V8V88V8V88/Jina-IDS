"""
Jina IDS - Professional Intrusion Detection Engine
Main Detection Orchestrator
"""

import logging
import threading
import time
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from collections import defaultdict

from core.packet_capture import PacketCapture, PacketInfo
from core.analyzer import TrafficAnalyzer, AnalysisResult
from core.rule_engine import Alert

logger = logging.getLogger("JinaIDS.Detector")


@dataclass
class DetectionStats:
    """Statistics from detection engine."""
    start_time: datetime = field(default_factory=datetime.now)
    packets_processed: int = 0
    alerts_generated: int = 0
    alerts_by_severity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    alerts_by_category: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    def update(self, alerts: List[Alert]):
        for alert in alerts:
            self.alerts_generated += 1
            self.alerts_by_severity[alert.severity] += 1
            self.alerts_by_category[alert.category] += 1
    
    def to_dict(self) -> Dict:
        elapsed = (datetime.now() - self.start_time).total_seconds()
        return {
            "uptime_seconds": elapsed,
            "packets_processed": self.packets_processed,
            "packets_per_second": self.packets_processed / elapsed if elapsed > 0 else 0,
            "alerts_generated": self.alerts_generated,
            "alerts_by_severity": dict(self.alerts_by_severity),
            "alerts_by_category": dict(self.alerts_by_category)
        }


class IntrusionDetector:
    """
    Main Intrusion Detection Engine - orchestrates all detection components.
    
    Features:
    - Real-time packet capture and analysis
    - Multi-threaded processing
    - Alert aggregation and deduplication
    - Callback system for alerts
    - Statistics and reporting
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # Initialize components
        capture_config = self.config.get("capture", {})
        analysis_config = self.config.get("analysis", {})
        
        self.packet_capture = PacketCapture(capture_config)
        self.analyzer = TrafficAnalyzer(analysis_config)
        
        # Detection settings
        self.enable_ml = self.config.get("enable_ml", True)
        self.enable_signatures = self.config.get("enable_signatures", True)
        
        # State
        self.is_running = False
        self.detection_thread: Optional[threading.Thread] = None
        self.stats = DetectionStats()
        
        # Alert handling
        self.alert_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.alert_callbacks: List[Callable[[Alert], None]] = []
        self.recent_alerts: Dict[str, datetime] = {}  # For deduplication
        self.alert_aggregation_window = self.config.get("aggregation_window", 60)
        
        # ML detector (lazy initialization)
        self._ml_detector = None
        
        logger.info("Intrusion Detector initialized")
    
    @property
    def ml_detector(self):
        """Lazy load ML detector."""
        if self._ml_detector is None and self.enable_ml:
            try:
                from ml.detector import MLAnomalyDetector
                self._ml_detector = MLAnomalyDetector()
                logger.info("ML Anomaly Detector loaded")
            except Exception as e:
                logger.warning(f"Could not load ML detector: {e}")
                self._ml_detector = False  # Mark as failed
        return self._ml_detector if self._ml_detector else None
    
    def register_alert_callback(self, callback: Callable[[Alert], None]):
        """Register a callback to be called for each alert."""
        self.alert_callbacks.append(callback)
    
    def _should_alert(self, alert: Alert) -> bool:
        """Check if alert should be generated (deduplication)."""
        # Create deduplication key
        key = f"{alert.rule_id}:{alert.src_ip}:{alert.dst_ip}"
        
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.alert_aggregation_window)
        
        # Check if we've seen this recently
        if key in self.recent_alerts:
            if self.recent_alerts[key] > cutoff:
                return False  # Suppress duplicate
        
        self.recent_alerts[key] = now
        
        # Clean old entries periodically
        if len(self.recent_alerts) > 10000:
            self.recent_alerts = {
                k: v for k, v in self.recent_alerts.items()
                if v > cutoff
            }
        
        return True
    
    def _process_alert(self, alert: Alert):
        """Process and distribute an alert."""
        if not self._should_alert(alert):
            return
        
        # Add to queue
        try:
            self.alert_queue.put_nowait(alert)
        except queue.Full:
            logger.warning("Alert queue full, dropping alert")
        
        # Call registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
        
        # Log the alert
        severity_colors = {
            "critical": "\033[91m",  # Red
            "high": "\033[93m",      # Yellow
            "medium": "\033[94m",    # Blue
            "low": "\033[92m",       # Green
        }
        reset = "\033[0m"
        color = severity_colors.get(alert.severity, "")
        
        logger.warning(f"{color}[ALERT] {alert}{reset}")
    
    def _detection_loop(self):
        """Main detection loop running in separate thread."""
        logger.info("Detection loop started")
        
        while self.is_running:
            try:
                # Get packets from capture
                packets = self.packet_capture.get_packets(max_count=100, timeout=0.1)
                
                if not packets:
                    continue
                
                # Analyze packets
                result = self.analyzer.analyze_packets(packets)
                self.stats.packets_processed += result.packets_analyzed
                
                # Process alerts from signature detection
                for alert in result.alerts:
                    self._process_alert(alert)
                    self.stats.update([alert])
                
                # ML-based detection (if enabled)
                if self.ml_detector:
                    for packet in packets:
                        try:
                            ml_result = self.ml_detector.predict(packet)
                            if ml_result and ml_result.is_anomaly:
                                alert = Alert(
                                    timestamp=datetime.now(),
                                    rule_id="ML-ANOMALY",
                                    rule_name="ML Anomaly Detection",
                                    severity="medium",
                                    category="anomaly",
                                    description=f"ML detected anomaly (score: {ml_result.score:.2f})",
                                    src_ip=packet.src_ip,
                                    dst_ip=packet.dst_ip,
                                    src_port=packet.src_port,
                                    dst_port=packet.dst_port,
                                    protocol=packet.protocol,
                                    mitre_attack="T1071"
                                )
                                self._process_alert(alert)
                                self.stats.update([alert])
                        except Exception as e:
                            logger.debug(f"ML detection error: {e}")
                
            except Exception as e:
                logger.error(f"Detection loop error: {e}")
                time.sleep(0.1)
        
        logger.info("Detection loop stopped")
    
    def start(self, background: bool = True):
        """Start the intrusion detection system."""
        if self.is_running:
            logger.warning("Detector already running")
            return True
        
        logger.info("Starting Intrusion Detection System...")
        
        # Start packet capture
        if not self.packet_capture.start_capture(background=True):
            logger.error("Failed to start packet capture")
            return False
        
        self.is_running = True
        self.stats = DetectionStats()
        
        if background:
            self.detection_thread = threading.Thread(
                target=self._detection_loop,
                daemon=True,
                name="DetectionThread"
            )
            self.detection_thread.start()
            logger.info("Detection started in background")
        else:
            self._detection_loop()
        
        return True
    
    def stop(self):
        """Stop the intrusion detection system."""
        if not self.is_running:
            return
        
        logger.info("Stopping Intrusion Detection System...")
        
        self.is_running = False
        
        # Stop capture
        self.packet_capture.stop_capture()
        
        # Wait for detection thread
        if self.detection_thread and self.detection_thread.is_alive():
            self.detection_thread.join(timeout=5)
        
        logger.info("Intrusion Detection System stopped")
    
    def get_alerts(self, max_count: int = 100) -> List[Alert]:
        """Get recent alerts from queue."""
        alerts = []
        while len(alerts) < max_count:
            try:
                alert = self.alert_queue.get_nowait()
                alerts.append(alert)
            except queue.Empty:
                break
        return alerts
    
    def detect_intrusions(self, analysis: AnalysisResult) -> List[Alert]:
        """Process analysis result and generate alerts (for compatibility)."""
        for alert in analysis.alerts:
            self._process_alert(alert)
        return analysis.alerts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive detection statistics."""
        stats = self.stats.to_dict()
        stats["capture"] = self.packet_capture.get_stats()
        stats["analysis"] = self.analyzer.get_analysis_stats()
        stats["is_running"] = self.is_running
        return stats
    
    def get_status(self) -> Dict[str, Any]:
        """Get current detector status."""
        return {
            "running": self.is_running,
            "capture_active": self.packet_capture.is_running,
            "interface": self.packet_capture.interface,
            "ml_enabled": self.ml_detector is not None,
            "stats": self.stats.to_dict()
        }


# Backward compatibility
ThreatDetector = IntrusionDetector


class DetectorBuilder:
    """Builder pattern for creating configured detector."""
    
    def __init__(self):
        self.config = {
            "capture": {},
            "analysis": {},
            "detection": {}
        }
    
    def with_interface(self, interface: str) -> 'DetectorBuilder':
        self.config["capture"]["interface"] = interface
        return self
    
    def with_ml(self, enabled: bool = True) -> 'DetectorBuilder':
        self.config["detection"]["enable_ml"] = enabled
        return self
    
    def with_rules(self, rules_file: str) -> 'DetectorBuilder':
        self.config["analysis"]["rules"] = rules_file
        return self
    
    def with_alert_callback(self, callback: Callable[[Alert], None]) -> 'DetectorBuilder':
        if "callbacks" not in self.config:
            self.config["callbacks"] = []
        self.config["callbacks"].append(callback)
        return self
    
    def build(self) -> IntrusionDetector:
        detector = IntrusionDetector(self.config)
        for callback in self.config.get("callbacks", []):
            detector.register_alert_callback(callback)
        return detector


if __name__ == "__main__":
    # Test the detector
    import json
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    def alert_handler(alert: Alert):
        print(f"ALERT HANDLER: {alert}")
    
    # Create detector using builder
    detector = (DetectorBuilder()
                .with_interface("auto")
                .with_ml(False)
                .with_alert_callback(alert_handler)
                .build())
    
    print("Starting detector (requires root for packet capture)...")
    detector.start()
    
    try:
        # Run for 30 seconds
        for i in range(30):
            time.sleep(1)
            if i % 5 == 0:
                print(f"\nStats at {i}s:")
                print(json.dumps(detector.get_status(), indent=2, default=str))
    except KeyboardInterrupt:
        print("\nInterrupted")
    finally:
        detector.stop()
        print("\nFinal Stats:")
        print(json.dumps(detector.get_stats(), indent=2, default=str))
