"""
Jina IDS Core Module
Network Intrusion Detection Components
"""

from core.packet_capture import PacketCapture, PacketInfo
from core.analyzer import TrafficAnalyzer, AnalysisResult
from core.detector import IntrusionDetector, DetectionStats, DetectorBuilder
from core.rule_engine import RuleEngine, DetectionRule, Alert

__all__ = [
    # Packet Capture
    "PacketCapture",
    "PacketInfo",
    
    # Traffic Analysis
    "TrafficAnalyzer", 
    "AnalysisResult",
    
    # Intrusion Detection
    "IntrusionDetector",
    "DetectionStats",
    "DetectorBuilder",
    
    # Rule Engine
    "RuleEngine",
    "DetectionRule",
    "Alert"
]

__version__ = "2.0.0"
