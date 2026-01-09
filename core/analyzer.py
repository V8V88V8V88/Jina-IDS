"""
Jina IDS - Professional Traffic Analyzer
Real-time Network Analysis with Anomaly Detection
"""

import logging
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
import statistics

from core.rule_engine import RuleEngine, Alert
from core.packet_capture import PacketInfo

logger = logging.getLogger("JinaIDS.Analyzer")


@dataclass
class ConnectionState:
    """Track state of a network connection."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    flags_seen: set = field(default_factory=set)
    
    @property
    def connection_id(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}"
    
    @property
    def duration(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()


@dataclass
class HostProfile:
    """Profile for a network host to detect anomalies."""
    ip: str
    first_seen: datetime
    last_seen: datetime
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    unique_dst_ports: set = field(default_factory=set)
    unique_dst_ips: set = field(default_factory=set)
    protocols_used: set = field(default_factory=set)
    failed_connections: int = 0
    # Enhanced tracking for real scan detection
    syn_only_ports: set = field(default_factory=set)  # Ports with only SYN, no ACK
    rst_received: set = field(default_factory=set)  # Ports that sent RST
    successful_connections: set = field(default_factory=set)  # Ports with successful handshake
    port_connection_map: Dict[int, Dict] = field(default_factory=dict)  # Track each port's connection state
    
    def update(self, packet: PacketInfo, is_source: bool):
        self.last_seen = packet.timestamp
        if is_source:
            self.packets_sent += 1
            self.bytes_sent += packet.length
            self.unique_dst_ports.add(packet.dst_port)
            self.unique_dst_ips.add(packet.dst_ip)
            
            # Track connection state for scan detection
            if packet.dst_port not in self.port_connection_map:
                self.port_connection_map[packet.dst_port] = {
                    'syn_sent': False,
                    'syn_ack_received': False,  # SYN-ACK from destination
                    'ack_sent': False,  # ACK we sent
                    'rst_received': False,
                    'data_exchanged': False,
                    'first_syn': None,
                    'packet_count': 0
                }
            
            port_state = self.port_connection_map[packet.dst_port]
            port_state['packet_count'] += 1
            
            # Check TCP flags from source perspective
            flags = packet.flags
            if "SYN" in flags and "ACK" not in flags:
                # Initial SYN sent
                port_state['syn_sent'] = True
                if port_state['first_syn'] is None:
                    port_state['first_syn'] = packet.timestamp
                self.syn_only_ports.add(packet.dst_port)
            elif "ACK" in flags and port_state['syn_sent']:
                # ACK sent (after receiving SYN-ACK)
                port_state['ack_sent'] = True
                if port_state['syn_ack_received']:
                    self.successful_connections.add(packet.dst_port)
            
            # Check if data was exchanged (indicates successful connection)
            if packet.payload and len(packet.payload) > 0:
                port_state['data_exchanged'] = True
                self.successful_connections.add(packet.dst_port)
        else:
            # Packet received (from destination)
            self.packets_received += 1
            self.bytes_received += packet.length
            
            # Check for SYN-ACK or RST responses
            flags = packet.flags
            if "SYN" in flags and "ACK" in flags:
                # Received SYN-ACK (connection accepted)
                if packet.src_port in self.port_connection_map:
                    self.port_connection_map[packet.src_port]['syn_ack_received'] = True
                    if self.port_connection_map[packet.src_port]['ack_sent']:
                        self.successful_connections.add(packet.src_port)
            elif "RST" in flags:
                # Received RST (connection refused/closed)
                if packet.src_port in self.port_connection_map:
                    self.port_connection_map[packet.src_port]['rst_received'] = True
                    self.rst_received.add(packet.src_port)
                    # Remove from syn_only if we got RST
                    self.syn_only_ports.discard(packet.src_port)
        
        self.protocols_used.add(packet.protocol)


@dataclass
class AnalysisResult:
    """Result of traffic analysis containing alerts and statistics."""
    alerts: List[Alert] = field(default_factory=list)
    packets_analyzed: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    stats: Dict[str, Any] = field(default_factory=dict)
    
    def add_alert(self, alert: Alert):
        self.alerts.append(alert)
    
    def merge(self, other: 'AnalysisResult'):
        self.alerts.extend(other.alerts)
        self.packets_analyzed += other.packets_analyzed


class TrafficAnalyzer:
    """
    Professional network traffic analyzer.
    
    Features:
    - Signature-based detection via RuleEngine
    - Behavioral anomaly detection
    - Port scan detection
    - DoS/DDoS detection
    - Connection tracking
    - Host profiling
    - Rate-based analysis
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        # Initialize rule engine
        rules_file = self.config.get("rules", "data/rules/default_rules.json")
        self.rule_engine = RuleEngine(rules_file)
        
        # Connection tracking
        self.connections: Dict[str, ConnectionState] = {}
        self.connection_lock = threading.Lock()
        
        # Host profiles
        self.hosts: Dict[str, HostProfile] = {}
        self.host_lock = threading.Lock()
        
        # Rate tracking for attack detection
        self.rate_tracker: Dict[str, Dict] = defaultdict(lambda: {
            "packets": [],
            "syn_packets": [],
            "icmp_packets": [],
            "udp_packets": [],
            "connections": []
        })
        
        # Detection thresholds
        self.thresholds = {
            "port_scan_ports": self.config.get("port_scan_threshold", 15),
            "port_scan_window": self.config.get("port_scan_window", 60),
            "syn_flood_rate": self.config.get("syn_flood_rate", 100),
            "syn_flood_window": self.config.get("syn_flood_window", 10),
            "icmp_flood_rate": self.config.get("icmp_flood_rate", 50),
            "connection_rate": self.config.get("connection_rate", 50),
            "dns_query_rate": self.config.get("dns_query_rate", 100)
        }
        
        # Statistics
        self.stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        
        logger.info("Traffic Analyzer initialized")
    
    def _get_connection_key(self, packet: PacketInfo) -> str:
        """Generate unique connection key."""
        # Sort to make bidirectional
        endpoints = sorted([
            (packet.src_ip, packet.src_port),
            (packet.dst_ip, packet.dst_port)
        ])
        return f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}-{packet.protocol}"
    
    def _update_connection(self, packet: PacketInfo):
        """Update connection tracking."""
        key = self._get_connection_key(packet)
        
        with self.connection_lock:
            if key not in self.connections:
                self.connections[key] = ConnectionState(
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    first_seen=packet.timestamp,
                    last_seen=packet.timestamp
                )
            
            conn = self.connections[key]
            conn.last_seen = packet.timestamp
            conn.packet_count += 1
            conn.byte_count += packet.length
            
            if "SYN" in packet.flags:
                conn.syn_count += 1
            
            for flag in packet.flags.split(","):
                if flag:
                    conn.flags_seen.add(flag)
    
    def _update_host_profile(self, packet: PacketInfo):
        """Update host profiles for behavioral analysis."""
        with self.host_lock:
            # Update source host
            if packet.src_ip:
                if packet.src_ip not in self.hosts:
                    self.hosts[packet.src_ip] = HostProfile(
                        ip=packet.src_ip,
                        first_seen=packet.timestamp,
                        last_seen=packet.timestamp
                    )
                self.hosts[packet.src_ip].update(packet, is_source=True)
            
            # Update destination host
            if packet.dst_ip:
                if packet.dst_ip not in self.hosts:
                    self.hosts[packet.dst_ip] = HostProfile(
                        ip=packet.dst_ip,
                        first_seen=packet.timestamp,
                        last_seen=packet.timestamp
                    )
                self.hosts[packet.dst_ip].update(packet, is_source=False)
    
    def _update_rate_tracker(self, packet: PacketInfo):
        """Track packet rates for flood detection."""
        src_ip = packet.src_ip
        now = packet.timestamp
        cutoff = now - timedelta(seconds=60)
        
        tracker = self.rate_tracker[src_ip]
        
        # Clean old entries and add new
        tracker["packets"] = [t for t in tracker["packets"] if t > cutoff]
        tracker["packets"].append(now)
        
        if "SYN" in packet.flags and "ACK" not in packet.flags:
            tracker["syn_packets"] = [t for t in tracker["syn_packets"] if t > cutoff]
            tracker["syn_packets"].append(now)
        
        if packet.protocol == "ICMP":
            tracker["icmp_packets"] = [t for t in tracker["icmp_packets"] if t > cutoff]
            tracker["icmp_packets"].append(now)
        
        if packet.protocol == "UDP":
            tracker["udp_packets"] = [t for t in tracker["udp_packets"] if t > cutoff]
            tracker["udp_packets"].append(now)
    
    def detect_port_scan(self, src_ip: str) -> Optional[Alert]:
        """Detect port scanning activity with verification."""
        with self.host_lock:
            host = self.hosts.get(src_ip)
            if not host:
                return None
            
            # Check if scanning by looking at unique destination ports
            duration = (host.last_seen - host.first_seen).total_seconds()
            
            if duration > 0 and len(host.unique_dst_ports) > self.thresholds["port_scan_ports"]:
                # Check if ports were scanned within time window
                if duration <= self.thresholds["port_scan_window"]:
                    # VERIFICATION: Check if this is a REAL scan
                    # Real scans have: many SYN-only attempts, few successful connections, many RSTs
                    total_ports = len(host.unique_dst_ports)
                    syn_only_count = len(host.syn_only_ports)
                    successful_count = len(host.successful_connections)
                    rst_count = len(host.rst_received)
                    
                    # Calculate scan confidence
                    failed_ratio = (syn_only_count - successful_count) / total_ports if total_ports > 0 else 0
                    success_ratio = successful_count / total_ports if total_ports > 0 else 0
                    
                    # REAL SCAN indicators:
                    # 1. High number of SYN-only attempts (no ACK/data)
                    # 2. Low success rate (< 20% connections successful)
                    # 3. Many RST responses (ports closed)
                    # 4. Sequential or random port patterns
                    
                    is_likely_scan = False
                    confidence = "low"
                    
                    if total_ports >= 15:
                        # Check 1: High failure rate
                        if failed_ratio > 0.7:  # 70%+ failed connections
                            is_likely_scan = True
                            confidence = "high"
                        # Check 2: Low success rate with many ports
                        elif success_ratio < 0.2 and total_ports > 20:
                            is_likely_scan = True
                            confidence = "medium"
                        # Check 3: Many RST responses
                        elif rst_count > total_ports * 0.5:
                            is_likely_scan = True
                            confidence = "medium"
                        # Check 4: Many SYN-only with no data exchange
                        elif syn_only_count > total_ports * 0.6 and success_ratio < 0.3:
                            is_likely_scan = True
                            confidence = "high"
                    
                    # Only alert if it's likely a real scan
                    if is_likely_scan:
                        scan_rate = len(host.unique_dst_ports) / duration
                        success_pct = (successful_count / total_ports * 100) if total_ports > 0 else 0
                        
                        return Alert(
                            timestamp=datetime.now(),
                            rule_id="SCAN-PORT",
                            rule_name="Port Scan Detected (Verified)",
                            severity="medium",
                            category="reconnaissance",
                            description=f"VERIFIED SCAN: {total_ports} ports in {duration:.1f}s (rate: {scan_rate:.1f}/s). "
                                      f"Failed: {syn_only_count - successful_count}, Success: {successful_count} ({success_pct:.1f}%), "
                                      f"RST: {rst_count}. Confidence: {confidence}",
                            src_ip=src_ip,
                            mitre_attack="T1046"
                        )
        
        return None
    
    def detect_syn_flood(self, src_ip: str) -> Optional[Alert]:
        """Detect SYN flood attack."""
        tracker = self.rate_tracker[src_ip]
        window = self.thresholds["syn_flood_window"]
        now = datetime.now()
        cutoff = now - timedelta(seconds=window)
        
        recent_syns = [t for t in tracker["syn_packets"] if t > cutoff]
        
        if len(recent_syns) > self.thresholds["syn_flood_rate"]:
            return Alert(
                timestamp=now,
                rule_id="DOS-SYN-FLOOD",
                rule_name="SYN Flood Attack",
                severity="high",
                category="dos",
                description=f"SYN flood: {len(recent_syns)} SYN packets in {window}s",
                src_ip=src_ip,
                mitre_attack="T1499.001"
            )
        
        return None
    
    def detect_icmp_flood(self, src_ip: str) -> Optional[Alert]:
        """Detect ICMP flood attack."""
        tracker = self.rate_tracker[src_ip]
        window = 10
        now = datetime.now()
        cutoff = now - timedelta(seconds=window)
        
        recent_icmp = [t for t in tracker["icmp_packets"] if t > cutoff]
        
        if len(recent_icmp) > self.thresholds["icmp_flood_rate"]:
            return Alert(
                timestamp=now,
                rule_id="DOS-ICMP-FLOOD",
                rule_name="ICMP Flood Attack",
                severity="medium",
                category="dos",
                description=f"ICMP flood: {len(recent_icmp)} ICMP packets in {window}s",
                src_ip=src_ip,
                mitre_attack="T1499.001"
            )
        
        return None
    
    def detect_horizontal_scan(self, src_ip: str) -> Optional[Alert]:
        """Detect horizontal scanning (scanning multiple hosts) with verification."""
        with self.host_lock:
            host = self.hosts.get(src_ip)
            if not host:
                return None
            
            duration = (host.last_seen - host.first_seen).total_seconds()
            
            # If contacting many unique IPs in short time
            if duration > 0 and duration <= 60:
                unique_targets = len(host.unique_dst_ips)
                if unique_targets > 20:
                    # VERIFICATION: Check if this is a REAL horizontal scan
                    # Real scans: many IPs, few successful connections per IP
                    # Legitimate: fewer IPs OR many successful connections
                    
                    # Calculate average ports per target IP
                    avg_ports_per_ip = len(host.unique_dst_ports) / unique_targets if unique_targets > 0 else 0
                    success_ratio = len(host.successful_connections) / len(host.unique_dst_ports) if len(host.unique_dst_ports) > 0 else 0
                    
                    # REAL SCAN indicators:
                    # 1. Many IPs with few ports each (probing)
                    # 2. Low success rate across all targets
                    # 3. Sequential IP ranges
                    
                    is_likely_scan = False
                    confidence = "low"
                    
                    if unique_targets >= 20:
                        # Check 1: Low ports per IP (probing behavior)
                        if avg_ports_per_ip < 3 and unique_targets > 25:
                            is_likely_scan = True
                            confidence = "high"
                        # Check 2: Low success rate with many targets
                        elif success_ratio < 0.2 and unique_targets > 25:
                            is_likely_scan = True
                            confidence = "medium"
                        # Check 3: Many targets in short time (aggressive scanning)
                        elif unique_targets > 30 and duration < 30:
                            is_likely_scan = True
                            confidence = "high"
                    
                    # Only alert if it's likely a real scan
                    if is_likely_scan:
                        return Alert(
                            timestamp=datetime.now(),
                            rule_id="SCAN-HORIZONTAL",
                            rule_name="Horizontal Scan Detected (Verified)",
                            severity="medium",
                            category="reconnaissance",
                            description=f"VERIFIED SCAN: {unique_targets} unique IPs in {duration:.1f}s. "
                                      f"Avg ports/IP: {avg_ports_per_ip:.1f}, Success rate: {success_ratio*100:.1f}%. "
                                      f"Confidence: {confidence}",
                            src_ip=src_ip,
                            mitre_attack="T1046"
                        )
        
        return None
    
    def analyze_packet(self, packet: PacketInfo) -> AnalysisResult:
        """
        Analyze a single packet for threats.
        
        Returns AnalysisResult with any generated alerts.
        """
        result = AnalysisResult(packets_analyzed=1, timestamp=packet.timestamp)
        
        # Update tracking
        self._update_connection(packet)
        self._update_host_profile(packet)
        self._update_rate_tracker(packet)
        
        # Update statistics
        self.stats["total_packets"] += 1
        self.protocol_stats[packet.protocol] += 1
        
        # 1. Signature-based detection
        signature_alerts = self.rule_engine.check_packet(packet)
        for alert in signature_alerts:
            result.add_alert(alert)
        
        # 2. Rate-based attack detection
        src_ip = packet.src_ip
        
        # Port scan detection (check periodically, not every packet)
        if self.stats["total_packets"] % 100 == 0:
            scan_alert = self.detect_port_scan(src_ip)
            if scan_alert:
                result.add_alert(scan_alert)
            
            h_scan_alert = self.detect_horizontal_scan(src_ip)
            if h_scan_alert:
                result.add_alert(h_scan_alert)
        
        # SYN flood detection
        if "SYN" in packet.flags:
            syn_alert = self.detect_syn_flood(src_ip)
            if syn_alert:
                result.add_alert(syn_alert)
        
        # ICMP flood detection
        if packet.protocol == "ICMP":
            icmp_alert = self.detect_icmp_flood(src_ip)
            if icmp_alert:
                result.add_alert(icmp_alert)
        
        return result
    
    def analyze_packets(self, packets: List[PacketInfo]) -> AnalysisResult:
        """Analyze multiple packets."""
        combined_result = AnalysisResult()
        
        for packet in packets:
            result = self.analyze_packet(packet)
            combined_result.merge(result)
        
        return combined_result
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        with self.connection_lock:
            active = len(self.connections)
            protocols = defaultdict(int)
            for conn in self.connections.values():
                protocols[conn.protocol] += 1
            
            return {
                "active_connections": active,
                "by_protocol": dict(protocols),
                "total_tracked": active
            }
    
    def get_host_stats(self) -> Dict[str, Any]:
        """Get host profile statistics."""
        with self.host_lock:
            return {
                "total_hosts": len(self.hosts),
                "top_talkers": sorted(
                    [(ip, h.packets_sent + h.packets_received) for ip, h in self.hosts.items()],
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
            }
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get overall analysis statistics."""
        return {
            "packets": dict(self.stats),
            "protocols": dict(self.protocol_stats),
            "connections": self.get_connection_stats(),
            "hosts": self.get_host_stats(),
            "rule_engine": self.rule_engine.get_rule_stats()
        }
    
    def cleanup_old_data(self, max_age_seconds: int = 3600):
        """Clean up old connection and profile data."""
        cutoff = datetime.now() - timedelta(seconds=max_age_seconds)
        
        with self.connection_lock:
            old_keys = [k for k, v in self.connections.items() if v.last_seen < cutoff]
            for key in old_keys:
                del self.connections[key]
            logger.debug(f"Cleaned up {len(old_keys)} old connections")
        
        with self.host_lock:
            old_hosts = [k for k, v in self.hosts.items() if v.last_seen < cutoff]
            for key in old_hosts:
                del self.hosts[key]
            logger.debug(f"Cleaned up {len(old_hosts)} old host profiles")


# Backward compatibility alias
PacketAnalyzer = TrafficAnalyzer


if __name__ == "__main__":
    # Test the analyzer
    logging.basicConfig(level=logging.INFO)
    
    analyzer = TrafficAnalyzer()
    print("Analyzer Stats:", analyzer.get_analysis_stats())
    
    # Create a test packet
    test_packet = PacketInfo(
        timestamp=datetime.now(),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=45678,
        dst_port=80,
        protocol="HTTP",
        length=500,
        payload=b"GET /admin?id=1 UNION SELECT password FROM users HTTP/1.1\r\nHost: target.com\r\n\r\n",
        http_uri="/admin?id=1 UNION SELECT password FROM users",
        http_method="GET"
    )
    
    result = analyzer.analyze_packet(test_packet)
    print(f"\nAnalyzed {result.packets_analyzed} packet(s)")
    print(f"Alerts generated: {len(result.alerts)}")
    for alert in result.alerts:
        print(f"  - {alert}")