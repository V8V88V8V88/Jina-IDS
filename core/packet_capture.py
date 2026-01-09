"""
Jina IDS - Professional Packet Capture Engine
CEH-Level Network Traffic Capture with Deep Packet Inspection
"""

import threading
import queue
import time
import logging
from typing import Optional, Callable, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, Raw, Ether,
        ARP, IPv6, conf, get_if_list, get_if_addr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("JinaIDS.PacketCapture")


@dataclass
class PacketInfo:
    """Structured packet information for analysis."""
    timestamp: datetime
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "UNKNOWN"
    length: int = 0
    ttl: int = 0
    flags: str = ""
    payload: bytes = b""
    raw_packet: Any = None
    
    # Protocol-specific fields
    dns_query: str = ""
    http_method: str = ""
    http_uri: str = ""
    http_host: str = ""
    http_user_agent: str = ""
    
    # Analysis flags
    is_fragmented: bool = False
    is_encrypted: bool = False
    
    # Metadata
    interface: str = ""
    direction: str = "unknown"  # inbound, outbound, internal


class PacketCapture:
    """
    Professional-grade packet capture engine.
    
    Features:
    - Multi-threaded packet capture
    - Deep packet inspection
    - Protocol parsing (TCP, UDP, ICMP, DNS, HTTP)
    - Configurable filtering
    - Non-blocking operation
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.interface = self._get_interface()
        self.promiscuous = self.config.get("promiscuous", True)
        self.buffer_size = self.config.get("buffer_size", 65536)
        self.timeout = self.config.get("timeout", 1)
        self.filter = self.config.get("filter", "")
        
        self.packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.is_running = False
        self.capture_thread: Optional[threading.Thread] = None
        self.callbacks: List[Callable[[PacketInfo], None]] = []
        
        # Statistics
        self.stats = defaultdict(int)
        self.start_time: Optional[datetime] = None
        
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available. Packet capture disabled.")
    
    def _get_interface(self) -> str:
        """Auto-detect or use configured network interface."""
        interface = self.config.get("interface", "auto")
        
        if interface == "auto":
            try:
                interfaces = get_if_list()
                # Prefer common interface names
                for preferred in ["eth0", "ens33", "enp0s3", "wlan0", "wlp2s0"]:
                    if preferred in interfaces:
                        logger.info(f"Auto-selected interface: {preferred}")
                        return preferred
                # Fallback to first non-loopback
                for iface in interfaces:
                    if iface != "lo":
                        logger.info(f"Using interface: {iface}")
                        return iface
                return "lo"
            except Exception as e:
                logger.warning(f"Could not auto-detect interface: {e}")
                return "lo"
        return interface
    
    def register_callback(self, callback: Callable[[PacketInfo], None]):
        """Register a callback for processed packets."""
        self.callbacks.append(callback)
    
    def _parse_packet(self, packet) -> Optional[PacketInfo]:
        """Parse raw packet into structured PacketInfo."""
        try:
            pkt_info = PacketInfo(
                timestamp=datetime.now(),
                raw_packet=packet,
                length=len(packet),
                interface=self.interface
            )
            
            # Layer 3 - IP
            if IP in packet:
                ip_layer = packet[IP]
                pkt_info.src_ip = ip_layer.src
                pkt_info.dst_ip = ip_layer.dst
                pkt_info.ttl = ip_layer.ttl
                pkt_info.is_fragmented = bool(ip_layer.frag)
                
                # Determine protocol
                if TCP in packet:
                    pkt_info.protocol = "TCP"
                    tcp_layer = packet[TCP]
                    pkt_info.src_port = tcp_layer.sport
                    pkt_info.dst_port = tcp_layer.dport
                    pkt_info.flags = self._get_tcp_flags(tcp_layer)
                    
                    # Mark encrypted ports (HTTPS, SSH, etc.)
                    encrypted_ports = {443, 8443, 22, 465, 993, 995, 636, 989, 990, 992}
                    if pkt_info.dst_port in encrypted_ports or pkt_info.src_port in encrypted_ports:
                        pkt_info.is_encrypted = True
                        pkt_info.protocol = "HTTPS" if pkt_info.dst_port == 443 or pkt_info.src_port == 443 else "ENCRYPTED"
                    
                    # HTTP detection (only for non-encrypted ports)
                    if Raw in packet and not pkt_info.is_encrypted:
                        payload = bytes(packet[Raw].load)
                        pkt_info.payload = payload
                        self._parse_http(payload, pkt_info)
                    elif Raw in packet and pkt_info.is_encrypted:
                        # Don't parse encrypted payloads to avoid false positives
                        pkt_info.payload = b""
                        
                elif UDP in packet:
                    pkt_info.protocol = "UDP"
                    udp_layer = packet[UDP]
                    pkt_info.src_port = udp_layer.sport
                    pkt_info.dst_port = udp_layer.dport
                    
                    # DNS detection
                    if DNS in packet:
                        pkt_info.protocol = "DNS"
                        self._parse_dns(packet[DNS], pkt_info)
                    
                    if Raw in packet:
                        pkt_info.payload = bytes(packet[Raw].load)
                        
                elif ICMP in packet:
                    pkt_info.protocol = "ICMP"
                    
            elif IPv6 in packet:
                pkt_info.protocol = "IPv6"
                pkt_info.src_ip = packet[IPv6].src
                pkt_info.dst_ip = packet[IPv6].dst
                
            elif ARP in packet:
                pkt_info.protocol = "ARP"
                pkt_info.src_ip = packet[ARP].psrc
                pkt_info.dst_ip = packet[ARP].pdst
            
            # Update stats
            self.stats["total_packets"] += 1
            self.stats[f"protocol_{pkt_info.protocol}"] += 1
            self.stats["total_bytes"] += pkt_info.length
            
            return pkt_info
            
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            self.stats["parse_errors"] += 1
            return None
    
    def _get_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string."""
        flags = []
        if tcp_layer.flags.S:
            flags.append("SYN")
        if tcp_layer.flags.A:
            flags.append("ACK")
        if tcp_layer.flags.F:
            flags.append("FIN")
        if tcp_layer.flags.R:
            flags.append("RST")
        if tcp_layer.flags.P:
            flags.append("PSH")
        if tcp_layer.flags.U:
            flags.append("URG")
        return ",".join(flags)
    
    def _parse_dns(self, dns_layer, pkt_info: PacketInfo):
        """Parse DNS query information."""
        try:
            if dns_layer.qd:
                pkt_info.dns_query = dns_layer.qd.qname.decode() if isinstance(
                    dns_layer.qd.qname, bytes
                ) else str(dns_layer.qd.qname)
        except Exception as e:
            logger.debug(f"DNS parse error: {e}")
    
    def _parse_http(self, payload: bytes, pkt_info: PacketInfo):
        """Parse HTTP headers from payload."""
        try:
            # Check if it looks like HTTP
            if not payload:
                return
                
            text = payload[:2048].decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            if not lines:
                return
            
            # Check for HTTP request
            first_line = lines[0]
            http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
            
            for method in http_methods:
                if first_line.startswith(method):
                    pkt_info.protocol = "HTTP"
                    parts = first_line.split(' ')
                    if len(parts) >= 2:
                        pkt_info.http_method = parts[0]
                        pkt_info.http_uri = parts[1]
                    break
            
            # Parse headers
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'host':
                        pkt_info.http_host = value
                    elif key == 'user-agent':
                        pkt_info.http_user_agent = value
                        
        except Exception as e:
            logger.debug(f"HTTP parse error: {e}")
    
    def _packet_handler(self, packet):
        """Handle captured packet."""
        pkt_info = self._parse_packet(packet)
        if pkt_info:
            # Add to queue for processing
            try:
                self.packet_queue.put_nowait(pkt_info)
            except queue.Full:
                self.stats["dropped_packets"] += 1
            
            # Call registered callbacks
            for callback in self.callbacks:
                try:
                    callback(pkt_info)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
    
    def _capture_loop(self):
        """Main capture loop running in separate thread."""
        logger.info(f"Starting capture on interface: {self.interface}")
        
        try:
            conf.promisc = self.promiscuous
            
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.is_running,
                filter=self.filter if self.filter else None
            )
        except PermissionError:
            logger.error("Permission denied. Run with sudo/root for packet capture.")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            logger.info("Capture loop ended")
    
    def start_capture(self, background: bool = True):
        """Start packet capture."""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture: Scapy not available")
            return False
        
        if self.is_running:
            logger.warning("Capture already running")
            return True
        
        self.is_running = True
        self.start_time = datetime.now()
        self.stats.clear()
        
        if background:
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                daemon=True,
                name="PacketCaptureThread"
            )
            self.capture_thread.start()
            logger.info("Packet capture started in background")
        else:
            self._capture_loop()
        
        return True
    
    def stop_capture(self):
        """Stop packet capture."""
        if not self.is_running:
            return
        
        self.is_running = False
        logger.info("Stopping packet capture...")
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        logger.info("Packet capture stopped")
    
    def get_packets(self, max_count: int = 100, timeout: float = 0.1) -> List[PacketInfo]:
        """Get captured packets from queue."""
        packets = []
        end_time = time.time() + timeout
        
        while len(packets) < max_count and time.time() < end_time:
            try:
                pkt = self.packet_queue.get_nowait()
                packets.append(pkt)
            except queue.Empty:
                break
        
        return packets
    
    def get_stats(self) -> Dict[str, Any]:
        """Get capture statistics."""
        stats = dict(self.stats)
        if self.start_time:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            stats["elapsed_seconds"] = elapsed
            if elapsed > 0:
                stats["packets_per_second"] = stats.get("total_packets", 0) / elapsed
        stats["queue_size"] = self.packet_queue.qsize()
        stats["is_running"] = self.is_running
        stats["interface"] = self.interface
        return stats
    
    @staticmethod
    def list_interfaces() -> List[Dict[str, str]]:
        """List available network interfaces."""
        interfaces = []
        try:
            for iface in get_if_list():
                try:
                    addr = get_if_addr(iface)
                    interfaces.append({
                        "name": iface,
                        "address": addr
                    })
                except Exception:
                    interfaces.append({
                        "name": iface,
                        "address": "N/A"
                    })
        except Exception as e:
            logger.error(f"Error listing interfaces: {e}")
        return interfaces


# Convenience class for backward compatibility
class TrafficCapture(PacketCapture):
    """Alias for PacketCapture."""
    pass


if __name__ == "__main__":
    # Test packet capture
    logging.basicConfig(level=logging.INFO)
    
    print("Available interfaces:")
    for iface in PacketCapture.list_interfaces():
        print(f"  {iface['name']}: {iface['address']}")
    
    print("\nStarting capture (requires root)...")
    capture = PacketCapture()
    
    def print_packet(pkt: PacketInfo):
        print(f"[{pkt.protocol}] {pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}")
    
    capture.register_callback(print_packet)
    capture.start_capture()
    
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        capture.stop_capture()
        print(f"\nStats: {capture.get_stats()}")
