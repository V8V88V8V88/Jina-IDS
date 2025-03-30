#!/usr/bin/env python3
"""
Network Intrusion Detection System - Main Entry Point
"""

import sys
import os
import argparse
from PyQt6.QtWidgets import QApplication

from gui.app import IDSApplication
from utils.config import load_config
from utils.logger import setup_logger

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    parser.add_argument("--config", type=str, default="config.json",
                        help="Path to configuration file")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug mode")
    parser.add_argument("--no-gui", action="store_true",
                        help="Run in console mode without GUI")
    
    return parser.parse_args()

def main():
    """Main entry point of the application."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Setup paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.join(base_dir, "data", "logs"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "data", "models"), exist_ok=True)
    
    # Setup logger
    log_file = os.path.join(base_dir, "data", "logs", "ids.log")
    logger = setup_logger(log_file, debug=args.debug)
    logger.info("Starting Network Intrusion Detection System")
    
    # Load configuration
    config_file = args.config
    if not os.path.isabs(config_file):
        config_file = os.path.join(base_dir, config_file)
    
    try:
        config = load_config(config_file)
        logger.info(f"Configuration loaded from {config_file}")
    except FileNotFoundError:
        logger.warning(f"Configuration file not found: {config_file}")
        logger.info("Using default configuration")
        config = load_config(None)
    
    if args.no_gui:
        # Run in console mode
        from core.packet_capture import PacketCapture
        from core.analyzer import TrafficAnalyzer
        from core.detector import IntrusionDetector
        
        # Initialize components
        packet_capture = PacketCapture(config["capture"])
        analyzer = TrafficAnalyzer(config["analysis"])
        detector = IntrusionDetector(config["detection"])
        
        # Start capturing and analyzing
        try:
            logger.info("Starting packet capture in console mode")
            packet_capture.start_capture()
            
            # Main console loop
            while True:
                packets = packet_capture.get_packets()
                if packets:
                    analysis = analyzer.analyze_packets(packets)
                    alerts = detector.detect_intrusions(analysis)
                    
                    if alerts:
                        for alert in alerts:
                            logger.warning(f"ALERT: {alert}")
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received, shutting down")
        finally:
            packet_capture.stop_capture()
            logger.info("Packet capture stopped")
    else:
        # Run in GUI mode
        app = QApplication(sys.argv)
        app.setApplicationName("Network Intrusion Detection System")
        
        window = IDSApplication(config, base_dir, logger)
        window.show()
        
        sys.exit(app.exec())

if __name__ == "__main__":
    main()
