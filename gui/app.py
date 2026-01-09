"""
Jina IDS - Professional GUI Application
Modern Dashboard for Network Intrusion Detection
"""

import sys
import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import deque

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QTabWidget,
    QGroupBox, QComboBox, QTextEdit, QSplitter, QFrame, QScrollArea,
    QGridLayout, QProgressBar, QMessageBox, QStatusBar, QToolBar,
    QSpinBox, QCheckBox, QLineEdit, QHeaderView, QStyle, QStyleFactory
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt6.QtGui import (
    QColor, QPalette, QFont, QIcon, QAction, QPainter, 
    QLinearGradient, QBrush, QPen
)

# Import our modules
try:
    from core.detector import IntrusionDetector
    from core.rule_engine import Alert
    from core.packet_capture import PacketCapture
except ImportError as e:
    print(f"Import error: {e}")


class AlertTableWidget(QTableWidget):
    """Custom table widget for displaying alerts."""
    
    SEVERITY_COLORS = {
        "critical": QColor(220, 53, 69),    # Red
        "high": QColor(255, 193, 7),        # Yellow
        "medium": QColor(23, 162, 184),     # Blue
        "low": QColor(40, 167, 69),         # Green
    }
    
    def __init__(self):
        super().__init__()
        self.setup_table()
    
    def setup_table(self):
        headers = ["Time", "Severity", "Rule", "Source", "Destination", "Category", "MITRE"]
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        
        # Style the header
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        self.setColumnWidth(1, 80)
        
        # Enable alternating row colors
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    
    def add_alert(self, alert: Alert):
        """Add an alert to the table."""
        row = 0  # Insert at top
        self.insertRow(row)
        
        # Time
        time_item = QTableWidgetItem(alert.timestamp.strftime("%H:%M:%S"))
        self.setItem(row, 0, time_item)
        
        # Severity with color
        severity_item = QTableWidgetItem(alert.severity.upper())
        severity_item.setBackground(self.SEVERITY_COLORS.get(alert.severity, QColor(128, 128, 128)))
        severity_item.setForeground(QColor(255, 255, 255))
        severity_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setItem(row, 1, severity_item)
        
        # Rule name
        self.setItem(row, 2, QTableWidgetItem(alert.rule_name))
        
        # Source
        src = f"{alert.src_ip}:{alert.src_port}" if alert.src_port else alert.src_ip
        self.setItem(row, 3, QTableWidgetItem(src))
        
        # Destination
        dst = f"{alert.dst_ip}:{alert.dst_port}" if alert.dst_port else alert.dst_ip
        self.setItem(row, 4, QTableWidgetItem(dst))
        
        # Category
        self.setItem(row, 5, QTableWidgetItem(alert.category))
        
        # MITRE ATT&CK
        self.setItem(row, 6, QTableWidgetItem(alert.mitre_attack))
        
        # Limit rows
        while self.rowCount() > 500:
            self.removeRow(self.rowCount() - 1)


class StatsWidget(QFrame):
    """Widget for displaying real-time statistics."""
    
    def __init__(self, title: str, value: str = "0", color: QColor = None):
        super().__init__()
        self.setFrameStyle(QFrame.Shape.Box | QFrame.Shadow.Raised)
        self.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border-radius: 10px;
                border: 1px solid #4a5568;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #a0aec0; font-size: 12px;")
        
        self.value_label = QLabel(value)
        color_str = f"rgb({color.red()}, {color.green()}, {color.blue()})" if color else "#fff"
        self.value_label.setStyleSheet(f"color: {color_str}; font-size: 28px; font-weight: bold;")
        
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        self.setLayout(layout)
    
    def set_value(self, value: str):
        self.value_label.setText(value)


class Dashboard(QWidget):
    """Main dashboard widget with real-time statistics."""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Stats row
        stats_layout = QHBoxLayout()
        
        self.packets_stat = StatsWidget("Packets Processed", "0", QColor(66, 153, 225))
        self.pps_stat = StatsWidget("Packets/Second", "0.0", QColor(72, 187, 120))
        self.alerts_stat = StatsWidget("Total Alerts", "0", QColor(237, 100, 166))
        self.critical_stat = StatsWidget("Critical Alerts", "0", QColor(245, 101, 101))
        
        stats_layout.addWidget(self.packets_stat)
        stats_layout.addWidget(self.pps_stat)
        stats_layout.addWidget(self.alerts_stat)
        stats_layout.addWidget(self.critical_stat)
        
        layout.addLayout(stats_layout)
        
        # Protocol distribution (simple text for now)
        protocol_group = QGroupBox("Protocol Distribution")
        protocol_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #4a5568;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        protocol_layout = QVBoxLayout()
        self.protocol_label = QLabel("Waiting for traffic...")
        self.protocol_label.setStyleSheet("color: #a0aec0;")
        protocol_layout.addWidget(self.protocol_label)
        protocol_group.setLayout(protocol_layout)
        
        layout.addWidget(protocol_group)
        
        self.setLayout(layout)
    
    def update_stats(self, stats: Dict):
        """Update dashboard with new statistics."""
        self.packets_stat.set_value(f"{stats.get('packets_processed', 0):,}")
        self.pps_stat.set_value(f"{stats.get('packets_per_second', 0):.1f}")
        self.alerts_stat.set_value(f"{stats.get('alerts_generated', 0):,}")
        
        severity_stats = stats.get('alerts_by_severity', {})
        critical = severity_stats.get('critical', 0)
        self.critical_stat.set_value(str(critical))
        
        # Update protocol distribution
        capture_stats = stats.get('capture', {})
        protocol_text = []
        for key, value in capture_stats.items():
            if key.startswith("protocol_"):
                proto = key.replace("protocol_", "")
                protocol_text.append(f"{proto}: {value}")
        
        if protocol_text:
            self.protocol_label.setText(" | ".join(protocol_text[:6]))


class IDSApplication(QMainWindow):
    """Main application window for Jina IDS."""
    
    alert_received = pyqtSignal(object)
    
    def __init__(self, config: Dict, base_dir: str, logger):
        super().__init__()
        self.config = config
        self.base_dir = base_dir
        self.logger = logger
        
        self.detector: Optional[IntrusionDetector] = None
        self.is_monitoring = False
        
        # Connect signal
        self.alert_received.connect(self._on_alert)
        
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        """Setup the main UI."""
        self.setWindowTitle("Jina IDS - Professional Network Intrusion Detection")
        self.setMinimumSize(1200, 800)
        
        # Apply dark theme
        self.apply_dark_theme()
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Create tab widget
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #4a5568;
                border-radius: 5px;
            }
            QTabBar::tab {
                background: #2d3748;
                color: #a0aec0;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background: #4a5568;
                color: #fff;
            }
        """)
        
        # Dashboard tab
        self.dashboard = Dashboard()
        tabs.addTab(self.dashboard, "📊 Dashboard")
        
        # Alerts tab
        alerts_widget = QWidget()
        alerts_layout = QVBoxLayout(alerts_widget)
        
        self.alert_table = AlertTableWidget()
        alerts_layout.addWidget(self.alert_table)
        
        tabs.addTab(alerts_widget, "🚨 Alerts")
        
        # Logs tab
        logs_widget = QWidget()
        logs_layout = QVBoxLayout(logs_widget)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background: #1a202c;
                color: #68d391;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                border: 1px solid #4a5568;
                border-radius: 5px;
            }
        """)
        logs_layout.addWidget(self.log_text)
        
        tabs.addTab(logs_widget, "📝 Logs")
        
        # Settings tab
        settings_widget = self.create_settings_widget()
        tabs.addTab(settings_widget, "⚙️ Settings")
        
        main_layout.addWidget(tabs)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Click 'Start Monitoring' to begin")
    
    def create_header(self) -> QWidget:
        """Create the header with controls."""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a365d, stop:1 #2d3748);
                border-radius: 10px;
                padding: 10px;
            }
        """)
        
        layout = QHBoxLayout(header)
        
        # Logo/Title
        title = QLabel("🛡️ Jina IDS")
        title.setStyleSheet("color: #fff; font-size: 24px; font-weight: bold;")
        layout.addWidget(title)
        
        subtitle = QLabel("Professional Network Intrusion Detection")
        subtitle.setStyleSheet("color: #a0aec0; font-size: 12px;")
        layout.addWidget(subtitle)
        
        layout.addStretch()
        
        # Interface selector
        iface_label = QLabel("Interface:")
        iface_label.setStyleSheet("color: #a0aec0;")
        layout.addWidget(iface_label)
        
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(150)
        self.interface_combo.setStyleSheet("""
            QComboBox {
                background: #2d3748;
                color: #fff;
                border: 1px solid #4a5568;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        self.populate_interfaces()
        layout.addWidget(self.interface_combo)
        
        # Start/Stop button
        self.start_button = QPushButton("▶ Start Monitoring")
        self.start_button.setStyleSheet("""
            QPushButton {
                background: #48bb78;
                color: #fff;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #38a169;
            }
            QPushButton:pressed {
                background: #2f855a;
            }
        """)
        self.start_button.clicked.connect(self.toggle_monitoring)
        layout.addWidget(self.start_button)
        
        return header
    
    def create_settings_widget(self) -> QWidget:
        """Create settings panel."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Detection settings
        detection_group = QGroupBox("Detection Settings")
        detection_layout = QGridLayout()
        
        self.ml_checkbox = QCheckBox("Enable ML Detection")
        self.ml_checkbox.setChecked(True)
        detection_layout.addWidget(self.ml_checkbox, 0, 0)
        
        self.signature_checkbox = QCheckBox("Enable Signature Detection")
        self.signature_checkbox.setChecked(True)
        detection_layout.addWidget(self.signature_checkbox, 0, 1)
        
        detection_group.setLayout(detection_layout)
        layout.addWidget(detection_group)
        
        # Rules info
        rules_group = QGroupBox("Loaded Rules")
        rules_layout = QVBoxLayout()
        
        self.rules_label = QLabel("Loading...")
        rules_layout.addWidget(self.rules_label)
        
        rules_group.setLayout(rules_layout)
        layout.addWidget(rules_group)
        
        # Update rules info
        self.update_rules_info()
        
        layout.addStretch()
        return widget
    
    def update_rules_info(self):
        """Update the rules information display."""
        try:
            rules_file = os.path.join(self.base_dir, "data", "rules", "default_rules.json")
            if os.path.exists(rules_file):
                with open(rules_file, "r") as f:
                    rules = json.load(f)
                
                payload_sigs = len(rules.get("payload_signatures", []))
                network_sigs = len(rules.get("network_signatures", []))
                
                text = f"""
                <b>Payload Signatures:</b> {payload_sigs}<br>
                <b>Network Signatures:</b> {network_sigs}<br>
                <b>Categories:</b> SQL Injection, XSS, Command Injection, Path Traversal, etc.<br>
                <b>MITRE ATT&CK:</b> Mapped
                """
                self.rules_label.setText(text)
        except Exception as e:
            self.rules_label.setText(f"Error loading rules: {e}")
    
    def populate_interfaces(self):
        """Populate interface dropdown."""
        self.interface_combo.clear()
        self.interface_combo.addItem("auto (Auto-detect)")
        
        try:
            interfaces = PacketCapture.list_interfaces()
            for iface in interfaces:
                self.interface_combo.addItem(f"{iface['name']} ({iface['address']})")
        except Exception as e:
            self.log(f"Could not list interfaces: {e}")
    
    def apply_dark_theme(self):
        """Apply dark theme to the application."""
        palette = QPalette()
        
        # Dark background
        palette.setColor(QPalette.ColorRole.Window, QColor(26, 32, 44))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(226, 232, 240))
        palette.setColor(QPalette.ColorRole.Base, QColor(45, 55, 72))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(74, 85, 104))
        palette.setColor(QPalette.ColorRole.Text, QColor(226, 232, 240))
        palette.setColor(QPalette.ColorRole.Button, QColor(45, 55, 72))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(226, 232, 240))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(66, 153, 225))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        
        self.setPalette(palette)
    
    def setup_timer(self):
        """Setup timer for updating stats."""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_stats)
        self.update_timer.start(1000)  # Update every second
    
    def toggle_monitoring(self):
        """Start or stop monitoring."""
        if self.is_monitoring:
            self.stop_monitoring()
        else:
            self.start_monitoring()
    
    def start_monitoring(self):
        """Start the IDS monitoring."""
        # Get selected interface
        interface_text = self.interface_combo.currentText()
        if interface_text.startswith("auto"):
            interface = "auto"
        else:
            interface = interface_text.split(" ")[0]
        
        # Configure
        self.config.setdefault("capture", {})["interface"] = interface
        self.config.setdefault("detection", {})["enable_ml"] = self.ml_checkbox.isChecked()
        
        # Create and start detector
        try:
            self.detector = IntrusionDetector(self.config.get("detection", {}))
            self.detector.register_alert_callback(self._alert_callback)
            
            if not self.detector.start(background=True):
                QMessageBox.critical(
                    self,
                    "Error",
                    "Failed to start packet capture.\nMake sure you're running as root/admin."
                )
                return
            
            self.is_monitoring = True
            self.start_button.setText("⏹ Stop Monitoring")
            self.start_button.setStyleSheet("""
                QPushButton {
                    background: #f56565;
                    color: #fff;
                    border: none;
                    border-radius: 5px;
                    padding: 10px 20px;
                    font-weight: bold;
                }
                QPushButton:hover { background: #e53e3e; }
            """)
            
            self.status_bar.showMessage(f"Monitoring on {self.detector.packet_capture.interface}...")
            self.log("Started monitoring")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start: {e}")
            self.log(f"Error: {e}")
    
    def stop_monitoring(self):
        """Stop the IDS monitoring."""
        if self.detector:
            self.detector.stop()
            self.detector = None
        
        self.is_monitoring = False
        self.start_button.setText("▶ Start Monitoring")
        self.start_button.setStyleSheet("""
            QPushButton {
                background: #48bb78;
                color: #fff;
                border: none;
                border-radius: 5px;
                padding: 10px 20px;
                font-weight: bold;
            }
            QPushButton:hover { background: #38a169; }
        """)
        
        self.status_bar.showMessage("Monitoring stopped")
        self.log("Stopped monitoring")
    
    def _alert_callback(self, alert: Alert):
        """Callback for alerts (called from detector thread)."""
        # Use signal to update UI from main thread
        self.alert_received.emit(alert)
    
    def _on_alert(self, alert: Alert):
        """Handle alert in main thread."""
        self.alert_table.add_alert(alert)
        self.log(f"ALERT: [{alert.severity.upper()}] {alert.rule_name} - {alert.src_ip}")
    
    def update_stats(self):
        """Update statistics display."""
        if self.detector and self.is_monitoring:
            try:
                stats = self.detector.get_stats()
                self.dashboard.update_stats(stats)
            except Exception as e:
                pass  # Ignore stats errors
    
    def log(self, message: str):
        """Add message to log display."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
    
    def closeEvent(self, event):
        """Handle window close."""
        if self.is_monitoring:
            self.stop_monitoring()
        event.accept()


# Convenience function for backward compatibility
def show_alert(message: str):
    """Show an alert message box."""
    QMessageBox.warning(None, "Alert", message)


def generate_report():
    """Generate a simple report."""
    print("Report generation requested")


if __name__ == "__main__":
    # Test the GUI
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    window = IDSApplication({}, os.getcwd(), None)
    window.show()
    
    sys.exit(app.exec())
