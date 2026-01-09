"""
Jina IDS - Alert System
Professional Alert Handling and Display
"""

from PyQt6.QtWidgets import (
    QMessageBox, QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFrame, QWidget, QTableWidget, 
    QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from datetime import datetime
from typing import Optional, List, Dict
from dataclasses import dataclass


# Alert severity definitions
SEVERITY_CONFIG = {
    "critical": {
        "color": "#f56565",
        "icon": "🔴",
        "priority": 1,
        "sound": True
    },
    "high": {
        "color": "#ed8936",
        "icon": "🟠",
        "priority": 2,
        "sound": True
    },
    "medium": {
        "color": "#ecc94b",
        "icon": "🟡",
        "priority": 3,
        "sound": False
    },
    "low": {
        "color": "#48bb78",
        "icon": "🟢",
        "priority": 4,
        "sound": False
    },
    "info": {
        "color": "#4299e1",
        "icon": "🔵",
        "priority": 5,
        "sound": False
    }
}


def show_alert(message: str, severity: str = "medium", title: str = "Security Alert"):
    """
    Show a styled alert message box.
    
    Args:
        message: Alert message to display
        severity: Alert severity (critical, high, medium, low, info)
        title: Dialog title
    """
    config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["medium"])
    
    msg_box = QMessageBox()
    msg_box.setWindowTitle(f"{config['icon']} {title}")
    msg_box.setText(message)
    
    if severity == "critical":
        msg_box.setIcon(QMessageBox.Icon.Critical)
    elif severity == "high":
        msg_box.setIcon(QMessageBox.Icon.Warning)
    elif severity in ("medium", "low"):
        msg_box.setIcon(QMessageBox.Icon.Information)
    else:
        msg_box.setIcon(QMessageBox.Icon.NoIcon)
    
    msg_box.setStyleSheet(f"""
        QMessageBox {{
            background: #1a202c;
        }}
        QMessageBox QLabel {{
            color: #e2e8f0;
            font-size: 13px;
        }}
        QPushButton {{
            background: {config['color']};
            color: #fff;
            border: none;
            border-radius: 5px;
            padding: 8px 20px;
            font-weight: bold;
        }}
        QPushButton:hover {{
            opacity: 0.9;
        }}
    """)
    
    msg_box.exec()


class AlertDetailDialog(QDialog):
    """Detailed view of a single alert."""
    
    def __init__(self, alert, parent=None):
        super().__init__(parent)
        self.alert = alert
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Alert Details")
        self.setMinimumSize(500, 400)
        
        layout = QVBoxLayout()
        
        # Header with severity
        config = SEVERITY_CONFIG.get(self.alert.severity, SEVERITY_CONFIG["medium"])
        
        header = QFrame()
        header.setStyleSheet(f"""
            QFrame {{
                background: {config['color']};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        header_layout = QVBoxLayout(header)
        
        severity_label = QLabel(f"{config['icon']} {self.alert.severity.upper()}")
        severity_label.setStyleSheet("color: #fff; font-size: 14px; font-weight: bold;")
        header_layout.addWidget(severity_label)
        
        rule_label = QLabel(self.alert.rule_name)
        rule_label.setStyleSheet("color: #fff; font-size: 18px; font-weight: bold;")
        header_layout.addWidget(rule_label)
        
        layout.addWidget(header)
        
        # Details
        details_frame = QFrame()
        details_frame.setStyleSheet("""
            QFrame {
                background: #2d3748;
                border-radius: 8px;
                padding: 15px;
            }
            QLabel {
                color: #e2e8f0;
                font-size: 12px;
            }
        """)
        details_layout = QVBoxLayout(details_frame)
        
        # Add detail rows
        details = [
            ("Time", self.alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
            ("Rule ID", self.alert.rule_id),
            ("Category", self.alert.category),
            ("Source", f"{self.alert.src_ip}:{self.alert.src_port}"),
            ("Destination", f"{self.alert.dst_ip}:{self.alert.dst_port}"),
            ("Protocol", self.alert.protocol),
            ("MITRE ATT&CK", self.alert.mitre_attack or "N/A"),
            ("Description", self.alert.description)
        ]
        
        for label, value in details:
            row = QHBoxLayout()
            
            lbl = QLabel(f"{label}:")
            lbl.setStyleSheet("color: #a0aec0; font-weight: bold; min-width: 100px;")
            row.addWidget(lbl)
            
            val = QLabel(str(value))
            val.setWordWrap(True)
            row.addWidget(val, 1)
            
            details_layout.addLayout(row)
        
        # Matched content if present
        if self.alert.matched_content:
            matched_label = QLabel("Matched Content:")
            matched_label.setStyleSheet("color: #a0aec0; font-weight: bold;")
            details_layout.addWidget(matched_label)
            
            matched_text = QTextEdit()
            matched_text.setPlainText(self.alert.matched_content[:500])
            matched_text.setReadOnly(True)
            matched_text.setMaximumHeight(100)
            matched_text.setStyleSheet("""
                QTextEdit {
                    background: #1a202c;
                    color: #fc8181;
                    border: 1px solid #4a5568;
                    border-radius: 5px;
                    font-family: monospace;
                }
            """)
            details_layout.addWidget(matched_text)
        
        layout.addWidget(details_frame)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("""
            QPushButton {
                background: #4a5568;
                color: #fff;
                border: none;
                border-radius: 5px;
                padding: 10px 30px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #718096;
            }
        """)
        close_btn.clicked.connect(self.accept)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
        
        # Apply dark theme
        self.setStyleSheet("""
            QDialog {
                background: #1a202c;
            }
        """)


class AlertWidget(QFrame):
    """Compact alert display widget for notifications."""
    
    clicked = pyqtSignal()
    dismissed = pyqtSignal()
    
    def __init__(self, alert, parent=None):
        super().__init__(parent)
        self.alert = alert
        self.setup_ui()
    
    def setup_ui(self):
        config = SEVERITY_CONFIG.get(self.alert.severity, SEVERITY_CONFIG["medium"])
        
        self.setStyleSheet(f"""
            QFrame {{
                background: #2d3748;
                border-left: 4px solid {config['color']};
                border-radius: 5px;
                margin: 2px;
            }}
            QFrame:hover {{
                background: #4a5568;
            }}
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        layout = QHBoxLayout()
        layout.setContentsMargins(10, 8, 10, 8)
        
        # Icon
        icon = QLabel(config['icon'])
        icon.setStyleSheet("font-size: 16px;")
        layout.addWidget(icon)
        
        # Content
        content_layout = QVBoxLayout()
        
        rule_label = QLabel(self.alert.rule_name)
        rule_label.setStyleSheet("color: #e2e8f0; font-weight: bold; font-size: 12px;")
        content_layout.addWidget(rule_label)
        
        src_label = QLabel(f"{self.alert.src_ip} → {self.alert.dst_ip}")
        src_label.setStyleSheet("color: #a0aec0; font-size: 10px;")
        content_layout.addWidget(src_label)
        
        layout.addLayout(content_layout, 1)
        
        # Time
        time_label = QLabel(self.alert.timestamp.strftime("%H:%M:%S"))
        time_label.setStyleSheet("color: #718096; font-size: 10px;")
        layout.addWidget(time_label)
        
        # Dismiss button
        dismiss_btn = QPushButton("×")
        dismiss_btn.setFixedSize(20, 20)
        dismiss_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #718096;
                border: none;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                color: #f56565;
            }
        """)
        dismiss_btn.clicked.connect(self.dismissed.emit)
        layout.addWidget(dismiss_btn)
        
        self.setLayout(layout)
    
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class AlertNotificationPanel(QWidget):
    """Panel showing recent alert notifications."""
    
    def __init__(self, max_alerts: int = 10, parent=None):
        super().__init__(parent)
        self.max_alerts = max_alerts
        self.alerts: List = []
        self.setup_ui()
    
    def setup_ui(self):
        self.layout = QVBoxLayout()
        self.layout.setSpacing(5)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header = QLabel("Recent Alerts")
        header.setStyleSheet("color: #e2e8f0; font-weight: bold; font-size: 14px; padding: 5px;")
        self.layout.addWidget(header)
        
        # Alerts container
        self.alerts_layout = QVBoxLayout()
        self.alerts_layout.setSpacing(2)
        self.layout.addLayout(self.alerts_layout)
        
        self.layout.addStretch()
        self.setLayout(self.layout)
    
    def add_alert(self, alert):
        """Add a new alert to the panel."""
        widget = AlertWidget(alert)
        widget.clicked.connect(lambda: self.show_alert_detail(alert))
        widget.dismissed.connect(lambda: self.remove_alert(widget))
        
        self.alerts_layout.insertWidget(0, widget)
        
        # Limit displayed alerts
        while self.alerts_layout.count() > self.max_alerts:
            item = self.alerts_layout.takeAt(self.alerts_layout.count() - 1)
            if item.widget():
                item.widget().deleteLater()
    
    def remove_alert(self, widget: AlertWidget):
        """Remove an alert widget."""
        self.alerts_layout.removeWidget(widget)
        widget.deleteLater()
    
    def show_alert_detail(self, alert):
        """Show detailed view of alert."""
        dialog = AlertDetailDialog(alert, self)
        dialog.exec()
    
    def clear_all(self):
        """Clear all alerts."""
        while self.alerts_layout.count():
            item = self.alerts_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()


if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication
    import sys
    from datetime import datetime
    
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Test alert
    @dataclass
    class TestAlert:
        timestamp: datetime
        rule_id: str
        rule_name: str
        severity: str
        category: str
        description: str
        src_ip: str
        dst_ip: str
        src_port: int
        dst_port: int
        protocol: str
        matched_content: str
        mitre_attack: str
    
    from dataclasses import dataclass
    
    alert = TestAlert(
        timestamp=datetime.now(),
        rule_id="SQL-INJECTION-001",
        rule_name="SQL Injection Detected",
        severity="critical",
        category="web_attack",
        description="Union-based SQL injection attempt detected",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.50",
        src_port=54321,
        dst_port=80,
        protocol="HTTP",
        matched_content="UNION SELECT password FROM users--",
        mitre_attack="T1190"
    )
    
    # Test dialog
    dialog = AlertDetailDialog(alert)
    dialog.exec()
    
    # Test notification panel
    panel = AlertNotificationPanel()
    panel.show()
    panel.resize(350, 400)
    
    for i in range(5):
        test = TestAlert(
            timestamp=datetime.now(),
            rule_id=f"TEST-{i}",
            rule_name=f"Test Alert {i}",
            severity=["critical", "high", "medium", "low", "info"][i],
            category="test",
            description="Test description",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            matched_content="test content",
            mitre_attack="T1234"
        )
        panel.add_alert(test)
    
    sys.exit(app.exec())
