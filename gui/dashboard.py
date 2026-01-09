"""
Jina IDS - Dashboard Widget
Real-time Network Monitoring Display
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
    QGroupBox, QGridLayout, QProgressBar
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from typing import Dict, Any
from collections import defaultdict


class StatsCard(QFrame):
    """A styled card for displaying a statistic."""
    
    def __init__(self, title: str, value: str = "0", color: str = "#4299e1"):
        super().__init__()
        self.color = color
        self.setup_ui(title, value)
    
    def setup_ui(self, title: str, value: str):
        self.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border-radius: 10px;
                border: 1px solid #4a5568;
                border-left: 4px solid {self.color};
            }}
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("color: #a0aec0; font-size: 12px; font-weight: bold;")
        
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"color: {self.color}; font-size: 28px; font-weight: bold;")
        
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        self.setLayout(layout)
    
    def set_value(self, value: str):
        self.value_label.setText(value)


class ProtocolBar(QWidget):
    """Progress bar showing protocol distribution."""
    
    def __init__(self, protocol: str, color: str = "#4299e1"):
        super().__init__()
        self.protocol = protocol
        
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 2, 0, 2)
        
        self.label = QLabel(protocol)
        self.label.setMinimumWidth(60)
        self.label.setStyleSheet("color: #a0aec0; font-size: 11px;")
        
        self.bar = QProgressBar()
        self.bar.setTextVisible(True)
        self.bar.setStyleSheet(f"""
            QProgressBar {{
                background: #2d3748;
                border: none;
                border-radius: 5px;
                height: 16px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background: {color};
                border-radius: 5px;
            }}
        """)
        self.bar.setMaximum(100)
        self.bar.setValue(0)
        
        self.count_label = QLabel("0")
        self.count_label.setMinimumWidth(60)
        self.count_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.count_label.setStyleSheet("color: #a0aec0; font-size: 11px;")
        
        layout.addWidget(self.label)
        layout.addWidget(self.bar)
        layout.addWidget(self.count_label)
        
        self.setLayout(layout)
    
    def set_value(self, count: int, percentage: int):
        self.bar.setValue(min(percentage, 100))
        self.count_label.setText(str(count))


class Dashboard(QWidget):
    """
    Main dashboard widget displaying real-time network statistics.
    """
    
    PROTOCOL_COLORS = {
        "TCP": "#4299e1",
        "UDP": "#48bb78",
        "ICMP": "#ed8936",
        "DNS": "#9f7aea",
        "HTTP": "#38b2ac",
        "HTTPS": "#667eea",
        "ARP": "#f687b3",
        "IPv6": "#fc8181"
    }
    
    def __init__(self):
        super().__init__()
        self.protocol_bars: Dict[str, ProtocolBar] = {}
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Title
        title = QLabel("📊 Network Security Dashboard")
        title.setStyleSheet("color: #e2e8f0; font-size: 18px; font-weight: bold;")
        layout.addWidget(title)
        
        # Stats cards row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(15)
        
        self.packets_card = StatsCard("Packets Processed", "0", "#4299e1")
        self.pps_card = StatsCard("Packets/Second", "0.0", "#48bb78")
        self.alerts_card = StatsCard("Total Alerts", "0", "#ed64a6")
        self.critical_card = StatsCard("Critical Alerts", "0", "#f56565")
        
        cards_layout.addWidget(self.packets_card)
        cards_layout.addWidget(self.pps_card)
        cards_layout.addWidget(self.alerts_card)
        cards_layout.addWidget(self.critical_card)
        
        layout.addLayout(cards_layout)
        
        # Protocol distribution
        protocol_group = QGroupBox("Protocol Distribution")
        protocol_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e2e8f0;
                border: 1px solid #4a5568;
                border-radius: 8px;
                margin-top: 15px;
                padding: 15px;
                padding-top: 25px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px;
            }
        """)
        
        self.protocol_layout = QVBoxLayout()
        self.protocol_layout.setSpacing(5)
        
        # Add protocol bars
        for proto, color in self.PROTOCOL_COLORS.items():
            bar = ProtocolBar(proto, color)
            self.protocol_bars[proto] = bar
            self.protocol_layout.addWidget(bar)
        
        protocol_group.setLayout(self.protocol_layout)
        layout.addWidget(protocol_group)
        
        # Connection stats
        connection_group = QGroupBox("Connection Statistics")
        connection_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #e2e8f0;
                border: 1px solid #4a5568;
                border-radius: 8px;
                margin-top: 15px;
                padding: 15px;
                padding-top: 25px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px;
            }
        """)
        
        conn_layout = QGridLayout()
        
        self.conn_active = QLabel("Active Connections: 0")
        self.conn_active.setStyleSheet("color: #a0aec0;")
        conn_layout.addWidget(self.conn_active, 0, 0)
        
        self.hosts_tracked = QLabel("Hosts Tracked: 0")
        self.hosts_tracked.setStyleSheet("color: #a0aec0;")
        conn_layout.addWidget(self.hosts_tracked, 0, 1)
        
        self.bytes_processed = QLabel("Bytes Processed: 0")
        self.bytes_processed.setStyleSheet("color: #a0aec0;")
        conn_layout.addWidget(self.bytes_processed, 1, 0)
        
        self.uptime_label = QLabel("Uptime: 0s")
        self.uptime_label.setStyleSheet("color: #a0aec0;")
        conn_layout.addWidget(self.uptime_label, 1, 1)
        
        connection_group.setLayout(conn_layout)
        layout.addWidget(connection_group)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def update_stats(self, stats: Dict[str, Any]):
        """Update dashboard with new statistics."""
        # Main stats
        self.packets_card.set_value(f"{stats.get('packets_processed', 0):,}")
        self.pps_card.set_value(f"{stats.get('packets_per_second', 0):.1f}")
        self.alerts_card.set_value(f"{stats.get('alerts_generated', 0):,}")
        
        severity_stats = stats.get('alerts_by_severity', {})
        critical = severity_stats.get('critical', 0)
        self.critical_card.set_value(str(critical))
        
        # Protocol distribution
        capture_stats = stats.get('capture', {})
        total_packets = capture_stats.get('total_packets', 1) or 1
        
        for proto, bar in self.protocol_bars.items():
            count = capture_stats.get(f'protocol_{proto}', 0)
            percentage = int((count / total_packets) * 100)
            bar.set_value(count, percentage)
        
        # Connection stats
        analysis = stats.get('analysis', {})
        connections = analysis.get('connections', {})
        hosts = analysis.get('hosts', {})
        
        self.conn_active.setText(f"Active Connections: {connections.get('active_connections', 0)}")
        self.hosts_tracked.setText(f"Hosts Tracked: {hosts.get('total_hosts', 0)}")
        
        total_bytes = capture_stats.get('total_bytes', 0)
        if total_bytes > 1024 * 1024:
            bytes_str = f"{total_bytes / (1024 * 1024):.1f} MB"
        elif total_bytes > 1024:
            bytes_str = f"{total_bytes / 1024:.1f} KB"
        else:
            bytes_str = f"{total_bytes} B"
        self.bytes_processed.setText(f"Bytes Processed: {bytes_str}")
        
        uptime = int(stats.get('uptime_seconds', 0))
        if uptime >= 3600:
            uptime_str = f"{uptime // 3600}h {(uptime % 3600) // 60}m"
        elif uptime >= 60:
            uptime_str = f"{uptime // 60}m {uptime % 60}s"
        else:
            uptime_str = f"{uptime}s"
        self.uptime_label.setText(f"Uptime: {uptime_str}")


if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication
    import sys
    
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Apply dark palette
    from PyQt6.QtGui import QPalette, QColor
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(26, 32, 44))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(226, 232, 240))
    app.setPalette(palette)
    
    dashboard = Dashboard()
    dashboard.show()
    dashboard.resize(800, 600)
    
    # Test updating stats
    test_stats = {
        "packets_processed": 12345,
        "packets_per_second": 145.7,
        "alerts_generated": 23,
        "alerts_by_severity": {"critical": 2, "high": 5, "medium": 10, "low": 6},
        "capture": {
            "total_packets": 12345,
            "total_bytes": 5678901,
            "protocol_TCP": 8000,
            "protocol_UDP": 2000,
            "protocol_ICMP": 100,
            "protocol_DNS": 1500,
            "protocol_HTTP": 500
        },
        "analysis": {
            "connections": {"active_connections": 45},
            "hosts": {"total_hosts": 12}
        },
        "uptime_seconds": 3725
    }
    
    dashboard.update_stats(test_stats)
    
    sys.exit(app.exec())
