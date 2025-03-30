from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QLabel, QWidget, QPushButton
from gui.dashboard import Dashboard
from gui.alerts import show_alert
from gui.report import generate_report

class IDSApplication(QMainWindow):
    """Main GUI application for Jina Network Analyzer."""
    
    def __init__(self, config, base_dir, logger):
        super().__init__()
        self.config = config
        self.base_dir = base_dir
        self.logger = logger

        self.setWindowTitle("Jina Network Analyzer")
        self.setGeometry(100, 100, 800, 600)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        # Dashboard section
        self.dashboard = Dashboard()
        layout.addWidget(self.dashboard)

        # Start Detection Button
        self.start_button = QPushButton("Start Detection")
        self.start_button.clicked.connect(self.start_detection)
        layout.addWidget(self.start_button)

        # Generate Report Button
        self.report_button = QPushButton("Generate Report")
        self.report_button.clicked.connect(self.generate_report)
        layout.addWidget(self.report_button)

        # Set Layout
        central_widget.setLayout(layout)

    def start_detection(self):
        """Start the network detection process."""
        from core.detector import ThreatDetector

        self.logger.info("Starting Network Threat Detection...")
        detector = ThreatDetector()
        detector.run()

    def generate_report(self):
        """Generate network security report."""
        generate_report()
        show_alert("Network report generated successfully!")

