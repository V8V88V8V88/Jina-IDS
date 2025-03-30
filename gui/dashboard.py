from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Dashboard - Network Security Status"))
        self.setLayout(layout)
