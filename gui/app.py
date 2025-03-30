from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel
import sys

class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Jina - Network Security")
        self.label = QLabel("Jina Network Analyzer", self)
        self.label.setGeometry(50, 50, 300, 50)

app = QApplication(sys.argv)
window = MainApp()
window.show()
sys.exit(app.exec())
