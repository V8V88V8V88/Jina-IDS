from PyQt6.QtWidgets import QMessageBox

def show_alert(message):
    alert = QMessageBox()
    alert.setIcon(QMessageBox.Icon.Warning)
    alert.setWindowTitle("Threat Alert")
    alert.setText(message)
    alert.exec()
