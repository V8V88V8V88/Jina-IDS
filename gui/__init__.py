"""
Jina IDS GUI Module
User Interface Components
"""

from gui.app import IDSApplication
from gui.dashboard import Dashboard
from gui.alerts import show_alert, AlertDetailDialog, AlertNotificationPanel
from gui.report import ReportGenerator, generate_report

__all__ = [
    "IDSApplication",
    "Dashboard",
    "show_alert",
    "AlertDetailDialog",
    "AlertNotificationPanel",
    "ReportGenerator",
    "generate_report"
]

__version__ = "2.0.0"
