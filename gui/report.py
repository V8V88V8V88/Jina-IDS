"""
Jina IDS - Report Generation
Professional Security Report Generation
"""

import os
import json
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger("JinaIDS.Report")


@dataclass
class ReportSummary:
    """Summary statistics for a report."""
    start_time: datetime
    end_time: datetime
    total_packets: int
    total_alerts: int
    alerts_by_severity: Dict[str, int]
    alerts_by_category: Dict[str, int]
    top_sources: List[tuple]
    top_destinations: List[tuple]
    top_rules_triggered: List[tuple]
    protocols_analyzed: Dict[str, int]


class ReportGenerator:
    """
    Generate comprehensive security reports.
    
    Supports:
    - CSV export
    - JSON export
    - HTML report
    - Executive summary
    """
    
    def __init__(self, output_dir: str = "data/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_report(
        self, 
        alerts: List[Any], 
        stats: Dict[str, Any],
        format: str = "html"
    ) -> str:
        """
        Generate a security report.
        
        Args:
            alerts: List of Alert objects
            stats: Statistics dictionary
            format: Output format (html, csv, json)
        
        Returns:
            Path to generated report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == "csv":
            return self._generate_csv(alerts, timestamp)
        elif format == "json":
            return self._generate_json(alerts, stats, timestamp)
        else:
            return self._generate_html(alerts, stats, timestamp)
    
    def _generate_csv(self, alerts: List[Any], timestamp: str) -> str:
        """Generate CSV report of alerts."""
        filepath = os.path.join(self.output_dir, f"alerts_{timestamp}.csv")
        
        fieldnames = [
            "timestamp", "severity", "rule_id", "rule_name", 
            "category", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "mitre_attack", "description", "matched_content"
        ]
        
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for alert in alerts:
                row = {
                    "timestamp": getattr(alert, 'timestamp', '').isoformat() if hasattr(alert, 'timestamp') else '',
                    "severity": getattr(alert, 'severity', ''),
                    "rule_id": getattr(alert, 'rule_id', ''),
                    "rule_name": getattr(alert, 'rule_name', ''),
                    "category": getattr(alert, 'category', ''),
                    "src_ip": getattr(alert, 'src_ip', ''),
                    "dst_ip": getattr(alert, 'dst_ip', ''),
                    "src_port": getattr(alert, 'src_port', 0),
                    "dst_port": getattr(alert, 'dst_port', 0),
                    "protocol": getattr(alert, 'protocol', ''),
                    "mitre_attack": getattr(alert, 'mitre_attack', ''),
                    "description": getattr(alert, 'description', ''),
                    "matched_content": getattr(alert, 'matched_content', '')[:200]
                }
                writer.writerow(row)
        
        logger.info(f"CSV report generated: {filepath}")
        return filepath
    
    def _generate_json(self, alerts: List[Any], stats: Dict, timestamp: str) -> str:
        """Generate JSON report."""
        filepath = os.path.join(self.output_dir, f"report_{timestamp}.json")
        
        report_data = {
            "report_info": {
                "generated_at": datetime.now().isoformat(),
                "generator": "Jina IDS",
                "version": "2.0.0"
            },
            "statistics": stats,
            "alerts": [
                {
                    "timestamp": getattr(a, 'timestamp', '').isoformat() if hasattr(a, 'timestamp') else '',
                    "severity": getattr(a, 'severity', ''),
                    "rule_id": getattr(a, 'rule_id', ''),
                    "rule_name": getattr(a, 'rule_name', ''),
                    "category": getattr(a, 'category', ''),
                    "src_ip": getattr(a, 'src_ip', ''),
                    "dst_ip": getattr(a, 'dst_ip', ''),
                    "protocol": getattr(a, 'protocol', ''),
                    "mitre_attack": getattr(a, 'mitre_attack', ''),
                    "description": getattr(a, 'description', '')
                }
                for a in alerts
            ]
        }
        
        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {filepath}")
        return filepath
    
    def _generate_html(self, alerts: List[Any], stats: Dict, timestamp: str) -> str:
        """Generate HTML report."""
        filepath = os.path.join(self.output_dir, f"report_{timestamp}.html")
        
        # Count severities
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        category_counts: Dict[str, int] = {}
        
        for alert in alerts:
            sev = getattr(alert, 'severity', 'low')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            cat = getattr(alert, 'category', 'unknown')
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        # Generate alert rows
        alert_rows = ""
        for alert in alerts[:100]:  # Limit to 100 for HTML
            sev_class = getattr(alert, 'severity', 'low')
            alert_rows += f"""
            <tr class="alert-{sev_class}">
                <td>{getattr(alert, 'timestamp', '').strftime('%H:%M:%S') if hasattr(alert, 'timestamp') else ''}</td>
                <td><span class="severity-badge {sev_class}">{sev_class.upper()}</span></td>
                <td>{getattr(alert, 'rule_name', '')}</td>
                <td>{getattr(alert, 'src_ip', '')}:{getattr(alert, 'src_port', '')}</td>
                <td>{getattr(alert, 'dst_ip', '')}:{getattr(alert, 'dst_port', '')}</td>
                <td>{getattr(alert, 'category', '')}</td>
                <td>{getattr(alert, 'mitre_attack', '')}</td>
            </tr>
            """
        
        # Category stats
        category_html = ""
        for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            category_html += f"<li>{cat}: {count}</li>"
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jina IDS Security Report</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
            color: #e2e8f0;
            min-height: 100vh;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        
        header {{
            background: linear-gradient(90deg, #2d3748, #4a5568);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}
        h1 {{ margin: 0; font-size: 2.5em; }}
        h1 .icon {{ font-size: 1.2em; }}
        .subtitle {{ color: #a0aec0; margin-top: 10px; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #2d3748;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #4299e1;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }}
        .stat-card.critical {{ border-color: #f56565; }}
        .stat-card.high {{ border-color: #ed8936; }}
        .stat-card.medium {{ border-color: #ecc94b; }}
        .stat-card.low {{ border-color: #48bb78; }}
        
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #fff;
        }}
        .stat-label {{ color: #a0aec0; margin-top: 5px; }}
        
        .section {{
            background: #2d3748;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }}
        .section h2 {{
            margin-top: 0;
            border-bottom: 2px solid #4a5568;
            padding-bottom: 10px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #4a5568;
        }}
        th {{ background: #1a202c; color: #a0aec0; }}
        tr:hover {{ background: #4a5568; }}
        
        .severity-badge {{
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .severity-badge.critical {{ background: #f56565; color: #fff; }}
        .severity-badge.high {{ background: #ed8936; color: #fff; }}
        .severity-badge.medium {{ background: #ecc94b; color: #1a202c; }}
        .severity-badge.low {{ background: #48bb78; color: #fff; }}
        
        ul {{ padding-left: 20px; }}
        li {{ margin: 8px 0; }}
        
        footer {{
            text-align: center;
            color: #718096;
            margin-top: 30px;
            padding: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span class="icon">🛡️</span> Jina IDS Security Report</h1>
            <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{len(alerts)}</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">{severity_counts.get('critical', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{severity_counts.get('high', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{severity_counts.get('medium', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">{severity_counts.get('low', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Alert Categories</h2>
            <ul>
                {category_html if category_html else '<li>No alerts recorded</li>'}
            </ul>
        </div>
        
        <div class="section">
            <h2>🚨 Recent Alerts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Severity</th>
                        <th>Rule</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Category</th>
                        <th>MITRE</th>
                    </tr>
                </thead>
                <tbody>
                    {alert_rows if alert_rows else '<tr><td colspan="7" style="text-align:center;">No alerts recorded</td></tr>'}
                </tbody>
            </table>
        </div>
        
        <footer>
            <p>Generated by Jina IDS - Professional Network Intrusion Detection System</p>
        </footer>
    </div>
</body>
</html>
        """
        
        with open(filepath, "w") as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {filepath}")
        return filepath


def generate_report(
    log_file: str = "data/logs/alerts.log",
    output_file: str = None,
    format: str = "html"
) -> str:
    """
    Convenience function to generate a report.
    
    Args:
        log_file: Path to alerts log (not used in new version)
        output_file: Custom output path (optional)
        format: Report format (html, csv, json)
    
    Returns:
        Path to generated report
    """
    generator = ReportGenerator()
    
    # This is a placeholder - in real use, you'd pass actual alerts
    filepath = generator.generate_report([], {}, format)
    
    print(f"Report generated: {filepath}")
    return filepath


if __name__ == "__main__":
    # Test report generation
    from datetime import datetime
    from dataclasses import dataclass
    
    @dataclass
    class MockAlert:
        timestamp: datetime
        severity: str
        rule_id: str
        rule_name: str
        category: str
        src_ip: str
        dst_ip: str
        src_port: int
        dst_port: int
        protocol: str
        mitre_attack: str
        description: str
        matched_content: str
    
    # Generate test alerts
    alerts = [
        MockAlert(
            timestamp=datetime.now(),
            severity="critical",
            rule_id="SQL-001",
            rule_name="SQL Injection",
            category="web_attack",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol="HTTP",
            mitre_attack="T1190",
            description="SQL injection detected",
            matched_content="UNION SELECT"
        ),
        MockAlert(
            timestamp=datetime.now(),
            severity="high",
            rule_id="XSS-001",
            rule_name="XSS Attack",
            category="web_attack",
            src_ip="192.168.1.101",
            dst_ip="10.0.0.1",
            src_port=54322,
            dst_port=80,
            protocol="HTTP",
            mitre_attack="T1059.007",
            description="XSS detected",
            matched_content="<script>"
        )
    ]
    
    generator = ReportGenerator()
    
    # Generate all formats
    html_path = generator.generate_report(alerts, {}, "html")
    csv_path = generator.generate_report(alerts, {}, "csv")
    json_path = generator.generate_report(alerts, {}, "json")
    
    print(f"Generated reports:")
    print(f"  HTML: {html_path}")
    print(f"  CSV: {csv_path}")
    print(f"  JSON: {json_path}")
