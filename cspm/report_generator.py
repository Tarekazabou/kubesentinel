"""
Report Generator - Generate JSON and HTML reports from CSPM findings
"""

import json
from pathlib import Path
from typing import List, Dict
from datetime import datetime


class ReportGenerator:
    """Generate reports from manifest scan findings."""
    
    def __init__(self, findings: List[Dict]):
        self.findings = findings
        self.severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    
    def generate_json(self, output_path: str):
        """Generate JSON report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': self._get_summary(),
            'findings': sorted(
                self.findings,
                key=lambda x: self.severity_order.get(x['severity'], 99)
            )
        }
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
    
    def generate_html(self, output_path: str):
        """Generate HTML report."""
        summary = self._get_summary()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KubeSentinel CSPM Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        
        h1 {{
            color: #333;
            margin-bottom: 10px;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 10px;
        }}
        
        .timestamp {{
            color: #666;
            font-size: 12px;
            margin-bottom: 20px;
        }}
        
        .summary {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
            border-left: 4px solid #2c3e50;
        }}
        
        .summary h2 {{
            color: #2c3e50;
            margin-bottom: 15px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }}
        
        .stat {{
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            color: white;
            font-weight: bold;
        }}
        
        .stat-critical {{
            background: linear-gradient(135deg, #ff6b6b, #ee5a6f);
        }}
        
        .stat-high {{
            background: linear-gradient(135deg, #ffa94d, #ff922b);
        }}
        
        .stat-medium {{
            background: linear-gradient(135deg, #ffd93d, #fcb900);
        }}
        
        .stat-low {{
            background: linear-gradient(135deg, #6bcf7f, #51cf66);
        }}
        
        .stat-total {{
            background: linear-gradient(135deg, #2c3e50, #34495e);
        }}
        
        .stat-value {{
            font-size: 28px;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 12px;
            opacity: 0.9;
        }}
        
        table {{
            border-collapse: collapse;
            width: 100%;
            margin-top: 20px;
        }}
        
        thead {{
            background-color: #2c3e50;
            color: white;
        }}
        
        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        tbody tr {{
            border-bottom: 1px solid #e0e0e0;
        }}
        
        tbody tr:hover {{
            background-color: #f8f9fa;
        }}
        
        td {{
            padding: 12px 15px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 12px;
        }}
        
        .critical {{
            background: #ff6b6b;
        }}
        
        .high {{
            background: #ffa94d;
        }}
        
        .medium {{
            background: #ffd93d;
            color: #333;
        }}
        
        .low {{
            background: #6bcf7f;
        }}
        
        .rule {{
            font-family: 'Courier New', monospace;
            font-size: 12px;
            background: #f5f5f5;
            padding: 3px 6px;
            border-radius: 3px;
        }}
        
        .file {{
            color: #666;
            font-size: 12px;
        }}
        
        .message {{
            color: #333;
        }}
        
        .remediation {{
            color: #27ae60;
            font-size: 12px;
        }}
        
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #666;
            font-size: 12px;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>KubeSentinel CSPM Report</h1>
        <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        
        <div class="summary">
            <h2>Summary</h2>
            <div class="stats">
                <div class="stat stat-total">
                    <div class="stat-value">{summary['total']}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat stat-critical">
                    <div class="stat-value">{summary['CRITICAL']}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat stat-high">
                    <div class="stat-value">{summary['HIGH']}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat stat-medium">
                    <div class="stat-value">{summary['MEDIUM']}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat stat-low">
                    <div class="stat-value">{summary['LOW']}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </div>
"""
        
        if self.findings:
            html += """
        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>File</th>
                    <th>Message</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
"""
            
            for finding in sorted(
                self.findings,
                key=lambda x: self.severity_order.get(x['severity'], 99)
            ):
                severity = finding['severity']
                html += f"""
                <tr>
                    <td><span class="severity-badge {severity.lower()}">{severity}</span></td>
                    <td><span class="rule">{finding['rule']}</span></td>
                    <td><span class="file">{finding.get('file', 'N/A')}</span></td>
                    <td><span class="message">{finding['message']}</span></td>
                    <td><span class="remediation">{finding.get('remediation', 'N/A')}</span></td>
                </tr>
"""
            
            html += """
            </tbody>
        </table>
"""
        else:
            html += """
        <div class="no-findings">
            <h2>✓ No findings detected</h2>
            <p>Your Kubernetes manifests appear to be secure!</p>
        </div>
"""
        
        html += """
        <div class="footer">
            <p>KubeSentinel CSPM Report | Cloud Security Posture Management</p>
        </div>
    </div>
</body>
</html>
"""
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _get_summary(self) -> Dict[str, int]:
        """Count findings by severity."""
        summary = {'total': len(self.findings), 'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            severity = finding.get('severity', 'UNKNOWN')
            if severity in summary:
                summary[severity] += 1
        return summary
    
    def get_summary_text(self) -> str:
        """Get a text summary of findings."""
        summary = self._get_summary()
        text = f"""
KubeSentinel CSPM Report Summary
================================

Total Findings: {summary['total']}
  Critical: {summary['CRITICAL']}
  High: {summary['HIGH']}
  Medium: {summary['MEDIUM']}
  Low: {summary['LOW']}

Generated: {datetime.now().isoformat()}
"""
        return text
