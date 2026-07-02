"""
PortSentinel - Report Generator
Generates HTML, TXT, and JSON reports from scan results.
"""

import json
import datetime
import os


class ReportGenerator:
    def __init__(self, target: str, results: dict, banner_data: dict,
                 os_info: dict, risk_data: dict, output_dir: str = 'reports'):
        self.target = target
        self.results = results
        self.banner_data = banner_data
        self.os_info = os_info
        self.risk_data = risk_data
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.dt_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _filename(self, ext: str) -> str:
        safe_target = self.target.replace('.', '_').replace(':', '_')
        return os.path.join(self.output_dir, f"portsentinel_{safe_target}_{self.timestamp}.{ext}")

    def generate_html(self) -> str:
        path = self._filename('html')
        posture = self.risk_data.get('posture', 'N/A') if self.risk_data else 'N/A'
        avg_score = self.risk_data.get('average_score', 0) if self.risk_data else 0
        posture_color = '#ff4444' if 'CRITICAL' in posture or 'HIGH' in posture else '#ffaa00'
        os_guess = self.os_info.get('os_guess', 'Unknown') if self.os_info else 'Not scanned'

        # Build port rows
        all_open = []
        for proto, res in self.results.items():
            for port, state in res.items():
                if state == 'OPEN':
                    all_open.append((port, proto.upper(), state))

        port_rows = ''
        for port, proto, state in sorted(all_open):
            banner_info = self.banner_data.get(port, {}) if self.banner_data else {}
            service = banner_info.get('service', self._port_name(port))
            version = banner_info.get('version', '')
            risk_info = (self.risk_data or {}).get('port_risks', {}).get(port)
            risk_level = risk_info.risk_level if risk_info else 'INFO'
            risk_score = risk_info.risk_score if risk_info else 'N/A'
            risk_colors = {
                'CRITICAL': '#ff4444', 'HIGH': '#ff8800',
                'MEDIUM': '#ffcc00', 'LOW': '#44ff88', 'INFO': '#44ccff'
            }
            rc = risk_colors.get(risk_level, '#888')
            port_rows += f"""
            <tr>
                <td>{port}</td>
                <td>{proto}</td>
                <td style="color:#44ff88">{state}</td>
                <td>{service}</td>
                <td>{version}</td>
                <td style="color:{rc}"><strong>{risk_level}</strong></td>
                <td>{risk_score}</td>
            </tr>"""

        # Build risk detail rows
        risk_rows = ''
        if self.risk_data:
            for port, risk in sorted(self.risk_data.get('port_risks', {}).items()):
                cves = ', '.join(risk.cve_references) if risk.cve_references else 'N/A'
                risk_rows += f"""
                <div class="risk-card risk-{risk.risk_level.lower()}">
                    <h3>Port {port} — {risk.service} <span class="badge">{risk.risk_level} ({risk.risk_score}/10)</span></h3>
                    <p><strong>Reason:</strong> {risk.reason}</p>
                    <p><strong>CVEs:</strong> <code>{cves}</code></p>
                    <p><strong>Remediation:</strong> {risk.remediation}</p>
                </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PortSentinel Report - {self.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ background: #0a0e1a; color: #c9d1d9; font-family: 'Courier New', monospace; padding: 2rem; }}
        .header {{ text-align: center; padding: 2rem; border-bottom: 2px solid #30363d; margin-bottom: 2rem; }}
        .header h1 {{ font-size: 2.5rem; color: #00d4ff; text-shadow: 0 0 20px #00d4ff44; letter-spacing: 4px; }}
        .header h2 {{ font-size: 1.2rem; color: #8b949e; margin-top: 0.5rem; }}
        .meta {{ display: flex; gap: 2rem; justify-content: center; margin-top: 1rem; flex-wrap: wrap; }}
        .meta-item {{ background: #161b22; padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid #30363d; font-size: 0.9rem; }}
        .meta-item span {{ color: #00d4ff; }}
        .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        .section h2 {{ color: #00d4ff; margin-bottom: 1rem; font-size: 1.1rem; letter-spacing: 2px; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        th {{ background: #1f2937; color: #8b949e; padding: 0.6rem 1rem; text-align: left; }}
        td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #21262d; }}
        tr:hover {{ background: #1c2230; }}
        .posture {{ font-size: 1.5rem; font-weight: bold; color: {posture_color}; }}
        .score {{ font-size: 3rem; color: {posture_color}; font-weight: bold; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }}
        .summary-card {{ background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }}
        .summary-card .value {{ font-size: 2rem; font-weight: bold; margin-top: 0.5rem; }}
        .risk-card {{ background: #0d1117; border-left: 4px solid #444; border-radius: 4px; padding: 1rem; margin-bottom: 1rem; }}
        .risk-card.risk-critical {{ border-left-color: #ff4444; }}
        .risk-card.risk-high {{ border-left-color: #ff8800; }}
        .risk-card.risk-medium {{ border-left-color: #ffcc00; }}
        .risk-card.risk-low {{ border-left-color: #44ff88; }}
        .risk-card h3 {{ color: #c9d1d9; margin-bottom: 0.5rem; }}
        .risk-card p {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 0.3rem; }}
        .badge {{ font-size: 0.7rem; padding: 2px 8px; border-radius: 12px; background: #30363d; color: #fff; }}
        code {{ background: #1f2937; padding: 2px 6px; border-radius: 3px; color: #ff8800; }}
        .footer {{ text-align: center; color: #30363d; margin-top: 2rem; font-size: 0.8rem; }}
        .os-box {{ display: flex; gap: 1rem; align-items: center; }}
        .os-icon {{ font-size: 3rem; }}
        .os-details p {{ color: #8b949e; font-size: 0.9rem; margin: 0.2rem 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ PORTSENTINEL</h1>
        <h2>Intelligent Port Scanner & Service Risk Analyzer</h2>
        <div class="meta">
            <div class="meta-item">Target: <span>{self.target}</span></div>
            <div class="meta-item">Scan Time: <span>{self.dt_str}</span></div>
            <div class="meta-item">Tool: <span>PortSentinel v1.0</span></div>
            <div class="meta-item">Method: <span>TCP/UDP Socket Scan</span></div>
        </div>
    </div>

    <div class="section">
        <h2>📊 EXECUTIVE SUMMARY</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div>Open Ports</div>
                <div class="value" style="color:#44ff88">{len(all_open)}</div>
            </div>
            <div class="summary-card">
                <div>Risk Score</div>
                <div class="value" style="color:{posture_color}">{avg_score}</div>
            </div>
            <div class="summary-card">
                <div>Critical</div>
                <div class="value" style="color:#ff4444">{self.risk_data.get('critical_count', 0) if self.risk_data else 0}</div>
            </div>
            <div class="summary-card">
                <div>High Risk</div>
                <div class="value" style="color:#ff8800">{self.risk_data.get('high_count', 0) if self.risk_data else 0}</div>
            </div>
            <div class="summary-card">
                <div>OS Detection</div>
                <div class="value" style="color:#44ccff; font-size:1rem">{os_guess}</div>
            </div>
            <div class="summary-card">
                <div>Security Posture</div>
                <div class="posture">{posture}</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>🔍 PORT SCAN RESULTS</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th><th>Protocol</th><th>State</th>
                    <th>Service</th><th>Version</th><th>Risk Level</th><th>Score</th>
                </tr>
            </thead>
            <tbody>{port_rows}</tbody>
        </table>
    </div>

    {f'<div class="section"><h2>🖥️ OS FINGERPRINTING</h2><div class="os-box"><div class="os-icon">🖥️</div><div class="os-details"><p><strong>OS Guess:</strong> {os_guess}</p><p><strong>Confidence:</strong> {self.os_info.get("confidence","N/A")}</p><p><strong>TTL:</strong> {self.os_info.get("ttl","N/A")}</p><p><strong>Details:</strong> {"; ".join(self.os_info.get("details",[]))}</p></div></div></div>' if self.os_info else ''}

    {f'<div class="section"><h2>⚠️ RISK ANALYSIS & REMEDIATION</h2>{risk_rows}</div>' if risk_rows else ''}

    <div class="footer">
        <p>Generated by PortSentinel v1.0 | Internship Project — Network Security | {self.dt_str}</p>
        <p>Built with Python socket programming — No Nmap dependency</p>
    </div>
</body>
</html>"""

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        return path

    def generate_txt(self) -> str:
        path = self._filename('txt')
        lines = [
            "=" * 60,
            "   PORTSENTINEL SCAN REPORT",
            "   Intelligent Port Scanner & Service Risk Analyzer",
            "=" * 60,
            f"Target     : {self.target}",
            f"Scan Time  : {self.dt_str}",
            f"Tool       : PortSentinel v1.0",
            "",
        ]

        for proto, res in self.results.items():
            open_ports = {p: s for p, s in res.items() if s == 'OPEN'}
            lines.append(f"[ {proto.upper()} OPEN PORTS ]")
            lines.append(f"{'PORT':<10} {'STATE':<12} SERVICE")
            for port in sorted(open_ports.keys()):
                lines.append(f"{port:<10} {'OPEN':<12} {self._port_name(port)}")
            lines.append("")

        if self.os_info:
            lines += [
                "[ OS DETECTION ]",
                f"OS Guess   : {self.os_info.get('os_guess','Unknown')}",
                f"Confidence : {self.os_info.get('confidence','Low')}",
                f"TTL        : {self.os_info.get('ttl','N/A')}",
                "",
            ]

        if self.risk_data:
            lines += [
                "[ RISK SUMMARY ]",
                f"Posture    : {self.risk_data.get('posture','N/A')}",
                f"Avg Score  : {self.risk_data.get('average_score',0)}/10",
                f"Critical   : {self.risk_data.get('critical_count',0)}",
                "",
                "[ RISK DETAILS ]",
            ]
            for port, risk in sorted(self.risk_data.get('port_risks', {}).items()):
                lines += [
                    f"Port {port} — {risk.service} [{risk.risk_level} {risk.risk_score}/10]",
                    f"  Reason : {risk.reason}",
                    f"  CVEs   : {', '.join(risk.cve_references) if risk.cve_references else 'N/A'}",
                    f"  Fix    : {risk.remediation}",
                    "",
                ]

        lines.append(f"Report generated: {self.dt_str}")

        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        return path

    def generate_json(self) -> str:
        path = self._filename('json')

        def serialize_risk(risk_data):
            if not risk_data:
                return {}
            out = {k: v for k, v in risk_data.items() if k != 'port_risks'}
            out['port_risks'] = {}
            for port, risk in risk_data.get('port_risks', {}).items():
                out['port_risks'][port] = {
                    'service': risk.service,
                    'risk_level': risk.risk_level,
                    'risk_score': risk.risk_score,
                    'reason': risk.reason,
                    'cve_references': risk.cve_references,
                    'remediation': risk.remediation,
                }
            return out

        data = {
            'meta': {
                'tool': 'PortSentinel v1.0',
                'target': self.target,
                'scan_time': self.dt_str,
                'method': 'TCP/UDP Socket Scan (no Nmap)',
            },
            'scan_results': {proto: {str(p): s for p, s in res.items()} for proto, res in self.results.items()},
            'banner_data': {str(p): info for p, info in (self.banner_data or {}).items()},
            'os_info': self.os_info or {},
            'risk_data': serialize_risk(self.risk_data),
        }

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return path

    def _port_name(self, port: int) -> str:
        known = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt', 27017: 'MongoDB',
        }
        return known.get(port, f'port/{port}')
