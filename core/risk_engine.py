"""
PortSentinel - Risk Scoring Engine
Assigns CVSS-inspired risk scores to open ports based on:
- Port danger classification (HIGH/MEDIUM/LOW)
- Service banner analysis
- CVE reference mapping
- Remediation guidance
"""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class PortRisk:
    port: int
    service: str
    risk_level: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    risk_score: float        # 0.0 - 10.0
    reason: str
    cve_references: List[str] = field(default_factory=list)
    remediation: str = ''


# Port risk database — designed to go beyond Nmap's simple service listing
PORT_RISK_DB = {
    21: {
        'service': 'FTP',
        'risk': 'HIGH',
        'score': 8.0,
        'reason': 'FTP transmits credentials in plaintext. Susceptible to MITM and brute-force attacks.',
        'cves': ['CVE-2011-2523', 'CVE-2015-3306'],
        'remediation': 'Replace FTP with SFTP (port 22) or FTPS. Disable anonymous login. Use strong passwords.'
    },
    22: {
        'service': 'SSH',
        'risk': 'MEDIUM',
        'score': 5.0,
        'reason': 'SSH is encrypted but exposed SSH can be brute-forced. Version matters.',
        'cves': ['CVE-2023-38408', 'CVE-2016-0777'],
        'remediation': 'Use key-based authentication only. Disable root login. Change default port. Use Fail2Ban.'
    },
    23: {
        'service': 'Telnet',
        'risk': 'CRITICAL',
        'score': 9.8,
        'reason': 'Telnet sends all data including passwords in plaintext over the network.',
        'cves': ['CVE-2011-4862', 'CVE-2020-10188'],
        'remediation': 'Immediately disable Telnet. Replace with SSH. Block port 23 at firewall.'
    },
    25: {
        'service': 'SMTP',
        'risk': 'MEDIUM',
        'score': 5.5,
        'reason': 'Open SMTP relay can be abused for spam. Version-specific vulnerabilities exist.',
        'cves': ['CVE-2019-10149', 'CVE-2020-7247'],
        'remediation': 'Disable open relay. Require authentication. Use TLS. Configure SPF/DKIM/DMARC.'
    },
    53: {
        'service': 'DNS',
        'risk': 'MEDIUM',
        'score': 6.0,
        'reason': 'Open DNS resolvers enable amplification DDoS attacks and cache poisoning.',
        'cves': ['CVE-2020-1350', 'CVE-2008-1447'],
        'remediation': 'Restrict recursive queries to internal networks. Enable DNSSEC. Rate-limit queries.'
    },
    80: {
        'service': 'HTTP',
        'risk': 'MEDIUM',
        'score': 5.0,
        'reason': 'Unencrypted HTTP exposes data in transit. Common web vulnerabilities apply.',
        'cves': ['CVE-2021-41773', 'CVE-2017-7679'],
        'remediation': 'Redirect HTTP to HTTPS. Implement HSTS. Regularly patch the web server.'
    },
    110: {
        'service': 'POP3',
        'risk': 'HIGH',
        'score': 7.5,
        'reason': 'POP3 without TLS transmits email and credentials in plaintext.',
        'cves': ['CVE-2010-4535'],
        'remediation': 'Use POP3S (port 995) with TLS. Disable plain POP3. Migrate to IMAP over TLS.'
    },
    135: {
        'service': 'MS-RPC',
        'risk': 'HIGH',
        'score': 8.5,
        'reason': 'Windows RPC endpoint mapper. Historically exploited by worms like Blaster.',
        'cves': ['CVE-2003-0352', 'CVE-2017-0143'],
        'remediation': 'Block port 135 at firewall perimeter. Apply all Windows security patches.'
    },
    139: {
        'service': 'NetBIOS',
        'risk': 'HIGH',
        'score': 8.0,
        'reason': 'NetBIOS exposes Windows network shares and host information.',
        'cves': ['CVE-2017-0143', 'CVE-2020-0796'],
        'remediation': 'Disable NetBIOS over TCP/IP. Block ports 137-139. Use firewall rules.'
    },
    143: {
        'service': 'IMAP',
        'risk': 'MEDIUM',
        'score': 6.0,
        'reason': 'Unencrypted IMAP exposes email content and authentication credentials.',
        'cves': ['CVE-2021-38371'],
        'remediation': 'Migrate to IMAPS (port 993). Enforce TLS 1.2+. Disable STARTTLS downgrade.'
    },
    443: {
        'service': 'HTTPS',
        'risk': 'LOW',
        'score': 2.0,
        'reason': 'HTTPS is generally safe. Risk depends on certificate and TLS version.',
        'cves': ['CVE-2014-0160'],
        'remediation': 'Use TLS 1.2 or 1.3. Disable SSLv2/SSLv3/TLS 1.0. Renew certificates on time.'
    },
    445: {
        'service': 'SMB',
        'risk': 'CRITICAL',
        'score': 9.5,
        'reason': 'SMB has been exploited by EternalBlue (WannaCry ransomware). Never expose externally.',
        'cves': ['CVE-2017-0144', 'CVE-2020-0796'],
        'remediation': 'Block port 445 at firewall. Apply MS17-010 patch. Disable SMBv1 immediately.'
    },
    1433: {
        'service': 'MSSQL',
        'risk': 'CRITICAL',
        'score': 9.0,
        'reason': 'Exposed MSSQL is a high-value target for SQL injection and brute-force.',
        'cves': ['CVE-2020-0618', 'CVE-2019-1068'],
        'remediation': 'Never expose MSSQL to the internet. Use firewall rules. Require strong auth. Audit logins.'
    },
    3306: {
        'service': 'MySQL',
        'risk': 'HIGH',
        'score': 8.5,
        'reason': 'Exposed MySQL is a high-value target. Default configs are often insecure.',
        'cves': ['CVE-2012-2122', 'CVE-2016-6662'],
        'remediation': 'Bind MySQL to 127.0.0.1. Use firewall. Remove anonymous accounts. Audit privileges.'
    },
    3389: {
        'service': 'RDP',
        'risk': 'CRITICAL',
        'score': 9.8,
        'reason': 'RDP is frequently targeted by ransomware and brute-force campaigns.',
        'cves': ['CVE-2019-0708', 'CVE-2020-0609'],
        'remediation': 'Place RDP behind VPN. Enable NLA. Block port 3389 publicly. Use Account Lockout policy.'
    },
    5432: {
        'service': 'PostgreSQL',
        'risk': 'HIGH',
        'score': 8.0,
        'reason': 'Exposed PostgreSQL allows direct database access if misconfigured.',
        'cves': ['CVE-2019-10164', 'CVE-2018-10915'],
        'remediation': 'Bind to localhost. Use pg_hba.conf rules. Enforce password policies. Use SSL mode.'
    },
    6379: {
        'service': 'Redis',
        'risk': 'CRITICAL',
        'score': 9.8,
        'reason': 'Redis has no auth by default. Exposed Redis allows full data access and RCE via config writes.',
        'cves': ['CVE-2022-0543', 'CVE-2021-32628'],
        'remediation': 'Bind Redis to localhost. Set requirepass. Disable CONFIG command externally. Use firewall.'
    },
    8080: {
        'service': 'HTTP-Alt',
        'risk': 'MEDIUM',
        'score': 5.5,
        'reason': 'Alternate HTTP port. Often used by dev servers or proxies with weaker security.',
        'cves': [],
        'remediation': 'Audit what service is running. Apply same security as port 80. Avoid exposing dev services.'
    },
    27017: {
        'service': 'MongoDB',
        'risk': 'CRITICAL',
        'score': 9.5,
        'reason': 'MongoDB with no auth exposed to internet has caused numerous data breaches.',
        'cves': ['CVE-2019-2389'],
        'remediation': 'Enable --auth. Bind to localhost. Never expose MongoDB to the internet. Use firewall.'
    },
}

RISK_COLOR = {
    'CRITICAL': '\033[91m',   # Red
    'HIGH':     '\033[93m',   # Yellow
    'MEDIUM':   '\033[33m',   # Orange-ish
    'LOW':      '\033[92m',   # Green
    'INFO':     '\033[96m',   # Cyan
}


class RiskEngine:
    """
    Analyzes open ports and assigns risk scores.
    Provides CVE references and remediation guidance.
    """

    def analyze(self, open_ports: list, banner_data: dict = None) -> dict:
        """
        Analyze open ports and return risk report.
        Returns dict with per-port risks and summary.
        """
        port_risks = {}
        total_score = 0.0
        critical_count = 0
        high_count = 0

        for port in sorted(open_ports):
            if port in PORT_RISK_DB:
                db = PORT_RISK_DB[port]
                risk = PortRisk(
                    port=port,
                    service=db['service'],
                    risk_level=db['risk'],
                    risk_score=db['score'],
                    reason=db['reason'],
                    cve_references=db.get('cves', []),
                    remediation=db['remediation']
                )
            else:
                # Unknown port — assign generic risk
                risk = PortRisk(
                    port=port,
                    service=self._get_service_from_banner(port, banner_data),
                    risk_level='LOW',
                    risk_score=3.0,
                    reason=f'Non-standard open port {port}. Review necessity and apply firewall rules.',
                    cve_references=[],
                    remediation='Identify the service. If unnecessary, close the port. Apply firewall rules.'
                )

            port_risks[port] = risk
            total_score += risk.risk_score
            if risk.risk_level == 'CRITICAL':
                critical_count += 1
            elif risk.risk_level == 'HIGH':
                high_count += 1

        # Overall posture score
        avg_score = round(total_score / len(open_ports), 2) if open_ports else 0.0
        posture = self._get_posture(avg_score, critical_count)

        return {
            'port_risks': port_risks,
            'total_open': len(open_ports),
            'critical_count': critical_count,
            'high_count': high_count,
            'average_score': avg_score,
            'posture': posture,
        }

    def _get_service_from_banner(self, port: int, banner_data: dict) -> str:
        if banner_data and port in banner_data:
            return banner_data[port].get('service', f'Unknown:{port}')
        return f'Unknown (port {port})'

    def _get_posture(self, avg_score: float, critical_count: int) -> str:
        if critical_count >= 2 or avg_score >= 8.0:
            return 'COMPROMISED RISK'
        elif critical_count == 1 or avg_score >= 6.0:
            return 'HIGH RISK'
        elif avg_score >= 4.0:
            return 'MODERATE RISK'
        elif avg_score >= 2.0:
            return 'LOW RISK'
        else:
            return 'MINIMAL RISK'
