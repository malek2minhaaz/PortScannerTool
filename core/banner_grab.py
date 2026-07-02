"""
PortSentinel - Banner Grabber
Connects to open ports and retrieves service banners.
Identifies service name, version, and protocol from raw banner strings.
"""

import socket
import re


# Service-specific probes to trigger banner responses
SERVICE_PROBES = {
    21:  b'',                        # FTP sends banner automatically
    22:  b'',                        # SSH sends banner automatically
    25:  b'EHLO portsentinel\r\n',   # SMTP EHLO
    80:  b'HEAD / HTTP/1.0\r\n\r\n', # HTTP HEAD
    110: b'',                        # POP3 sends banner
    143: b'',                        # IMAP sends banner
    443: b'HEAD / HTTP/1.0\r\n\r\n', # HTTPS (won't work without TLS but grabs banner)
    3306: b'',                       # MySQL sends banner
    5432: b'',                       # PostgreSQL
    6379: b'PING\r\n',              # Redis
    8080: b'HEAD / HTTP/1.0\r\n\r\n',
    27017: b'',                      # MongoDB
}

# Known service signatures
SERVICE_SIGNATURES = {
    r'SSH-(\d+\.\d+)-([^\r\n]+)':      lambda m: f"SSH {m.group(1)} ({m.group(2).strip()})",
    r'220[- ]([^\r\n]*(FTP|vsftpd|ProFTPD|FileZilla)[^\r\n]*)': lambda m: f"FTP - {m.group(1).strip()}",
    r'220[- ]([^\r\n]*(SMTP|Postfix|Sendmail|Exchange)[^\r\n]*)': lambda m: f"SMTP - {m.group(1).strip()}",
    r'HTTP/(\d\.\d)\s+\d+':            lambda m: f"HTTP/{m.group(1)}",
    r'Server:\s*([^\r\n]+)':           lambda m: f"HTTP Server: {m.group(1).strip()}",
    r'Apache/([^\s]+)':                lambda m: f"Apache {m.group(1)}",
    r'nginx/([^\s\r\n]+)':             lambda m: f"Nginx {m.group(1)}",
    r'(\d+\.\d+\.\d+)-([^\r\n]+)MySQL': lambda m: f"MySQL {m.group(1)}",
    r'Redis\s+([\d\.]+)':              lambda m: f"Redis {m.group(1)}",
    r'\+PONG':                         lambda m: "Redis (PONG response)",
    r'^\*1\r\n\$4\r\nPONG':           lambda m: "Redis",
    r'ERR':                            lambda m: "Service error response",
}


class BannerGrabber:
    """
    Grabs service banners from open TCP ports.
    Uses service-specific probes and regex-based identification.
    """

    def __init__(self, target: str, timeout: float = 2.0):
        self.target = target
        self.timeout = timeout
        try:
            self.ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.ip = target

    def grab(self, port: int) -> dict:
        """Grab banner from a single port. Returns banner info dict."""
        result = {
            'port': port,
            'raw_banner': '',
            'service': 'Unknown',
            'version': '',
            'banner_clean': '',
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.ip, port))

            # Send probe if defined
            probe = SERVICE_PROBES.get(port, b'')
            if probe:
                sock.send(probe)

            # Receive banner
            banner_bytes = sock.recv(1024)
            sock.close()

            if banner_bytes:
                banner = banner_bytes.decode('utf-8', errors='replace').strip()
                result['raw_banner'] = banner
                result['banner_clean'] = ' '.join(banner.split())[:200]

                # Identify service from banner
                identified = self._identify(banner, port)
                result['service'] = identified['service']
                result['version'] = identified['version']

        except socket.timeout:
            result['service'] = 'Timeout (no banner)'
        except ConnectionRefusedError:
            result['service'] = 'Connection refused'
        except Exception as e:
            result['service'] = f'Error: {type(e).__name__}'

        return result

    def _identify(self, banner: str, port: int) -> dict:
        """Identify service from banner using regex signatures."""
        for pattern, formatter in SERVICE_SIGNATURES.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                identified = formatter(match)
                if ':' in identified:
                    parts = identified.split(':', 1)
                    return {'service': parts[0].strip(), 'version': parts[1].strip()}
                return {'service': identified, 'version': ''}

        # Fallback: use well-known port mapping
        fallback = self._port_to_service(port)
        return {'service': fallback, 'version': ''}

    def _port_to_service(self, port: int) -> str:
        """Map common ports to service names."""
        known = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 27017: 'MongoDB',
        }
        return known.get(port, f'Unknown (port {port})')

    def grab_all(self, ports: list) -> dict:
        """Grab banners from all specified ports. Returns {port: info}."""
        banner_data = {}
        if not ports:
            print("  \033[90m[~] No open ports to grab banners from.\033[0m")
            return banner_data

        for port in sorted(ports):
            print(f"  \033[90m[~] Grabbing banner from port {port}...\033[0m", end=' ')
            info = self.grab(port)
            banner_data[port] = info
            svc = info['service']
            ver = info['version']
            label = f"{svc} {ver}".strip() if ver else svc
            print(f"\033[96m{label}\033[0m")

        return banner_data
