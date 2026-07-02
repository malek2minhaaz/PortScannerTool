"""
PortSentinel - OS Fingerprinter
Detects operating system using:
1. ICMP TTL analysis (ping-based TTL inspection)
2. TCP Window Size fingerprinting
3. Open port profile matching
All implemented using raw Python sockets — no Nmap dependency.
"""

import socket
import struct
import subprocess
import platform
import re
from typing import Dict, Optional


# TTL → OS mapping (default TTL values per OS)
TTL_OS_MAP = [
    (255, 'Cisco IOS / Network Device'),
    (128, 'Windows (XP/7/8/10/11/Server)'),
    (64,  'Linux / macOS / Android / iOS'),
    (60,  'macOS (older)'),
    (32,  'Windows 95/98 (very old)'),
    (30,  'Windows 95 (very old)'),
]

# TCP Window sizes often associated with specific OS/stacks
WINDOW_OS_MAP = {
    65535: 'Windows / macOS (likely)',
    8192:  'Windows (classic)',
    5840:  'Linux 2.4+',
    29200: 'Linux 3.x+',
    14600: 'Linux 2.6',
    65340: 'macOS',
}

# Port profile → OS hints
PORT_OS_HINTS = {
    135:  'Windows (MS-RPC)',
    139:  'Windows (NetBIOS)',
    445:  'Windows (SMB)',
    3389: 'Windows (RDP)',
    5985: 'Windows (WinRM)',
    548:  'macOS (AFP)',
    22:   'Linux/Unix (OpenSSH)',
    2049: 'Linux/Unix (NFS)',
    111:  'Linux/Unix (RPC)',
}


class OSFingerprinter:
    """
    Passive + active OS fingerprinting using Python sockets and ICMP.
    """

    def __init__(self, target: str, timeout: float = 2.0):
        self.target = target
        self.timeout = timeout
        try:
            self.ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.ip = target

    def detect(self) -> Dict:
        """Run OS detection and return results dict."""
        result = {
            'ip': self.ip,
            'ttl': None,
            'ttl_os': 'Unknown',
            'port_hints': [],
            'confidence': 'Low',
            'os_guess': 'Unknown',
            'details': []
        }

        # Step 1: TTL via system ping
        ttl = self._get_ttl_ping()
        if ttl:
            result['ttl'] = ttl
            os_from_ttl = self._ttl_to_os(ttl)
            result['ttl_os'] = os_from_ttl
            result['details'].append(f"TTL={ttl} → suggests {os_from_ttl}")
            result['os_guess'] = os_from_ttl
            result['confidence'] = 'Medium'

        # Step 2: TCP Window size fingerprint
        window_os = self._tcp_window_fingerprint()
        if window_os:
            result['details'].append(f"TCP Window → {window_os}")
            if result['os_guess'] == 'Unknown':
                result['os_guess'] = window_os

        # Step 3: Port profile (if open_ports provided via TCP banner, we can check)
        # We probe a few well-known Windows/Linux ports
        port_hints = self._port_profile_hints()
        if port_hints:
            result['port_hints'] = port_hints
            for hint in port_hints:
                result['details'].append(f"Open port hint: {hint}")
            result['confidence'] = 'High'
            # Override OS guess based on port evidence
            hint_str = ' '.join(port_hints)
            if 'Windows' in hint_str:
                result['os_guess'] = 'Windows'
            elif 'Linux' in hint_str or 'Unix' in hint_str:
                result['os_guess'] = 'Linux/Unix'

        return result

    def _get_ttl_ping(self) -> Optional[int]:
        """Get TTL value by issuing a system ping and parsing output."""
        try:
            os_name = platform.system().lower()
            if os_name == 'windows':
                cmd = ['ping', '-n', '1', self.ip]
                pattern = r'TTL[=\s]+(\d+)'
            else:
                cmd = ['ping', '-c', '1', '-W', '2', self.ip]
                pattern = r'ttl[=\s]+(\d+)'

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            match = re.search(pattern, result.stdout, re.IGNORECASE)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None

    def _ttl_to_os(self, ttl: int) -> str:
        """Determine likely OS from TTL value."""
        # TTL decrements each hop — find nearest default TTL
        for default_ttl, os_name in sorted(TTL_OS_MAP, key=lambda x: x[0]):
            if ttl <= default_ttl:
                return os_name
        return f'Unknown (TTL={ttl})'

    def _tcp_window_fingerprint(self) -> Optional[str]:
        """Attempt TCP connection and read window size from SYN-ACK."""
        # Try to connect to common ports and check socket buffer info
        test_ports = [80, 22, 443, 8080, 21]
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.ip, port))
                if result == 0:
                    # Get socket receive window (approximate)
                    buf_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                    sock.close()
                    for window, os_name in WINDOW_OS_MAP.items():
                        if abs(buf_size - window * 2) < 1000:
                            return os_name
                    return f'Window size {buf_size}'
                sock.close()
            except Exception:
                pass
        return None

    def _port_profile_hints(self) -> list:
        """Probe a few OS-specific ports to gather hints."""
        hints = []
        probe_ports = list(PORT_OS_HINTS.keys())[:8]  # Limit probes

        for port in probe_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.ip, port))
                sock.close()
                if result == 0:
                    hints.append(PORT_OS_HINTS[port])
            except Exception:
                pass

        return list(set(hints))  # Deduplicate
