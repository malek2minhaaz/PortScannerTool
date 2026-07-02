"""
PortSentinel - Core Port Scanner
Uses Python socket programming (NOT Nmap)
Implements multi-threaded TCP connect scan and UDP probe scan
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import Logger


class PortScanner:
    """
    Multi-threaded port scanner using raw Python sockets.
    Supports TCP Connect Scan and UDP Probe Scan.
    Differentiated from Nmap: no SYN/stealth scanning — uses full connect
    with intelligent state classification (OPEN / CLOSED / FILTERED).
    """

    def __init__(self, target: str, ports: list, threads: int = 100,
                 timeout: float = 1.0, logger: Logger = None):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.logger = logger
        self._resolve_target()
        self._lock = threading.Lock()
        self._scanned = 0
        self._total = len(ports)

    def _resolve_target(self):
        """Resolve hostname to IP."""
        try:
            self.ip = socket.gethostbyname(self.target)
            if self.ip != self.target:
                print(f"\033[90m  [~] Resolved {self.target} → {self.ip}\033[0m")
        except socket.gaierror:
            print(f"\033[91m  [!] Cannot resolve host: {self.target}\033[0m")
            raise SystemExit(1)

    def _tcp_probe(self, port: int) -> tuple:
        """
        TCP Connect Probe — Full 3-way handshake.
        Returns (port, state) where state is OPEN / CLOSED / FILTERED
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            sock.close()

            if result == 0:
                return (port, 'OPEN')
            elif result in (111, 61, 10061):   # Connection refused
                return (port, 'CLOSED')
            else:
                return (port, 'FILTERED')

        except socket.timeout:
            return (port, 'FILTERED')
        except socket.error:
            return (port, 'FILTERED')

    def _udp_probe(self, port: int) -> tuple:
        """
        UDP Probe — Send empty datagram, check for ICMP port unreachable.
        UDP is inherently unreliable; OPEN|FILTERED if no response.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Send a probe packet
            probe_data = b'\x00' * 8
            # Use service-specific probes for known ports
            if port == 53:
                # DNS query
                probe_data = b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
                             b'\x07version\x04bind\x00\x00\x10\x00\x03'
            elif port == 161:
                # SNMP GetRequest
                probe_data = b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04' \
                             b'\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30' \
                             b'\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'

            sock.sendto(probe_data, (self.ip, port))
            sock.recvfrom(1024)
            sock.close()
            return (port, 'OPEN')

        except socket.timeout:
            return (port, 'OPEN|FILTERED')   # No ICMP response = might be open
        except ConnectionRefusedError:
            return (port, 'CLOSED')
        except PermissionError:
            return (port, 'OPEN|FILTERED')
        except Exception:
            return (port, 'FILTERED')

    def _progress(self):
        """Thread-safe progress counter."""
        with self._lock:
            self._scanned += 1
            pct = int((self._scanned / self._total) * 40)
            bar = '█' * pct + '░' * (40 - pct)
            print(f"\r  Progress: [{bar}] {self._scanned}/{self._total}", end='', flush=True)

    def tcp_scan(self, verbose: bool = False) -> dict:
        """Run multi-threaded TCP scan. Returns {port: state}."""
        results = {}
        print(f"\033[90m  [~] TCP scanning {self._total} ports on {self.ip} "
              f"({self.threads} threads, timeout={self.timeout}s)\033[0m\n")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {executor.submit(self._tcp_probe, p): p for p in self.ports}
            for future in as_completed(future_map):
                port, state = future.result()
                results[port] = state
                self._progress()

        print()  # newline after progress bar

        if self.logger:
            self.logger.log_scan('TCP', self.target, results)

        return results

    def udp_scan(self, verbose: bool = False) -> dict:
        """Run multi-threaded UDP scan. Returns {port: state}."""
        results = {}
        print(f"\033[90m  [~] UDP scanning {self._total} ports on {self.ip} "
              f"({self.threads} threads, timeout={self.timeout}s)\033[0m\n")
        print(f"\033[93m  [!] Note: UDP is stateless — results may show OPEN|FILTERED\033[0m\n")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {executor.submit(self._udp_probe, p): p for p in self.ports}
            for future in as_completed(future_map):
                port, state = future.result()
                results[port] = state
                self._progress()

        print()

        if self.logger:
            self.logger.log_scan('UDP', self.target, results)

        return results
