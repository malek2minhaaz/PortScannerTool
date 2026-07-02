"""
PortSentinel - Logger
Writes scan sessions to logs/scan_history.log
"""

import os
import datetime


class Logger:
    def __init__(self, log_dir: str = 'logs'):
        os.makedirs(log_dir, exist_ok=True)
        self.log_path = os.path.join(log_dir, 'scan_history.log')
        self.session_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._fh = open(self.log_path, 'a', encoding='utf-8')
        self._fh.write(f"\n{'='*60}\n")
        self._fh.write(f"SESSION: {self.session_time}\n")
        self._fh.write(f"{'='*60}\n")

    def log_scan(self, proto: str, target: str, results: dict):
        open_ports = [p for p, s in results.items() if s == 'OPEN']
        self._fh.write(f"[{proto}] Target: {target}\n")
        self._fh.write(f"  Open ports: {sorted(open_ports)}\n")
        self._fh.write(f"  Total scanned: {len(results)}\n")
        self._fh.flush()

    def log(self, message: str):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        self._fh.write(f"[{ts}] {message}\n")
        self._fh.flush()

    def close(self):
        self._fh.write(f"\nSession ended: {datetime.datetime.now().strftime('%H:%M:%S')}\n")
        self._fh.close()
