"""
Port Scanner - Display Utility
Handles all terminal output with color coding and formatting.
"""

import datetime


class Display:
    """Terminal display with high-visibility color support."""

    COLORS = {
        'RESET':    '\033[0m',
        'BOLD':     '\033[1m',
        'RED':      '\033[91m',
        'GREEN':    '\033[92m',
        'YELLOW':   '\033[93m',
        'BLUE':     '\033[94m',
        'MAGENTA':  '\033[95m',
        'CYAN':     '\033[96m',
        'WHITE':    '\033[97m',
        'GRAY':     '\033[37m',    # Changed from dark gray \033[90m → light gray \033[37m
        'ORANGE':   '\033[33m',
    }

    RISK_COLORS = {
        'CRITICAL': '\033[91m',    # Bright Red
        'HIGH':     '\033[93m',    # Bright Yellow
        'MEDIUM':   '\033[33m',    # Orange/Yellow
        'LOW':      '\033[92m',    # Bright Green
        'INFO':     '\033[97m',    # Bright White (was Cyan — hard to read)
    }

    STATE_COLORS = {
        'OPEN':          '\033[92m',   # Bright Green
        'CLOSED':        '\033[37m',   # Light Gray (was dark \033[90m)
        'FILTERED':      '\033[93m',   # Bright Yellow
        'OPEN|FILTERED': '\033[97m',   # Bright White (was Cyan)
    }

    def __init__(self, no_color: bool = False):
        self.no_color = no_color

    def _c(self, color_key: str) -> str:
        if self.no_color:
            return ''
        return self.COLORS.get(color_key, '')

    def _r(self) -> str:
        return '' if self.no_color else self.COLORS['RESET']

    def header(self, text: str):
        # Changed from CYAN → bright WHITE + GREEN separator for max visibility
        c = self._c('GREEN')
        w = self._c('WHITE')
        r = self._r()
        sep = '═' * 60
        print(f"\n{c}{sep}")
        print(f"  {w}\033[1m{text}\033[0m")
        print(f"{c}{sep}{r}")

    def info(self, text: str):
        # Changed from BLUE ([*] was dim blue) → bright WHITE label + normal text
        c = self._c('WHITE')
        r = self._r()
        print(f"  {c}[*]{r} {text}")

    def success(self, text: str):
        c = self._c('GREEN')
        r = self._r()
        print(f"  {c}[+]{r} {text}")

    def warning(self, text: str):
        c = self._c('YELLOW')
        r = self._r()
        print(f"  {c}[!]{r} {text}")

    def error(self, text: str):
        c = self._c('RED')
        r = self._r()
        print(f"  {c}[✗]{r} {text}")

    def print_scan_results(self, results: dict, proto: str, verbose: bool = False):
        """Print scan results table."""
        open_ports = {p: s for p, s in results.items() if s == 'OPEN'}
        other_ports = {p: s for p, s in results.items() if s != 'OPEN'}

        # Table header in bright white
        w = self._c('WHITE')
        r = self._r()
        print(f"\n  {w}{'PORT':<10} {'STATE':<15} {'PROTOCOL'}{r}")
        print(f"  {w}{'─'*10} {'─'*15} {'─'*10}{r}")

        for port in sorted(open_ports.keys()):
            state = open_ports[port]
            sc = '' if self.no_color else self.STATE_COLORS.get(state, '')
            service = self._get_service_name(port)
            print(f"  {sc}{port:<10} {state:<15} {proto}/{service}{r}")

        if verbose:
            for port in sorted(other_ports.keys()):
                state = other_ports[port]
                sc = '' if self.no_color else self.STATE_COLORS.get(state, '')
                print(f"  {sc}{port:<10} {state:<15} {proto}{r}")

        print()
        c_open = self._c('GREEN')
        print(f"  {c_open}Open ports: {len(open_ports)} / {len(results)} scanned{r}")
        if not verbose and other_ports:
            g = self._c('GRAY')
            print(f"  {g}(Use --verbose to show closed/filtered ports){r}")

    def print_banners(self, banner_data: dict):
        """Print banner grab results."""
        if not banner_data:
            return

        w = self._c('WHITE')
        r = self._r()
        print(f"\n  {w}{'PORT':<8} {'SERVICE':<20} {'VERSION/BANNER'}{r}")
        print(f"  {w}{'─'*8} {'─'*20} {'─'*40}{r}")

        for port, info in sorted(banner_data.items()):
            svc = info.get('service', 'Unknown')[:20]
            ver = info.get('version', '')[:40]
            banner = info.get('banner_clean', '')[:60]
            display_ver = ver if ver else banner[:40]
            c = self._c('CYAN')
            print(f"  {c}{port:<8}{r} {svc:<20} {display_ver}")

    def print_os_info(self, os_info: dict):
        """Print OS fingerprinting results."""
        if not os_info:
            return

        c = self._c('MAGENTA')
        r = self._r()
        g = self._c('GRAY')

        print(f"\n  {c}OS Guess    :{r} {os_info.get('os_guess', 'Unknown')}")
        print(f"  {c}Confidence  :{r} {os_info.get('confidence', 'Low')}")

        ttl = os_info.get('ttl')
        if ttl:
            print(f"  {c}TTL Value   :{r} {ttl}")
            print(f"  {c}TTL OS Hint :{r} {os_info.get('ttl_os', 'N/A')}")

        hints = os_info.get('port_hints', [])
        if hints:
            print(f"  {c}Port Hints  :{r} {', '.join(hints)}")

        details = os_info.get('details', [])
        if details:
            print(f"\n  {g}Evidence:")
            for d in details:
                print(f"  {g}  → {d}{r}")

    def print_risk_report(self, risk_data: dict):
        """Print risk analysis report."""
        if not risk_data:
            return

        port_risks = risk_data.get('port_risks', {})
        posture = risk_data.get('posture', 'UNKNOWN')
        avg_score = risk_data.get('average_score', 0.0)
        critical = risk_data.get('critical_count', 0)
        high = risk_data.get('high_count', 0)

        # Overall posture
        posture_color = '\033[91m' if 'COMPROMISED' in posture or 'HIGH' in posture else '\033[93m'
        r = self._r()
        w = self._c('WHITE')
        print(f"\n  {w}Overall Posture :{r} {posture_color}{posture}{r}")
        print(f"  {w}Average Score   :{r} {avg_score}/10.0")
        print(f"  {w}Critical Ports  :{r} {critical}")
        print(f"  {w}High Risk Ports :{r} {high}")

        print(f"\n  {w}{'PORT':<8} {'RISK':<12} {'SCORE':<8} SERVICE{r}")
        print(f"  {w}{'─'*8} {'─'*12} {'─'*8} {'─'*30}{r}")

        for port, risk in sorted(port_risks.items()):
            rc = '' if self.no_color else self.RISK_COLORS.get(risk.risk_level, '')
            score_bar = self._score_bar(risk.risk_score)
            print(f"  {rc}{port:<8} {risk.risk_level:<12} {risk.risk_score:<8}{r} {risk.service}")
            print(f"  {' '*8} {score_bar}")
            if risk.reason:
                g = self._c('GRAY')
                print(f"  {g}  ↳ {risk.reason[:80]}{r}")
            if risk.cve_references:
                c = self._c('CYAN')
                cves = ', '.join(risk.cve_references[:3])
                print(f"  {c}  ↳ CVEs: {cves}{r}")
            if risk.remediation:
                c = self._c('GREEN')
                print(f"  {c}  ↳ Fix : {risk.remediation[:80]}{r}")
            print()

    def _score_bar(self, score: float) -> str:
        """Visual score bar."""
        filled = int(score)
        bar = '█' * filled + '░' * (10 - filled)
        if score >= 9:
            color = '\033[91m'
        elif score >= 7:
            color = '\033[93m'
        elif score >= 4:
            color = '\033[33m'
        else:
            color = '\033[92m'
        return f"{color}[{bar}] {score}/10{self._r()}"

    def _get_service_name(self, port: int) -> str:
        """Return common service name for a port."""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 445: 'smb', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 6379: 'redis', 8080: 'http-alt',
            8443: 'https-alt', 27017: 'mongodb',
        }
        return services.get(port, 'unknown')

    # ─────────────────────────────────────────────
    #  Exploitation Awareness Display
    # ─────────────────────────────────────────────

    def print_exploit_report(self, report):
        """Print full exploitation awareness report."""
        if not report:
            return

        r = self._r()

        # ── Anonymous FTP ──────────────────────────
        if report.ftp_findings:
            w = self._c('WHITE')
            print(f"\n  {w}[ ANONYMOUS FTP CHECK ]{r}")
            print(f"  {'─'*50}")
            for f in report.ftp_findings:
                if f.anonymous_login:
                    rc = self._c('RED')
                    print(f"  {rc}[VULNERABLE]{r} Port {f.port} — Anonymous FTP login OPEN")
                    if f.writable:
                        print(f"  {rc}            ↳ Directory is WRITABLE — critical risk!{r}")
                    else:
                        y = self._c('YELLOW')
                        print(f"  {y}            ↳ Read-only access (no write permission){r}")
                elif f.status == 'SECURE':
                    g = self._c('GREEN')
                    print(f"  {g}[SECURE]{r}     Port {f.port} — Anonymous login rejected")
                else:
                    gr = self._c('GRAY')
                    print(f"  {gr}[ERROR]{r}      Port {f.port} — {f.note}")

        # ── SSH Cipher Audit ───────────────────────
        if report.ssh_findings:
            w = self._c('WHITE')
            print(f"\n  {w}[ SSH CIPHER AUDIT ]{r}")
            print(f"  {'─'*50}")
            for f in report.ssh_findings:
                if f.banner:
                    gr = self._c('GRAY')
                    print(f"  {gr}  Banner : {f.banner[:70]}{r}")

                if f.status == 'WEAK':
                    rc = self._c('RED')
                    y  = self._c('YELLOW')
                    print(f"  {rc}[WEAK ALGORITHMS DETECTED] Port {f.port}{r}")
                    if f.weak_kex:
                        print(f"  {y}  ↳ Weak KEX      : {', '.join(f.weak_kex)}{r}")
                    if f.weak_ciphers:
                        print(f"  {y}  ↳ Weak Ciphers  : {', '.join(f.weak_ciphers)}{r}")
                    if f.weak_macs:
                        print(f"  {y}  ↳ Weak MACs     : {', '.join(f.weak_macs)}{r}")
                    print(f"  {y}  ↳ Fix: Disable legacy algorithms in /etc/ssh/sshd_config{r}")
                elif f.status == 'SECURE':
                    g = self._c('GREEN')
                    print(f"  {g}[SECURE]{r} Port {f.port} — No weak SSH algorithms detected")
                else:
                    gr = self._c('GRAY')
                    print(f"  {gr}[ERROR]{r}  Port {f.port} — Could not audit SSH ciphers")

                if f.host_key_algos:
                    gr = self._c('GRAY')
                    print(f"  {gr}  Host Keys : {', '.join(f.host_key_algos[:4])}{r}")

        # ── Default Credentials ────────────────────
        if report.cred_findings:
            w = self._c('WHITE')
            print(f"\n  {w}[ DEFAULT CREDENTIALS CHECK ]{r}")
            print(f"  {'─'*50}")
            for f in report.cred_findings:
                if f.status == 'VULNERABLE':
                    rc = self._c('RED')
                    print(f"  {rc}[VULNERABLE]{r} Port {f.port} ({f.protocol})")
                    print(f"  {rc}             ↳ Login succeeded → {f.username}:{f.password}{r}")
                elif f.status == 'ERROR':
                    gr = self._c('GRAY')
                    print(f"  {gr}[ERROR]{r}      Port {f.port} ({f.protocol}) — {f.note}")
                # FAILED = good, no output needed to keep it clean

        # ── Summary ────────────────────────────────
        print()
        vuln_count = sum(1 for f in report.cred_findings if f.status == 'VULNERABLE')
        weak_ssh   = sum(1 for f in report.ssh_findings  if f.status == 'WEAK')
        anon_ftp   = sum(1 for f in report.ftp_findings  if f.anonymous_login)
        total      = vuln_count + weak_ssh + anon_ftp

        if total > 0:
            rc = self._c('RED')
            print(f"  {rc}⚠  {total} exploitation issue(s) found — immediate action required!{r}")
        else:
            g = self._c('GREEN')
            print(f"  {g}✔  No exploitation vulnerabilities detected{r}")
