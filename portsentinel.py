#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║           PORT SCANNER - Intelligent Port Scanner         ║
║           Built for Network Security Internship           ║
║           Author: Luffy | Tool: Port Scanner v1.0         ║
╚═══════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
from core.scanner import PortScanner
from core.banner_grab import BannerGrabber
from core.risk_engine import RiskEngine
from core.os_fingerprint import OSFingerprinter
from core.exploit_check import ExploitChecker
from reports.report_gen import ReportGenerator
from utils.display import Display
from utils.logger import Logger


def print_banner():
    banner = """
\033[92m
 ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
\033[0m
\033[93m        [ Intelligent Port Scanner & Service Risk Analyzer ] v1.0\033[0m
\033[37m        [ NOT Nmap — Built from scratch with Python socket programming ]\033[0m
"""
    print(banner)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog='portscanner',
        description='Port Scanner - Intelligent Port Scanner & Risk Analyzer',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 portsentinel.py -t 192.168.1.1
  python3 portsentinel.py -t 192.168.1.1 -p 1-1024
  python3 portsentinel.py -t 192.168.1.1 -p 22,80,443,3306
  python3 portsentinel.py -t 192.168.1.1 --scan-type udp
  python3 portsentinel.py -t 192.168.1.1 --banner --risk --os-detect
  python3 portsentinel.py -t 192.168.1.1 --full-scan --report html
  python3 portsentinel.py -t 192.168.1.1 -p 1-65535 --threads 200
        """
    )

    # Target
    parser.add_argument('-t', '--target', required=True,
                        help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024',
                        help='Port range (e.g., 1-1024) or comma-separated (e.g., 22,80,443)\nDefault: 1-1024')

    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--scan-type', choices=['tcp', 'udp', 'both'], default='tcp',
                            help='Scan type: tcp, udp, or both (default: tcp)')
    scan_group.add_argument('--threads', type=int, default=100,
                            help='Number of concurrent threads (default: 100)')
    scan_group.add_argument('--timeout', type=float, default=1.0,
                            help='Connection timeout in seconds (default: 1.0)')
    scan_group.add_argument('--full-scan', action='store_true',
                            help='Run full scan: banner grab + risk analysis + OS detect')

    # Feature flags
    feature_group = parser.add_argument_group('Features')
    feature_group.add_argument('--banner', action='store_true',
                               help='Enable service banner grabbing')
    feature_group.add_argument('--risk', action='store_true',
                               help='Enable risk scoring for open ports')
    feature_group.add_argument('--os-detect', action='store_true',
                               help='Enable OS fingerprinting via TTL/TCP analysis')
    feature_group.add_argument('--verbose', '-v', action='store_true',
                               help='Show detailed output including closed ports')
    feature_group.add_argument('--exploit', action='store_true',
                               help='Run exploitation awareness checks (default creds, SSH ciphers, anon FTP)')
    feature_group.add_argument('--no-creds', action='store_true',
                               help='Skip default credential checks (faster)')
    feature_group.add_argument('--no-ssh-audit', action='store_true',
                               help='Skip SSH cipher audit')

    # Output
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('--report', choices=['html', 'txt', 'json', 'all'],
                              help='Generate report in specified format')
    output_group.add_argument('--output-dir', default='reports',
                              help='Directory to save reports (default: reports/)')
    output_group.add_argument('--no-color', action='store_true',
                              help='Disable colored output')

    args = parser.parse_args()

    # Apply full-scan shortcut
    if args.full_scan:
        args.banner = True
        args.risk = True
        args.os_detect = True
        args.exploit = True

    # Setup logger
    logger = Logger()
    display = Display(no_color=args.no_color)

    # Parse ports
    ports = parse_ports(args.ports)
    if not ports:
        display.error("Invalid port specification. Use range (1-1024) or list (22,80,443)")
        sys.exit(1)

    display.info(f"Target     : {args.target}")
    display.info(f"Ports      : {args.ports} ({len(ports)} ports)")
    display.info(f"Scan Type  : {args.scan_type.upper()}")
    display.info(f"Threads    : {args.threads}")
    display.info(f"Timeout    : {args.timeout}s")
    display.info(f"Features   : {'Banner ' if args.banner else ''}{'Risk ' if args.risk else ''}{'OS-Detect' if args.os_detect else ''}")
    print()

    results = {}

    # TCP Scan
    if args.scan_type in ('tcp', 'both'):
        display.header("[ TCP PORT SCAN ]")
        scanner = PortScanner(args.target, ports, args.threads, args.timeout, logger)
        tcp_results = scanner.tcp_scan(verbose=args.verbose)
        results['tcp'] = tcp_results
        display.print_scan_results(tcp_results, 'TCP', args.verbose)

    # UDP Scan
    if args.scan_type in ('udp', 'both'):
        display.header("[ UDP PORT SCAN ]")
        scanner = PortScanner(args.target, ports, args.threads, args.timeout, logger)
        udp_results = scanner.udp_scan(verbose=args.verbose)
        results['udp'] = udp_results
        display.print_scan_results(udp_results, 'UDP', args.verbose)

    # Banner Grabbing
    banner_data = {}
    if args.banner:
        display.header("[ SERVICE BANNER GRABBING ]")
        open_ports = []
        for proto, res in results.items():
            if proto == 'tcp':
                open_ports = [p for p, s in res.items() if s == 'OPEN']
        grabber = BannerGrabber(args.target, args.timeout)
        banner_data = grabber.grab_all(open_ports)
        display.print_banners(banner_data)

    # OS Fingerprinting
    os_info = {}
    if args.os_detect:
        display.header("[ OS FINGERPRINTING ]")
        fingerprinter = OSFingerprinter(args.target, args.timeout)
        os_info = fingerprinter.detect()
        display.print_os_info(os_info)

    # Risk Analysis
    risk_data = {}
    if args.risk:
        display.header("[ RISK ANALYSIS & SCORING ]")
        open_ports = []
        for proto, res in results.items():
            open_ports.extend([p for p, s in res.items() if s == 'OPEN'])
        engine = RiskEngine()
        risk_data = engine.analyze(list(set(open_ports)), banner_data)
        display.print_risk_report(risk_data)

    # Exploitation Awareness
    exploit_report = None
    if getattr(args, 'exploit', False):
        display.header("[ EXPLOITATION AWARENESS ]")
        open_ports = []
        for proto, res in results.items():
            open_ports.extend([p for p, s in res.items() if s == 'OPEN'])
        open_ports = list(set(open_ports))
        checker = ExploitChecker(args.target, args.timeout)
        exploit_report = checker.run(
            open_ports,
            check_creds=not getattr(args, 'no_creds', False),
            check_ssh_ciphers=not getattr(args, 'no_ssh_audit', False),
            check_anon_ftp=True
        )
        display.print_exploit_report(exploit_report)

    # Report Generation
    if args.report:
        display.header("[ REPORT GENERATION ]")
        os.makedirs(args.output_dir, exist_ok=True)
        gen = ReportGenerator(args.target, results, banner_data, os_info, risk_data, args.output_dir)

        if args.report in ('html', 'all'):
            path = gen.generate_html()
            display.success(f"HTML Report saved: {path}")

        if args.report in ('txt', 'all'):
            path = gen.generate_txt()
            display.success(f"TXT  Report saved: {path}")

        if args.report in ('json', 'all'):
            path = gen.generate_json()
            display.success(f"JSON Report saved: {path}")

    # Summary
    print()
    display.header("[ SCAN COMPLETE ]")
    total_open = sum(
        sum(1 for s in res.values() if s == 'OPEN')
        for res in results.values()
    )
    display.success(f"Total open ports found: {total_open}")
    logger.close()


def parse_ports(port_str):
    """Parse port string into list of integers."""
    ports = []
    try:
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return sorted(set(p for p in ports if 1 <= p <= 65535))
    except ValueError:
        return []


if __name__ == '__main__':
    main()
