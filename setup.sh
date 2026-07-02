#!/bin/bash
# PortSentinel Setup Script
# Run: chmod +x setup.sh && ./setup.sh

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║     PortSentinel Setup & Installation     ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# Check Python version
PYTHON=$(which python3 2>/dev/null || which python 2>/dev/null)
if [ -z "$PYTHON" ]; then
    echo "[!] Python 3 not found. Please install Python 3.8+"
    exit 1
fi

PY_VER=$($PYTHON --version 2>&1)
echo "[+] Found: $PY_VER"

# Create directories
echo "[+] Creating directories..."
mkdir -p reports logs

# Make main script executable
chmod +x portsentinel.py
echo "[+] Made portsentinel.py executable"

# Quick syntax check
echo "[*] Running syntax check..."
$PYTHON -m py_compile portsentinel.py && echo "[+] Syntax OK: portsentinel.py"
$PYTHON -m py_compile core/scanner.py && echo "[+] Syntax OK: core/scanner.py"
$PYTHON -m py_compile core/banner_grab.py && echo "[+] Syntax OK: core/banner_grab.py"
$PYTHON -m py_compile core/risk_engine.py && echo "[+] Syntax OK: core/risk_engine.py"
$PYTHON -m py_compile core/os_fingerprint.py && echo "[+] Syntax OK: core/os_fingerprint.py"
$PYTHON -m py_compile utils/display.py && echo "[+] Syntax OK: utils/display.py"
$PYTHON -m py_compile utils/logger.py && echo "[+] Syntax OK: utils/logger.py"
$PYTHON -m py_compile reports/report_gen.py && echo "[+] Syntax OK: reports/report_gen.py"

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║         Setup Complete! Try:              ║"
echo "║                                           ║"
echo "║  python3 portsentinel.py --help           ║"
echo "║  python3 portsentinel.py -t 127.0.0.1    ║"
echo "╚═══════════════════════════════════════════╝"
echo ""
