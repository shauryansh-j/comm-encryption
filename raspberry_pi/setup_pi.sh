#!/usr/bin/env bash
# ==============================================================================
# SecureFlex-MAVLink Raspberry Pi 5 Automated Setup & Provisioning Script
# Raspberry Pi OS Lite (64-bit Debian / Python 3.11+)
# ==============================================================================

set -euo pipefail

echo "=========================================================="
echo "  SecureFlex-MAVLink: Raspberry Pi 5 Environment Setup"
echo "=========================================================="

PROJECT_DIR="$HOME/SecureFlex-MAVLink"

# 1. Update system packages
echo "[*] Step 1: Updating system packages and installing prerequisites..."
sudo apt-get update -y
sudo apt-get install -y python3-venv python3-pip git ufw

# 2. Configure project directory
echo "[*] Step 2: Creating project directories..."
mkdir -p "$PROJECT_DIR/config"
mkdir -p "$PROJECT_DIR/logs"

# 3. Create Python Virtual Environment
echo "[*] Step 3: Setting up isolated Python virtual environment..."
if [ ! -d "$PROJECT_DIR/.venv" ]; then
    python3 -m venv "$PROJECT_DIR/.venv"
fi
source "$PROJECT_DIR/.venv/bin/activate"

# 4. Install pinned dependencies
echo "[*] Step 4: Installing required Python packages..."
pip install --upgrade pip
pip install -r "$PROJECT_DIR/requirements-pi.txt"

# 5. Restrict secret key permissions if present
if [ -f "$PROJECT_DIR/config/secret.key" ]; then
    echo "[*] Step 5: Securing secret key file permissions (chmod 600)..."
    chmod 600 "$PROJECT_DIR/config/secret.key"
else
    echo "[!] Notice: config/secret.key not found. Transfer it securely from Windows via SCP."
fi

# 6. Configure UFW Firewall for UDP 14550
echo "[*] Step 6: Configuring UFW firewall rules for MAVLink UDP port 14550..."
sudo ufw allow 14550/udp comment "SecureFlex MAVLink UDP" || true

# 7. Install and enable systemd daemon
echo "[*] Step 7: Configuring systemd background service..."
SERVICE_SRC="$PROJECT_DIR/raspberry_pi/service/secureflex-receiver.service"
if [ -f "$SERVICE_SRC" ]; then
    sudo cp "$SERVICE_SRC" /etc/systemd/system/secureflex-receiver.service
    sudo systemctl daemon-reload
    sudo systemctl enable secureflex-receiver.service
    echo "[+] Service enabled! Start manually with: sudo systemctl start secureflex-receiver"
    echo "[+] Check live status with: sudo journalctl -u secureflex-receiver -f"
fi

# 8. Run unit test verification
echo "[*] Step 8: Running cryptographic and framing unit tests..."
pytest "$PROJECT_DIR/tests"

echo "=========================================================="
echo "  [SUCCESS] Raspberry Pi 5 Setup Completed Successfully!"
echo "=========================================================="

