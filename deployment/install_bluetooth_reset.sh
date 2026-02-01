#!/bin/bash
#
# Quick deployment script for Bluetooth Reset feature
# Run this on your Raspberry Pi after pulling the latest code
#

set -e

echo "=== Nerdlock Bluetooth Reset Deployment ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo"
    exit 1
fi

# 1. Copy script to /opt/Nerdlock
echo "1. Installing reset script..."
mkdir -p /opt/Nerdlock/scripts

# Check if we're running from /opt/Nerdlock already
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$SCRIPT_DIR" = "/opt/Nerdlock" ]; then
    echo "   ✓ Already running from /opt/Nerdlock, script already in place"
else
    cp scripts/reset_bluetooth.sh /opt/Nerdlock/scripts/
    chmod +x /opt/Nerdlock/scripts/reset_bluetooth.sh
    echo "   ✓ Script installed to /opt/Nerdlock/scripts/reset_bluetooth.sh"
fi

# Make sure it's executable
chmod +x /opt/Nerdlock/scripts/reset_bluetooth.sh

# 2. Install sudoers rule
echo "2. Installing sudoers rule..."
if [ -f /etc/sudoers.d/nerdlock ]; then
    echo "   ! Sudoers file already exists, backing up..."
    cp /etc/sudoers.d/nerdlock /etc/sudoers.d/nerdlock.backup.$(date +%Y%m%d_%H%M%S)
fi

# Check if we're running from /opt/Nerdlock already
if [ "$SCRIPT_DIR" = "/opt/Nerdlock" ]; then
    cp deployment/nerdlock.sudoers /etc/sudoers.d/nerdlock
else
    cp deployment/nerdlock.sudoers /etc/sudoers.d/nerdlock
fi
chmod 0440 /etc/sudoers.d/nerdlock

# Validate sudoers syntax
if visudo -c -f /etc/sudoers.d/nerdlock > /dev/null 2>&1; then
    echo "   ✓ Sudoers rule installed and validated"
else
    echo "   ✗ Sudoers syntax error! Removing file..."
    rm /etc/sudoers.d/nerdlock
    exit 1
fi

# 3. Detect gunicorn user
echo "3. Detecting web server user..."
GUNICORN_USER=$(ps aux | grep '[g]unicorn' | awk '{print $1}' | head -n1)
if [ -n "$GUNICORN_USER" ]; then
    echo "   Found gunicorn running as: $GUNICORN_USER"

    # Update sudoers if not www-data
    if [ "$GUNICORN_USER" != "www-data" ]; then
        echo "   Updating sudoers for user: $GUNICORN_USER"
        sed -i "s/^www-data/$GUNICORN_USER/" /etc/sudoers.d/nerdlock
        echo "   ✓ Updated"
    fi
else
    echo "   ! Gunicorn not running, using default 'www-data'"
    echo "   ! If this is wrong, edit /etc/sudoers.d/nerdlock manually"
fi

# 4. Test permissions
echo "4. Testing permissions..."
if [ -n "$GUNICORN_USER" ]; then
    if sudo -u "$GUNICORN_USER" sudo /opt/Nerdlock/scripts/reset_bluetooth.sh > /dev/null 2>&1; then
        echo "   ✓ Bluetooth reset works for $GUNICORN_USER"
    else
        echo "   ✗ Test failed! Check sudoers configuration"
        exit 1
    fi
fi

# 5. Restart application
echo "5. Restarting nerdlock service..."
if systemctl is-active --quiet nerdlock; then
    systemctl restart nerdlock
    echo "   ✓ Service restarted"
else
    echo "   ! Service 'nerdlock' not found or not running"
    echo "   ! Restart manually: sudo systemctl restart <your-service-name>"
fi

echo
echo "=== Deployment Complete ==="
