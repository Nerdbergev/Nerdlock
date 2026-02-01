#!/bin/bash
#
# Bluetooth Reset Script
# Use this if Nerdlock can't unlock doors due to BLE connection issues
# Run as root or with sudo
#

echo "Resetting Bluetooth adapter..."

# Method 1: Soft reset via bluetoothctl
echo "Attempting soft reset..."
bluetoothctl power off
sleep 2
bluetoothctl power on
sleep 2

# Method 2: Restart Bluetooth service
echo "Restarting Bluetooth service..."
systemctl restart bluetooth
sleep 3

# Method 3: Reset the HCI device (if soft methods fail)
if command -v hciconfig &> /dev/null; then
    echo "Performing HCI reset..."
    hciconfig hci0 down
    sleep 1
    hciconfig hci0 up
    sleep 2
fi

echo "Bluetooth reset complete."
echo "Please wait a few seconds before trying to unlock again."
