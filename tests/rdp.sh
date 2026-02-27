#!/bin/bash
# RDP module test
# Requires a Windows machine with RDP enabled
# Usage: ./rdp.sh <target_ip> [username] [password]

set -e

TARGET="${1:?Usage: $0 <target_ip> [username] [password]}"
USER="${2:-Administrator}"
PASS="${3:-Password123}"

echo "[*] Testing RDP brute-force against $TARGET..."
../bruter -m rdp -t "$TARGET" -u "$USER" -w /dev/stdin <<< "wrong_password
$PASS
also_wrong"

echo ""
echo "[+] Done"
